# frien — Configuration Reference

## Config File Format

frien uses YAML configuration. The default search path is:

1. `--config` flag value
2. `/etc/frien/config.yaml`
3. `./frien.yaml` (development only)

Environment variables override file values using the prefix `FRIEN_` followed by the uppercased, underscore-separated key path (e.g., `FRIEN_NODE_ID`, `FRIEN_TRANSPORT_PEER_PORT`).

**A `.env.example` file is provided at the repo root. Never commit real `.env` or secret files.**

---

## Required Fields

Daemon fails to start if any of these are missing or invalid:

| Field | Type | Description |
|-------|------|-------------|
| `node.id` | string | Unique node identifier. Use reverse-DNS style: `node.edge.eu-west.01` |
| `node.zone` | string | Zone/scope membership. e.g., `edge-eu-west` |
| `node.role` | string | `edge` \| `core` \| `gateway` |
| `identity.cert_path` | string | Path to PEM node certificate (short-lived) |
| `identity.key_path` | string | Path to PEM private key (encrypted at rest recommended) |
| `identity.ca_cert_path` | string | Path to PEM CA cert (required when `ca_mode=file`, which is the default) |
| `identity.ca_overlap_window` | duration | How long a `frienctl rotate-ca`-staged CA bundle stays trusted alongside the current one before superseding it. Default: `24h` |
| `storage.wal_dir` | string | Directory for WAL files. Must be writable by `frien` user |
| `storage.db_path` | string | Path to bbolt database file |
| `transport.peer_port` | int | UDP port for QUIC peer mesh. Default: `7443` |

---

## Full Configuration Reference

```yaml
# ─────────────────────────────────────────────
# Node Identity
# ─────────────────────────────────────────────
node:
  id: "node.edge.eu-west.01"     # required; unique per node
  zone: "edge-eu-west"           # required; zone membership
  role: "edge"                   # required; edge | core | gateway
  trust_tier: "standard"         # standard | trusted | high; default: standard

# ─────────────────────────────────────────────
# Identity and Certificates
# ─────────────────────────────────────────────
identity:
  cert_path: "/etc/frien/keys/node.crt"     # required
  key_path: "/etc/frien/keys/node.key"      # required
  ca_cert_path: "/etc/frien/ca.crt"         # required when ca_mode=file
  renewal_threshold: "1h"                   # renew cert when this close to expiry
  renewal_endpoint: ""                      # CA renewal endpoint (empty = no auto-renew)
  operator_root_cert: "/etc/frien/operator-root.crt"  # for control-plane verification

  # CA integration mode — no code changes needed to point at a different CA
  ca_mode: "file"                           # file | bundle_url | spiffe
  ca_bundle_url: ""                         # HTTPS URL; required when ca_mode=bundle_url
  ca_bundle_refresh: "1h"                   # re-fetch interval for bundle_url mode
  spiffe_socket: ""                         # UNIX socket; required when ca_mode=spiffe
                                            # e.g. "unix:///run/spire/sockets/agent.sock"

  # Hybrid PQC signing — controls OperationEnvelope signature fields
  # "ed25519"                  — classical only
  # "hybrid-ed25519-ml-dsa-65" — send both (default; backward-compatible)
  # "ml-dsa-65"                — PQC only (not recommended until ecosystem matures)
  signing_algorithm: "hybrid-ed25519-ml-dsa-65"
  pqc_key_path: ""                          # ML-DSA-65 key PEM; auto-generated if empty
                                            # required when signing_algorithm=ml-dsa-65

  # PQC TLS key exchange — protects sessions against harvest-now-decrypt-later
  # "x25519mlkem768" — hybrid X25519 + ML-KEM-768 (FIPS 203, Go 1.23+) — default
  # "classical"      — X25519 only; use for Go < 1.23 or strict FIPS environments
  pqc_kem: "x25519mlkem768"

# ─────────────────────────────────────────────
# Transport (QUIC + mTLS)
# ─────────────────────────────────────────────
transport:
  peer_port: 7443                # required; UDP port
  peer_bind: "0.0.0.0"          # bind address for peer listener
  max_message_bytes: 1048576     # 1MB per message max
  handshake_rate_limit: 10       # handshakes/sec per remote IP
  stream_rate_limit: 100         # streams/sec per peer
  dial_timeout: "5s"
  session_idle_timeout: "30s"
  clock_skew_window: "10s"       # reject operations outside this window

# ─────────────────────────────────────────────
# Seed Nodes (bootstrap)
# ─────────────────────────────────────────────
seeds:
  - address: "10.0.1.10:7443"
  - address: "10.0.1.11:7443"
mdns_discovery: false            # enable for lab/LAN; disable for production

# ─────────────────────────────────────────────
# Membership (SWIM)
# ─────────────────────────────────────────────
membership:
  probe_interval: "1s"
  probe_timeout: "500ms"
  suspect_multiplier: 4          # probe_interval * N before marking dead
  max_gossip_nodes: 3            # piggyback targets per membership round

# ─────────────────────────────────────────────
# Admin API (gRPC)
# ─────────────────────────────────────────────
admin_api:
  socket: "/run/frien/admin.sock"   # default; Unix socket
  tcp_listen: ""                    # optional; "127.0.0.1:9443" for TLS TCP
  tls_cert: ""                      # required if tcp_listen is set
  tls_key: ""                       # required if tcp_listen is set
  max_recv_message_bytes: 524288    # 512KB
  request_timeout: "10s"
  read_only: false                  # true = disable all mutating RPCs

# ─────────────────────────────────────────────
# Storage
# ─────────────────────────────────────────────
storage:
  wal_dir: "/var/lib/frien/wal"        # required
  db_path: "/var/lib/frien/state.db"  # required; bbolt
  snapshot_dir: "/var/lib/frien/snapshots"
  wal_sync: true                       # fsync on every WAL append (safer, slower)
  compaction_interval: "1h"            # how often to attempt checkpoint + compact
  compaction_min_age: "2h"             # minimum age of entries before pruning
  compaction_peer_ack_fraction: 0.6    # fraction of in-scope peers that must ack checkpoint

# ─────────────────────────────────────────────
# Admission Control
# ─────────────────────────────────────────────
admission:
  per_detector_burst: 100         # token-bucket burst per detector
  per_detector_rate: 10           # tokens/sec per detector
  per_node_burst: 500             # total node burst
  per_node_rate: 50               # total tokens/sec
  coalesce_window: "5s"           # window for coalescing identical signals
  shed_min_confidence: 0.5        # drop below this confidence under storm

# ─────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────
policy:
  policy_file: "/etc/frien/policy.yaml"   # operator-signed policy
  enforce_mode: "observe"                 # observe | enforce; default MUST be observe
  dry_run: false
  max_new_rules_per_minute: 20
  protected_cidrs:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
    - "169.254.0.0/16"
    - "::1/128"
    - "fc00::/7"
    - "fe80::/10"
  protect_self_planes: true        # dynamically protect frien's own addresses
  deny_targeting_admin_endpoint: true

# ─────────────────────────────────────────────
# Enforcement Adapters
# ─────────────────────────────────────────────
enforcement:
  nftables:
    enabled: false                 # disabled until explicitly enabled
    table: "frien"
    chain_input: "frien-input"
    chain_forward: "frien-forward"
    max_rule_ttl: "24h"
    kernel_timeout_required: true
    deadman_switch_timeout: "30s"  # remove all rules if no heartbeat within this period
  kubernetes:
    enabled: false
    kubeconfig: ""                 # empty = in-cluster
  cilium:
    enabled: false
  siem_webhook:
    enabled: false
    endpoint: ""
    auth_header: ""                # set via FRIEN_ENFORCEMENT_SIEM_AUTH_HEADER env var

# ─────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────
detectors:
  ssh_bruteforce:
    enabled: true
    backend: "log"                 # "log" (default) | "ebpf" (requires kernel 5.8+, CAP_BPF)
    auth_log: "/var/log/auth.log"  # used when backend=log; ignored when backend=ebpf
    threshold: 10                  # failed attempts within window
    window: "60s"
    confidence: 0.9
  http_rate_anomaly:
    enabled: false
    backend: "log"
    access_log: ""
    threshold: 1000
    window: "60s"
    confidence: 0.7
  port_scan:
    enabled: false
    backend: "ebpf"               # eBPF-only; no log-file equivalent
    threshold: 20                 # distinct ports within window
    window: "10s"
    confidence: 0.85
  privilege_escalation:
    enabled: false
    backend: "ebpf"               # eBPF-only; hooks commit_creds tracepoint
    confidence: 0.99
  process_anomaly:
    enabled: false
    backend: "ebpf"               # hooks sched_process_exec; hooks sched_process_exec
    allowlist: []                 # list of binary paths allowed; everything else alerts
    confidence: 0.8

# ─────────────────────────────────────────────
# Observability
# ─────────────────────────────────────────────
observability:
  log_level: "info"               # debug | info | warn | error
  log_format: "json"              # json | text
  metrics_bind: "127.0.0.1:9109"
  otel_endpoint: ""               # OTel collector gRPC endpoint for push metrics/traces
  trace_sample_rate: 0.1          # 0.0–1.0
  health_bind: "127.0.0.1:9110"

# ─────────────────────────────────────────────
# Hardening
# ─────────────────────────────────────────────
harden:
  profile: "server"               # dev | server | edge | kubernetes | strict
  auto_apply: false               # never auto-apply; operator must invoke frienctl harden apply
```

---

## Environment Variable Overrides

Any config field can be overridden with `FRIEN_` + uppercased dotted path, replacing dots with underscores:

| Environment Variable | Config Field | Notes |
|---------------------|-------------|-------|
| `FRIEN_NODE_ID` | `node.id` | |
| `FRIEN_NODE_ZONE` | `node.zone` | |
| `FRIEN_IDENTITY_KEY_PATH` | `identity.key_path` | |
| `FRIEN_TRANSPORT_PEER_PORT` | `transport.peer_port` | |
| `FRIEN_ADMIN_API_SOCKET` | `admin_api.socket` | |
| `FRIEN_POLICY_ENFORCE_MODE` | `policy.enforce_mode` | Cannot be set to `enforce` via env; requires explicit file config |
| `FRIEN_ENFORCEMENT_SIEM_AUTH_HEADER` | `enforcement.siem_webhook.auth_header` | Secret; set via env only |
| `FRIEN_OBSERVABILITY_LOG_LEVEL` | `observability.log_level` | |

Secrets (keys, auth headers, tokens) **must** be provided via environment variable or a secrets manager, never in the config file checked into source control.

---

## Startup Validation

The daemon performs these checks at startup and fails fast if any fail:

1. All required fields are non-empty
2. `node.id` matches the CN in the loaded certificate
3. Certificate is not expired and will not expire within `renewal_threshold`
4. CA cert chain is valid
5. WAL directory exists and is writable
6. bbolt path is writable
7. `policy.enforce_mode` defaults to `observe` unless explicitly set to `enforce`
8. Protected CIDRs parse without error
9. If `admin_api.tcp_listen` is set, `tls_cert` and `tls_key` must also be set
10. `transport.max_message_bytes` is within safe bounds (64KB–16MB)
