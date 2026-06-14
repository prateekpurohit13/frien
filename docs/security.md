# frien — Security Model

## Threat Model Summary

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model.

Key attacker capabilities considered:

| Attacker | Capability |
|----------|-----------|
| External network attacker | Can observe peer UDP traffic; cannot forge valid mTLS sessions without a valid cert |
| Compromised node | Can sign and send data-plane messages; cannot sign control-plane objects (different key type) |
| Malicious peer | Can send crafted or equivocating messages; detected via Merkle DAG, quarantined, revoked |
| Compromised operator key | Can issue arbitrary control-plane objects; mitigated by KMS/HSM-backed keys, audit trail |
| Supply-chain attacker | Mitigated by SBOM, govulncheck, cosign-signed releases, reproducible builds |

---

## Trust Boundaries

### Data Plane (Node Keys)
- Node certificates are short-lived (hours), issued by a private CA
- A signed data-plane message proves *who sent it*, not that the content is true
- Receiving a signed ThreatRecord does not authorize enforcement
- A compromised node can only affect what the policy and quorum allow

### Control Plane (Operator Keys)
- Policies, trust-tier assignments, and revocations are signed by operator/CA keys
- Operator keys must be KMS/HSM-backed in production (never on-node)
- A node only accepts a policy whose signature verifies against the pinned operator root
- Control-plane objects are the only source of enforcement authority

---

## Authentication

| Surface | Mechanism |
|---------|-----------|
| Peer mesh | mTLS with short-lived node certificates (private CA) |
| Admin API (socket) | Unix socket peer credential (UID/GID of caller) |
| Admin API (TCP, optional) | mTLS or bearer token (OIDC) |
| Dashboard (optional) | OIDC; no custom password systems |
| frienctl CLI | Communicates via admin socket; user must have socket access |

---

## Authorization (RBAC)

Roles: `viewer`, `operator`, `admin`, `breakglass`

Role assignment is in the config or OIDC claim. No default roles are granted to anonymous callers.

---

## Certificate Lifecycle

- Node certs: short-lived (default 8h); auto-renewed against private CA
- Compromise window bounded by cert lifetime, not revocation propagation delay
- Revocation set is a control-plane OR-Set gossipped mesh-wide; operator/CA-signed only
- A revoked fingerprint causes:
  - Immediate session drop at transport layer
  - Rejection of all data-plane messages at policy layer

---

## Privilege Separation

| Process | User | Capabilities |
|---------|------|-------------|
| `friend` daemon | `frien` (non-root) | None special; network sockets only |
| `frien-enforcer` | `frien-enforcer` | `CAP_NET_ADMIN` scoped to frien chains only |
| `frienctl` | operator user | Communicates via admin socket |

The daemon **never** runs as root. The enforcer has only the minimum capability for its adapter (nftables chains it created; never the host baseline).

---

## Enforcement Safety Controls

1. Default observe-only mode — no rules applied until operator promotion
2. All rules carry kernel-native TTL (`nftables timeout`); self-expire without daemon
3. Dead-man's switch: enforcer removes all frien rules if daemon heartbeat stops
4. Protected CIDR list (IPv4 + IPv6): matching targets are never blocked
5. Self-plane protection: frien's own mesh/admin/metrics addresses are dynamically protected
6. Durable rollback tokens: survive daemon crash; reconciled on restart
7. Max rules per minute: prevents runaway enforcement under storm
8. Partition-safe quorum: minority partition cannot take fleet-scoped enforcement
9. Breakglass: `frienctl --local breakglass` flushes all rules and forces observe mode

---

## Input Validation and Sanitization

- All gRPC message fields are validated at interceptor layer before handler execution
- Max message sizes enforced at transport and gRPC layers
- Enum values are validated; unknown values rejected
- String fields have length limits
- Clock-skew window: operations outside the window are rejected (prevents replay via stale messages)
- Replay detection: op_id + origin_node_id dedup within receive window

---

## Secret Management

- Private keys: encrypted at rest (recommended); stored in `/etc/frien/keys/` with `0600` permissions
- Operator signing keys: KMS/HSM-backed; never stored on node
- Config secrets (SIEM auth header, etc.): environment variables only, never config files
- No default passwords; no anonymous access
- `.env.example` only in repo; never commit real `.env` or key files

---

## Audit Logging

- Every admin API mutating call produces an immutable audit log entry
- Audit entries include: timestamp, caller identity, method, arguments summary, result, request ID
- Audit log is append-only; hash-linked for tamper evidence
- `frienctl explain <indicator>` exposes full decision provenance: contributing identities, quorum weight, signed policy version, TTL, adapter state

---

## Network Hardening Defaults

| Surface | Default |
|---------|---------|
| Peer mesh port (UDP 7443) | Bind all; restrict by security group/firewall to known peer CIDRs |
| Admin API | Unix socket only; no network exposure |
| Metrics endpoint | `127.0.0.1:9109`; local only |
| Debug endpoint | Disabled; explicit enable required |

frien's own network addresses are dynamically added to the protected set so enforcement policy can never block frien's own control plane.

---

## Post-Quantum Cryptography (PQC)

frien applies crypto agility at three independent layers. Each layer has a different maturity level today.

### Layer 1 — TLS Key Exchange (session protection)

**Status: production-ready, enabled by default.**

```yaml
identity:
  pqc_kem: "x25519mlkem768"   # hybrid X25519 + ML-KEM-768 (FIPS 203, Go 1.23+)
```

This protects gossip sessions against "harvest now, decrypt later" attacks. The hybrid scheme runs both X25519 and ML-KEM-768 in parallel — the session key is secure if either algorithm is unbroken. Falling back to `"classical"` disables ML-KEM.

### Layer 2 — Operation Envelope Signing (data authenticity)

**Status: implemented via `cloudflare/circl`. Migration path to Go stdlib when available.**

Every `OperationEnvelope` carries two signatures over the same canonical content:
- **ed25519** (64 bytes) — always present; classical baseline
- **ML-DSA-65** (3309 bytes, FIPS 204) — present when sender has a PQC key

Receivers verify whichever algorithm they support. Preference order: ML-DSA-65 > ed25519. A corrupted PQC signature is a **hard reject** — a valid classical signature cannot rescue a broken PQC signature (prevents downgrade attacks).

```yaml
identity:
  signing_algorithm: "hybrid-ed25519-ml-dsa-65"   # default; sends both
  pqc_key_path: "/etc/frien/keys/node-mldsa.key"  # optional; auto-generated if absent
```

When Go stdlib ships ML-DSA (expected ~Go 1.27/1.28), the `cloudflare/circl` implementation in `internal/identity/signer.go` is replaced with the stdlib equivalent. Wire format (`pqc_algorithm`, `pqc_signature`, `pqc_key_id` fields in `OperationEnvelope`) remains unchanged.

### Layer 3 — Certificate Signatures (CA-issued node identity)

**Status: not yet practical. CA ecosystem (AWS Private CA, SPIRE) does not yet issue PQC-signed certificates at scale. Planned for Phase 7+.**

Composite X.509 certificates (classical ECDSA + ML-DSA dual signatures) are defined in IETF drafts but not finalized. frien's crypto-agile `Signer`/`Verifier` interface is designed to accommodate composite certs when the CA ecosystem supports them.

### Signing Algorithm Configuration Reference

| `signing_algorithm` | Sends | Receives |
|--------------------|-------|---------|
| `"ed25519"` | ed25519 only | Accepts ed25519; ignores PQC fields |
| `"hybrid-ed25519-ml-dsa-65"` (default) | Both | Prefers ML-DSA-65; falls back to ed25519 |
| `"ml-dsa-65"` | ML-DSA-65 only | Requires PQC; rejects classical-only |

### CA Integration Modes

| `ca_mode` | How the CA root cert is provided | Who uses it |
|-----------|----------------------------------|-------------|
| `"file"` (default) | PEM file at `ca_cert_path` | Any CA (AWS Private CA, Vault, internal) |
| `"bundle_url"` | HTTPS endpoint; refreshed per `ca_bundle_refresh` | Dynamic CA rotation |
| `"spiffe"` | SPIFFE Workload API at `spiffe_socket` | Kubernetes + SPIRE (Netflix, Uber, Anthem) |

---

## Supply Chain

From day one, every build:
- Runs `govulncheck` — fails on known critical CVEs
- Generates SBOM with `syft`
- Scans images with `grype`
- Signs releases and container images with `cosign`
- Targets reproducible builds

A tool that runs privileged on a fleet must be supply-chain clean from the first commit.

---

## Security Error Handling

- Internal errors are never exposed in API responses (no stack traces, DB errors, key paths)
- All error responses use safe, user-oriented messages with a request ID for correlation
- Rate limit errors return `RESOURCE_EXHAUSTED` with a `Retry-After` hint
- Auth errors return `UNAUTHENTICATED` or `PERMISSION_DENIED` — never information about why (no oracle)
