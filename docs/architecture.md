# frien — Architecture

## Overview

frien is a headless decentralized security-state mesh. Infrastructure nodes detect security-relevant events locally, share signed evidence-backed state across peers using gossip and delta-state CRDTs, verify provenance through a tamper-evident Merkle DAG, and enforce safe mitigations through pluggable adapters — observe-only by default.

**This is not a consensus or BFT system.** frien is *accountable*: it detects equivocation, produces portable misbehavior proofs, and provides provenance trails. It does not claim to tolerate arbitrary Byzantine faults.

---

## Architectural Layers

```
Layer 0  Protocol Versioning          — every wire object carries proto_version
Layer 1  Transport + Identity         — QUIC, mTLS, short-lived certs
Layer 2  Membership                   — SWIM (alive/suspect/dead/left)
Layer 3  Distributed State + Scoping  — op-id-keyed grow-only set (union merge), deterministic projections, scope/zone router
Layer 4  Tamper-Evidence + Compaction — Merkle DAG, checkpoint, compaction
Layer 5  Trust + Policy Engine        — operator-signed policy, partition-safe quorum
Layer 6  Detection + Admission        — pluggable detectors, token-bucket, coalescing
Layer 7  Enforcement (fail-safe)      — observe-only default, nftables, dead-man switch
Layer 8  Storage                      — WAL, bbolt, signed snapshots
Layer 9  Observability                — slog/zerolog, Prometheus, OTel traces
Layer 10 Identity Lifecycle           — short-lived certs, operator-signed revocation
Layer 11 Control Plane Distribution   — operator-signed policies/trust/revocations
```

---

## Trust Planes

Two distinct trust domains exist and must never be conflated:

| Plane | Objects | Signed By | Purpose |
|-------|---------|-----------|---------|
| Data plane | ThreatRecord, EnforcementDecision | Node key (cert) | Observations — prove provenance, not truth |
| Control plane | Policy, TrustTier, RevocationRecord | Operator/CA key (KMS/HSM) | Grant authority — the only objects that may trigger enforcement |

A signed data-plane message proves the sender's identity. It does **not** prove the content is true. Only operator-signed control-plane objects may grant enforcement authority.

---

## Key Components

### `cmd/friend` — Main Daemon
Unprivileged process. Runs the mesh, policy engine, storage, local API, detectors, and observability. Does **not** own firewall rule lifetime.

### `cmd/frien-enforcer` — Privileged Helper
Minimal OS capability (CAP_NET_ADMIN scoped to frien's own nftables chains). Owns the lifetime of every rule it applies. Implements the dead-man's switch: removes all frien-managed rules if daemon heartbeats stop.

### `cmd/frienctl` — Operator CLI
Local operator tool. Communicates via the local gRPC Unix socket. All commands are authenticated, audited, and scoped.

### `internal/transport` — QUIC + mTLS Peer Sessions
- Peer authentication via short-lived mTLS certificates (hours, not months)
- Revocation checked at session establishment (revoked fingerprint → drop session)
- Max message size enforcement, per-peer rate limits, deadline handling

### `internal/membership` — SWIM Membership
- States: alive / suspect / dead / left
- Seed-node bootstrap; optional mDNS for lab/LAN
- Membership messages piggyback bounded CRDT deltas and revocation-set updates

### `internal/crdt` — State Engine
- Grow-only set of immutable signed ops keyed by `op_id`; merge is pure set-union (a join-semilattice — SEC by construction). Not an OR-Set: `op_id` is unique and single-author, so there is no concurrent same-key write to arbitrate.
- TTL expiry, author retraction (single-writer LWW by `seq`), and quorum are deterministic projections over the set, not part of the merge. Union preserves equivocation evidence that a keep-one LWW-set would discard.
- LWW-Register-per-field for node metadata, G-Counter for telemetry. `EnforcementDecision.applied`/`rolled_back` are local bbolt columns, not gossiped.
- Hybrid Logical Clocks (HLC) stamp every op; persisted across restart, clamped to bounded drift, feeding the clock-skew rejection.
- Scope/zone replication enforced on both egress and ingress; anti-entropy reconciles per-scope Merkle roots bounded below by the latest common checkpoint.

### `internal/verify` — Merkle DAG + Equivocation Detection
- Every operation in a signed envelope with parent hashes
- Detects missing parents, replay, stale operations, equivocation
- Equivocation → portable misbehavior proof → peer quarantine → revocation proposal

### `internal/checkpoint` — Compaction Anchor
- Periodic signed Checkpoint linking to previous checkpoint
- DAG nodes and WAL entries below acknowledged checkpoints are pruned
- Preserves verifiability without unbounded storage (CT-style tree-head consistency)

### `internal/policy` — Trust + Partition-Safe Quorum
- Evaluates incoming state against operator-signed policy
- Quorum: distinct valid identities, trust-tier weighted, local-receive-time window
- Partition behavior: minority partition → intelligence-only (no fleet-scoped enforcement)
- Protected CIDR lists (IPv4 + IPv6), self-plane protection

### `internal/enforcer` — Adapter Interfaces
- Primary: nftables with kernel-native `timeout` (rules self-expire even if daemon dies)
- Adapters: Kubernetes NetworkPolicy, Cilium, Envoy/NGINX, SIEM/SOAR webhook
- Rollback tokens persisted in WAL; reconciled on restart
- **Future (Phase 5+):** XDP/eBPF enforcement adapter — evaluate drop rules at NIC driver level before packets enter the kernel network stack (~3–5x lower latency than nftables at high packet rates)

### `internal/detectors/ebpf` — eBPF Detector Backend (Phase 5+)
eBPF lets frien attach detectors directly to kernel tracepoints instead of tailing log files. Opt-in per-detector via `backend: "ebpf"` in config. Requires kernel 5.8+ and `CAP_BPF`.

| Detector | Kernel hook | Advantage over log-file |
|---|---|---|
| SSH brute-force | `security_socket_connect` + PAM auth tracepoint | Sub-millisecond; no log rotation/parsing dependency |
| Port scan | `tcp_v4_connect` / `udp_sendmsg` kprobe | Detects before connection fully establishes |
| Privilege escalation | `commit_creds` tracepoint | Catches `setuid(0)` from unexpected processes instantly |
| DNS exfiltration | `udp_sendmsg` + payload inspection | Catches long-subdomain exfil patterns |
| Process anomaly | `sched_process_exec` tracepoint | Unexpected binaries running on a node |

Library: `github.com/cilium/ebpf` (same library Cilium uses). BPF C sources live in `internal/detectors/ebpf/bpf/`; compiled `.bpf.o` objects are either committed or built via `make bpf-gen`. All eBPF detectors produce the same `ThreatRecord` output as log-file detectors — the admission and coalescing layers above them are unchanged.

### `internal/admission` — Storm Protection
- Per-detector and per-node operation-creation budgets (token-bucket)
- Coalescing: many identical signals collapse into one record with `coalesced_count`
- Priority shedding: low-severity/low-confidence signals dropped first under storm

### `internal/revocation` — Identity Lifecycle
- Short-lived certs (hours); auto-renewal against private CA
- Revocation set: control-plane CRDT (OR-Set), operator/CA-signed entries only
- Transport layer: revoked fingerprint → session drop
- Policy layer: revoked reporter → report rejected

---

## Quorum Definition

A report contributes to quorum only when all of these hold:

1. **Distinct identity** — distinct, currently-valid, CA-issued node certificate
2. **Trust-tier weighted** — weight per tier; quorum expressed as required weight, not count
3. **Bounded receive window** — measured by local receive clock, not origin wall-clock
4. **Not a relayed duplicate** — keyed by (op_id, origin_node_id); gossip amplification does not manufacture quorum

Partition behavior is **fail-safe**: a minority partition that cannot observe the required weight from distinct identities **must not** take fleet-scoped enforcement. Falls back to intelligence-only.

---

## Enforcement Safety Model

1. Default mode is `observe` — decisions logged, audited, explained; no rule applied
2. Operator explicitly promotes a node to `enforce` per adapter
3. All rules carry kernel-native expiry (nftables `timeout`)
4. Enforcer dead-man's switch: daemon heartbeat stops → all frien-managed rules removed
5. Protected CIDRs (IPv4 + IPv6) and frien's own planes cannot be blocked
6. Durable rollback tokens reconciled on restart
7. Breakglass: `frienctl --local breakglass --flush-enforcement --force-observe`

---

## Data Model Summary

See [docs/database.md](database.md) for full schema. Key objects:

- `OperationEnvelope` — signed versioned wrapper for all wire objects
- `ThreatRecord` — signed evidence-backed security observation with scope
- `EnforcementDecision` — policy-approved action with rollback token and kernel timeout
- `Policy` — operator-signed YAML policy with quorum, TTL, and protected-CIDR rules
- `RevocationRecord` — operator-signed cert fingerprint revocation
- `Checkpoint` — signed compaction anchor with materialized state hash
- `PeerState` — membership, trust tier, enforce mode, cert fingerprint, misbehavior score

---

## Crypto Agility — Three-Layer PQC Model

frien is designed so that quantum-resistant algorithms can be adopted incrementally at three independent layers:

| Layer | Algorithm | Status |
|-------|-----------|--------|
| TLS key exchange | Hybrid X25519 + ML-KEM-768 (FIPS 203) | **Default** (`pqc_kem: "x25519mlkem768"`) |
| Envelope signing | Hybrid ed25519 + ML-DSA-65 (FIPS 204) | **Default** (`signing_algorithm: "hybrid-ed25519-ml-dsa-65"`) |
| Certificate signatures | Composite X.509 ECDSA + ML-DSA | **Planned** — CA ecosystem not yet ready |

**Hybrid signature model** (Layer 2): every `OperationEnvelope` carries both an ed25519 signature and an ML-DSA-65 signature over the same canonical content. Receivers verify whichever they support. A corrupted PQC signature is a hard reject — the classical signature cannot rescue it — preventing downgrade attacks.

**Library**: `github.com/cloudflare/circl v1.6.3` implements ML-DSA-65. When Go stdlib ships native ML-DSA (expected ~Go 1.27/1.28), the implementation in `internal/identity/signer.go` and `internal/identity/verifier.go` will be swapped behind the `Signer`/`Verifier` interfaces. Wire format is unchanged.

**Key exchange** (Layer 1): TLS `tls.X25519MLKEM768` curve preference (Go 1.23+) wraps gossip sessions in a hybrid handshake. Session keys require breaking both X25519 and ML-KEM-768 to decrypt. Configurable to `"classical"` for pre-1.23 peers.

---

## Deployment Modes

| Mode | Description |
|------|-------------|
| Host (EC2/Linux) | `friend` daemon + `frien-enforcer` → nftables; local WAL + bbolt |
| Kubernetes (EKS) | DaemonSet; enforcer in separate container; Kubernetes NetworkPolicy / Cilium adapter |
| Observe-only | Any node before operator promotion — full intelligence, no enforcement |

---

## Reference

See [FRIEN_ARCHITECTURE.md](FRIEN_ARCHITECTURE.md) for the full canonical architecture document.
