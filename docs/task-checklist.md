# frien — Implementation Task Checklist

Last updated: 2026-07-10 (Phase 0 complete: tooling, proto codegen, CI baseline, TLA+ skeleton)

Legend: `[x]` = complete and verified | `[ ]` = pending | `[~]` = in progress

---

## Phase 0: Project Definition and Safety Baseline (Sprint 0)

### Documentation Setup
- [x] `docs/architecture.md` — architecture summary
- [x] `docs/workflow.md` — event lifecycle and workflows
- [x] `docs/api-manual.md` — gRPC API reference
- [x] `docs/task-checklist.md` — this file
- [x] `docs/folder-structure.md` — folder layout
- [x] `docs/configuration.md` — all config variables
- [x] `docs/security.md` — security model and controls
- [x] `docs/database.md` — data model and storage schema
- [x] `docs/testing.md` — testing strategy
- [x] `docs/deployment.md` — deployment guide
- [x] `docs/error-handling.md` — error handling patterns
- [x] `docs/grpc-contracts.md` — gRPC contract versioning
- [x] `docs/PROTOCOL.md` — wire protocol versioning
- [x] `docs/THREAT_MODEL.md` — threat model
- [x] `docs/ENFORCEMENT_SAFETY.md` — observe→enforce safety
- [x] `docs/COMPLIANCE.md` — compliance mappings
- [x] `docs/UPGRADE.md` — upgrade guide

### Repository Scaffold
- [x] Go module initialized (`go.mod` with `github.com/prateekpurohit13/frien`, go 1.26.1)
- [x] Correct folder structure created (see `docs/folder-structure.md`)
- [x] `.env.example` created at repo root
- [x] `Makefile` created with standard targets
- [x] `.gitignore` updated (key files, binaries, WAL data)

### gRPC Contract Definition
- [x] `proto/v1/frien.proto` — all message types and services defined
- [x] `pkg/proto/v1/` — generated Go code from proto (via `buf generate`, `buf.gen.yaml` + `proto/v1/buf.yaml`; `protoc-gen-go`/`protoc-gen-go-grpc` plugins)
- [x] `internal/version/version.go` — protocol version constants and negotiation

### Go Package Skeleton (Phase 0 / Phase 1 start)
- [x] `internal/version/version.go` + tests — protocol versioning, negotiation
- [x] `internal/errors/errors.go` + tests — AppError, gRPC status mapping, sentinels
- [x] `internal/config/config.go` + `loader.go` + tests — load, validate, env override, fail-fast
- [x] `internal/logger/logger.go` — zerolog structured logger initialization
- [x] `cmd/friend/main.go` — bootstrap skeleton (config→logger→storage placeholder→identity placeholder→gRPC placeholder→graceful shutdown)
- [x] `cmd/frienctl/main.go` — stub (Phase 1)
- [x] `cmd/frien-enforcer/main.go` — stub (Phase 5)

### Build Verification
- [x] `go build ./...` — passes cleanly
- [x] `go test -race ./internal/...` — all tests pass
- [x] `golangci-lint` configured (`.golangci.yaml`) — not yet run locally (golangci-lint binary not installed on this Windows dev box; runs in CI)
- [x] SBOM generation (`syft`) step drafted — `.github/workflows/ci.yml` `sbom` job (`anchore/sbom-action`)
- [x] Signed artifact workflow drafted (`cosign`) — `.github/workflows/ci.yml` `release-sign` job (keyless `cosign sign-blob`, tag-triggered)

### CI Baseline
- [x] `govulncheck` integrated — `.github/workflows/ci.yml` `vuln` job
- [x] `golangci-lint` configured — `.github/workflows/ci.yml` `lint` job (`golangci-lint-action`)
- [x] SBOM + signing CI steps drafted — see above

### TLA+ Spec Skeleton
- [x] `specs/frien.tla` — skeleton covering membership FSM (alive/suspect/dead/left), quorum-gated enforcement, misbehavior quarantine, and revocation; not yet model-checked with TLC

---

## Phase 1: Secure Node Foundation (Sprint 1)

### Config Package
- [ ] `internal/config/config.go` — typed Config struct
- [ ] `internal/config/loader.go` — YAML + env override loading
- [ ] `internal/config/validator.go` — fail-fast validation
- [ ] `internal/config/config_test.go` — unit tests (missing required, env override, secret injection)

### Logger Package
- [ ] `internal/logger/logger.go` — structured logger initialization (slog)
- [ ] `internal/logger/logger_test.go`

### Version Package
- [ ] `internal/version/version.go` — proto version constants, software version
- [ ] `internal/version/version_test.go`

### Storage Package (skeleton)
- [ ] `internal/storage/wal.go` — append-only WAL with hash-linked entries
- [ ] `internal/storage/bbolt.go` — bbolt initialization and bucket creation
- [ ] `internal/storage/snapshot.go` — snapshot load/save
- [ ] `internal/storage/storage_test.go`

### Node Identity
- [ ] `internal/identity/identity.go` — cert loading, fingerprint, renewal check
- [x] `internal/identity/canonical.go` — deterministic canonical signed content (SHA-256, length-prefixed)
- [x] `internal/identity/signer.go` — `Signer` interface; Ed25519Signer, MLDSASigner (circl), HybridSigner
- [x] `internal/identity/verifier.go` — `Verify()` with hybrid policy (PQC preferred, hard reject on corrupt PQC)
- [x] `internal/identity/identity_test.go` — 16 tests: canonical, ed25519, ML-DSA-65, hybrid, downgrade prevention

### PQC Implementation (added 2026-06-14)
- [x] `go.mod` — `github.com/cloudflare/circl v1.6.3` added
- [x] `proto/v1/frien.proto` — `OperationEnvelope` fields 13–15: `pqc_algorithm`, `pqc_key_id`, `pqc_signature`
- [x] `internal/config/config.go` — `IdentityConfig`: `CAMode`, `CABundleURL`, `CABundleRefresh`, `SPIFFESocket`, `SigningAlgorithm`, `PQCKeyPath`, `PQCKem`
- [x] `internal/config/loader.go` — defaults: `signing_algorithm=hybrid-ed25519-ml-dsa-65`, `pqc_kem=x25519mlkem768`
- [x] `docs/security.md` — PQC three-layer model, signing algorithm table, CA integration mode table
- [x] `docs/grpc-contracts.md` — hybrid signature protocol, canonical content spec, verification policy
- [x] `docs/configuration.md` — all PQC and CA integration config fields documented
- [x] `docs/architecture.md` — Crypto Agility section with three-layer PQC model
- [x] `docs/PROTOCOL.md` — hybrid sig note, canonical bytes, receiver preference order
- [ ] Phase 2: TLS `tls.X25519MLKEM768` wired into `internal/transport/quic.go` (when transport is built)
- [ ] Phase 7+: Composite X.509 cert support (CA ecosystem must mature first)

### gRPC Server Skeleton
- [ ] `internal/grpc/server.go` — gRPC server setup
- [ ] `internal/grpc/api.go` — AdminService registration
- [ ] `internal/middleware/chain.go` — interceptor chain
- [ ] `internal/middleware/panic_recovery.go`
- [ ] `internal/middleware/request_logger.go`

### Main Daemon Bootstrap
- [ ] `cmd/friend/main.go` — compact bootstrap (load config, init logger, init storage, init identity, register gRPC, start server, graceful shutdown)

### Errors Package
- [ ] `internal/errors/errors.go` — AppError types, gRPC status mapping
- [ ] `internal/errors/errors_test.go`

### Health Package
- [ ] `internal/health/health.go` — readiness and liveness handlers

### Phase 1 Exit Criteria
- [ ] One node starts, exposes health endpoint, writes WAL entries, and shuts down cleanly
- [ ] `frienctl status` returns node status via admin socket
- [ ] Config validation rejects missing required fields with clear diagnostic
- [ ] WAL replay recovers state on restart
- [ ] All unit tests pass with race detector

---

## Phase 2: Peer Transport, Membership, and Admission (Sprint 2)

### Transport Package
- [ ] `internal/transport/quic.go` — QUIC listener and dialer
- [ ] `internal/transport/session.go` — peer session management
- [ ] `internal/transport/tls.go` — mTLS config builder
- [ ] `internal/transport/transport_test.go`

### Version Negotiation
- [ ] `internal/version/negotiate.go` — handshake negotiation
- [ ] `internal/version/negotiate_test.go`

### Membership Package
- [ ] `internal/membership/swim.go` — SWIM probe/ping-req/indirect-ping
- [ ] `internal/membership/state.go` — alive/suspect/dead/left FSM
- [ ] `internal/membership/membership_test.go`

### Admission Package
- [ ] `internal/admission/budget.go` — token-bucket per detector and per node
- [ ] `internal/admission/coalesce.go` — signal coalescing
- [ ] `internal/admission/shed.go` — priority shedding under storm
- [ ] `internal/admission/admission_test.go`

### Phase 2 Exit Criteria
- [ ] 3 nodes discover each other and detect failure
- [ ] Simulated storm is coalesced/shed without crash
- [ ] Revoked cert session is rejected at transport

---

## Phase 3: Scoped CRDT State Mesh (Sprint 3)

- [ ] `internal/crdt/hlc.go` — Hybrid Logical Clock
- [ ] `internal/crdt/orset.go` — expiring delta OR-Set
- [ ] `internal/crdt/crdt_test.go` — convergence, idempotency, commutativity, associativity property tests
- [ ] `internal/scope/router.go` — zone/scope replication router
- [ ] Anti-entropy sync (root-hash exchange + DAG walk above shared checkpoint)

### Phase 3 Exit Criteria
- [ ] Zone-scoped threat record converges on in-scope peers; out-of-scope peer does not receive it
- [ ] Replayed operation is rejected

---

## Phase 4: Tamper-Evidence, Compaction, and Revocation (Sprint 4)

- [ ] `internal/verify/signature.go` — ed25519 signature verification
- [ ] `internal/verify/dag.go` — Merkle DAG parent tracking, root-hash exchange
- [ ] `internal/verify/equivocation.go` — equivocation detection and proof
- [ ] `internal/checkpoint/checkpoint.go` — signed checkpoint creation
- [ ] `internal/checkpoint/compact.go` — WAL and DAG compaction
- [ ] `internal/revocation/revocation.go` — operator-signed revocation set

### Phase 4 Exit Criteria
- [ ] Conflicting operations produce a misbehavior proof and quarantine
- [ ] Revoked cert rejected mesh-wide
- [ ] DAG and WAL stay bounded in soak test

---

## Phase 5: Signed Policy and Fail-Safe Enforcement (Sprint 5)

- [ ] `internal/policy/engine.go` — policy evaluation
- [ ] `internal/policy/quorum.go` — partition-safe quorum check
- [ ] `internal/policy/protect.go` — protected CIDR and self-plane checks
- [ ] `internal/enforcer/nftables.go` — nftables adapter with kernel expiry
- [ ] `internal/enforcer/deadman.go` — dead-man's switch
- [ ] `internal/enforcer/rollback.go` — durable rollback token management
- [ ] `internal/audit/explain.go` — `frienctl explain` data assembly

### Phase 5 Exit Criteria
- [ ] Observe mode logs/explains without applying rules
- [ ] Enforce mode creates self-expiring nftables entry
- [ ] Protected target is denied by policy with explanation
- [ ] Minority partition refuses fleet-scoped enforcement
- [ ] Daemon crash leaves no leaked rule past kernel timeout

---

## Phase 6: Detection, Visualization, and Demo (Sprint 6)

- [ ] `internal/detector/interface.go` — Detector interface (shared by log-file and eBPF backends)
- [ ] `internal/detector/ssh_bruteforce.go` — log-file backend
- [ ] `internal/detector/http_rate_anomaly.go` — log-file backend
- [ ] Dashboard BFF and Next.js admin panel (stub)
- [ ] Demo cluster scripts

---

## Phase 7: Integrations, Hardening, and Upgrades (Sprint 7)

- [ ] `internal/harden/doctor.go` — self-hardening check
- [ ] Kubernetes NetworkPolicy adapter
- [ ] Cilium adapter prototype
- [ ] Mixed-version upgrade tests
- [ ] Fuzz tests for protocol handlers
- [ ] `frienctl harden apply` profiles

### eBPF Detector Backend (Phase 7 add-on)
- [ ] Add `github.com/cilium/ebpf` dependency to `go.mod`
- [ ] `internal/detectors/ebpf/bpf/ssh.c` — BPF C source for SSH brute-force (PAM auth tracepoint)
- [ ] `internal/detectors/ebpf/bpf/portscan.c` — `tcp_v4_connect` kprobe
- [ ] `internal/detectors/ebpf/bpf/privesc.c` — `commit_creds` tracepoint
- [ ] `internal/detectors/ebpf/bpf/process.c` — `sched_process_exec` tracepoint
- [ ] `internal/detectors/ebpf/loader.go` — load compiled `.bpf.o`, attach to kernel hooks, emit `ThreatRecord`
- [ ] `Makefile` target `bpf-gen` — compile BPF C → `.bpf.o` via `clang -target bpf`
- [ ] `internal/config` — add `backend: "log"|"ebpf"` per detector; `CAP_BPF` capability check at startup
- [ ] Integration test: eBPF SSH detector fires on simulated failed auth in Linux container
- [ ] (Phase 8+) XDP enforcement adapter in `internal/enforcer/xdp.go` — pre-stack packet drop via `github.com/cilium/ebpf` XDP program; replaces nftables for high-throughput nodes

---

## Current Status

**Completed:** Phase 0 — all documentation + project scaffold + core package skeleton ✓

**Verified:**
- `go build ./...` — clean
- `go test -race ./internal/...` — all pass (errors, config, version packages)

**Next step (Phase 1):** Implement `internal/storage` (WAL + bbolt), `internal/identity` (cert load/renewal), `internal/grpc` (server + interceptor chain), `internal/health`, and wire them into `cmd/friend/main.go` so a real node can start, serve health, and write WAL entries.

---

## Known Limitations and Notes

- TLA+ spec skeleton is planned but not yet drafted
- `frienctl` CLI binary is not yet implemented; admin API will be tested via grpcurl initially
- nftables adapter requires Linux; tests on non-Linux CI should skip enforcer tests via build tags
- Kubernetes adapter deferred to Phase 7
- OPA/Rego policy integration deferred until YAML policy engine is stable
