# frien — Implementation Task Checklist

Last updated: 2026-06-18 (Phase 0 complete + Phase 1 secure node foundation complete)

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
- [x] `.gitignore` updated (key files, certs, binaries, WAL/db/snapshot/socket data, SBOM artifacts)

### gRPC Contract Definition
- [x] `proto/v1/frien.proto` — all message types and services defined
- [x] `pkg/proto/v1/` — generated Go code from proto (`make proto-gen`; protoc-gen-go + protoc-gen-go-grpc)
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
- [x] `golangci-lint` configured (`.golangci.yml`, schema v2; pinned in CI)
- [x] SBOM generation (`syft`) step drafted (CI `supply-chain` job)
- [x] Signed artifact workflow drafted (`cosign` keyless via OIDC)

### CI Baseline
- [x] `govulncheck` integrated (CI `vuln` job)
- [x] `golangci-lint` configured (CI `lint` job, pinned version)
- [x] SBOM + signing CI steps drafted (CI `supply-chain` job: syft SBOM, grype scan, cosign sign)
- [x] `.github/workflows/ci.yml` — build/test(race)/proto-freshness/lint/vuln/sbom/sign

### TLA+ Spec Skeleton
- [x] `specs/frien.tla` — skeleton covering membership, quorum, quarantine, revocation with safety invariants (QuorumSafety, NoSelfLockout, Quarantine/RevocationExcludesQuorum)

---

## Phase 1: Secure Node Foundation (Sprint 1)

### Config Package
- [x] `internal/config/config.go` — typed Config struct
- [x] `internal/config/loader.go` — YAML + env override loading + defaults
- [x] validation — fail-fast `Validate()` lives in `config.go` (consolidated, not a separate validator.go)
- [x] `internal/config/config_test.go` — unit tests (missing required, env override, secret injection)

### Logger Package
- [x] `internal/logger/logger.go` — structured logger initialization (zerolog; see note below)
- [ ] `internal/logger/logger_test.go` — (Init is a thin wrapper; covered indirectly)

> Note: the project standardized on `zerolog` (not stdlib `slog`) for structured logging; this is reflected across all packages.

### Version Package
- [x] `internal/version/version.go` — proto version constants, software version, Negotiate/IsSupported
- [x] `internal/version/version_test.go`

### Storage Package
- [x] `internal/storage/wal.go` — append-only hash-linked WAL (magic+len+prevhash+payload+selfhash); torn-tail recovery; tamper detection
- [x] `internal/storage/bbolt.go` — bbolt init, all buckets, schema-version stamp + newer-schema refusal
- [x] `internal/storage/snapshot.go` — atomic snapshot save (temp+rename) / load-latest
- [x] `internal/storage/store.go` — Store composes WAL+bbolt+snapshots behind one lifecycle
- [x] `internal/storage/storage_test.go` — append/replay, cross-restart chain, tamper, torn-tail, snapshots, schema guard

### Node Identity
- [x] `internal/identity/identity.go` — cert/key load, ed25519 signer derivation, fingerprint, CN check, renewal/expiry checks, CA pool loader
- [x] `internal/identity/identity_load_test.go` — load, CN mismatch, non-ed25519 rejection, renewal thresholds, expiry, missing file
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

### gRPC Server + Admin API
- [x] `internal/grpc/server.go` — server setup, Unix socket (stale-socket-safe) + optional TLS TCP, lifecycle (Start/Stop)
- [x] `internal/grpc/api.go` — AdminService; GetStatus implemented; later RPCs return clear Unimplemented (named phase)
- [x] `internal/grpc/server_test.go` — GetStatus over real socket, degraded-on-expiry, Unimplemented, non-socket-file guard
- [x] `internal/middleware/chain.go` — composes the interceptor chain (extensible for later phases)
- [x] `internal/middleware/panic_recovery.go` — panic → INTERNAL, stack logged internally only
- [x] `internal/middleware/request_logger.go` — request ID, x-request-id trailer, method/caller/code/latency log
- [x] `internal/middleware/context.go` — request-ID context helpers
- [x] `internal/middleware/middleware_test.go`

### Operation Log over WAL (Phase 1 addition)
- [x] `internal/oplog/oplog.go` — signed lifecycle OperationEnvelopes appended to WAL; verifying replay (payload hash + ed25519); per-node seq continues across restarts
- [x] `internal/oplog/oplog_test.go` — append/recover across restart, seq continuity, tampered-record rejection

### Main Daemon Bootstrap
- [x] `cmd/friend/main.go` — thin `run()`: config → logger → storage → identity → oplog recover+start → health → admin gRPC → ready → signal → graceful shutdown
- [x] `cmd/frienctl/main.go` — `version` + `status` (dials admin socket, prints GetStatus); socket resolved via --socket/--config/default

### Errors Package
- [x] `internal/errors/errors.go` — AppError types, gRPC status mapping, sentinel constructors
- [x] `internal/errors/errors_test.go`

### Health Package
- [x] `internal/health/health.go` — `/healthz` liveness, `/readyz` readiness gating, local HTTP server with graceful shutdown
- [x] `internal/health/health_test.go`

### Phase 1 Exit Criteria
- [x] One node starts, exposes health endpoint, writes WAL entries, and shuts down cleanly — verified via smoke test
- [x] `frienctl status` returns node status via admin socket — verified
- [x] Config validation rejects missing required fields with clear diagnostic
- [x] WAL replay recovers state on restart — verified (2 records recovered, seq continues; corrupt WAL refuses start)
- [x] All unit tests pass with race detector (`go test -race ./...`)

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

**Completed:** Phase 0 (definition + safety baseline + CI) ✓ and Phase 1 (secure node foundation) ✓

**Verified:**
- `go build ./...` — clean
- `go vet ./...` — clean
- `go test -race ./...` — all pass (config, errors, version, identity, storage, middleware, health, grpc, oplog)
- End-to-end smoke: daemon starts → `frienctl status` over socket → `/healthz`+`/readyz` 200 → SIGTERM clean shutdown
- Restart smoke: WAL replay recovers prior lifecycle records (seq continues); corrupt WAL → daemon refuses to start

**Next step (Phase 2):** QUIC + mTLS peer transport, protocol-version negotiation at handshake, SWIM membership, admission control (budgets/coalescing/shedding), clock-skew window, and the deterministic simulation harness. Wire `tls.X25519MLKEM768` into the transport at this point. `ListPeers` becomes implementable once membership exists.

---

## Known Limitations and Notes

- `golangci-lint` and `govulncheck` are not installed in the local dev image; both run in CI (`.github/workflows/ci.yml`). `.golangci.yml` uses schema v2 (version pinned in CI).
- TLA+ spec (`specs/frien.tla`) is a Phase 0 skeleton: state + safety invariants are defined; the `Next` action relation is abstract and will be refined as each protocol (membership, quorum, quarantine, revocation) is implemented. Not yet wired into a TLC model-check CI job.
- Admin API has no Auth/RBAC interceptor yet (Unix-socket file permissions are the current access control). Auth, RBAC, rate-limit, validation, and audit interceptors slot into `middleware.Chain` in later phases.
- `oplog` request/op IDs use random tokens, not ULIDs; a ULID is adopted in Phase 3 where lexical time-ordering matters. Cross-node signature verification on replay is deferred to the Phase 4 verify layer (all Phase 1 WAL records are self-authored).
- Envelope signing in `oplog` is ed25519-only for now; PQC (ML-DSA-65) envelope signing over the wire is wired with transport in Phase 2+.
- `frienctl` implements `version` and `status`; remaining subcommands track their server-side RPCs.
- nftables adapter requires Linux; tests on non-Linux CI should skip enforcer tests via build tags
- Kubernetes adapter deferred to Phase 7
- OPA/Rego policy integration deferred until YAML policy engine is stable
