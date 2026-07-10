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
- [x] `internal/transport/quic.go` — QUIC listener and dialer (quic-go; ALPN `frien-mesh/1`)
- [x] `internal/transport/session.go` — peer session management; raw QUIC + length-prefixed protobuf framing; client/server version negotiation on first stream
- [x] `internal/transport/tls.go` — mTLS config builder; `tls.X25519MLKEM768` default (classical fallback); CN-based peer verify + revocation hook
- [x] `internal/transport/transport_test.go` — establish/negotiate, classical KEM, revoked-peer drop, untrusted-CA reject, frame bounds
- Note: `transport.clock_skew_window` enforcement is deferred to Phase 3 — it operates on operation HLCs, which do not exist until the CRDT layer. Config field is validated; transport carries no placeholder for it.

### Version Negotiation
- [x] `internal/version/negotiate.go` — handshake negotiation (highest-common Resolve/Accept; replaced first-match Negotiate)
- [x] `internal/version/negotiate_test.go`

### Membership Package
- [x] `internal/membership/swim.go` — SWIM driver: direct probe → indirect ping-req relays → suspect; incarnation/self-refutation; bounded O(log N) update dissemination; Prober + Clock + Rand injected for determinism
- [x] `internal/membership/state.go` — alive/suspect/dead/left FSM with SWIM incarnation merge rules; suspicion-timeout expiry
- [x] `internal/membership/membership_test.go` — merge-rule units, self-refutation, suspect expiry, probe→suspect→dead, and deterministic 3-node discovery + failure detection

### Admission Package
- [x] `internal/admission/budget.go` — token-bucket per detector and per node (detector token refunded when node bucket is the binding limit)
- [x] `internal/admission/coalesce.go` — signal coalescing into a running coalesced_count; bounded by window-based Expire
- [x] `internal/admission/shed.go` — priority shedding; high/critical never shed, low/medium shed below confidence floor under storm
- [x] `internal/admission/admission.go` — Controller composing coalesce → shed → budget (storm = node fill ratio < 0.5)
- [x] `internal/admission/admission_test.go`

### Phase 2 Exit Criteria
- [x] 3 nodes discover each other and detect failure — proven by deterministic in-process SWIM simulation (`TestThreeNodeDiscoveryAndFailure`); the live QUIC gossip pump that ships membership Updates between real processes is wired in Phase 3
- [x] Simulated storm is coalesced/shed without crash — `TestControllerShedsUnderStorm`, coalescer tests
- [x] Revoked cert session is rejected at transport — `TestRevokedPeerRejected`

---

## Phase 3: Scoped State Mesh (Sprint 3)

**State model (see FRIEN_ARCHITECTURE §10 Layer 3 + database.md "CRDT State Model"):** the replicated state is a **grow-only set of immutable signed ops keyed by `op_id`; merge is pure set-union**. Retraction, equivocation, and quorum-counting are **projections** over the set (pure functions of it); record TTL expiry additionally reads the local clock, so it converges as clocks agree — the set itself always converges by union. None of these are part of the merge. This is chosen over OR-Set (unnecessary add-wins/tombstone machinery that would collapse the distinct-identity quorum signal) and over keep-one LWW-element-set (which would discard equivocation evidence). Causal `parents` are optional and not gated on in Phase 3.

### Sprint 3a — HLC (foundation) ✓
- [x] `internal/crdt/hlc.go` — Hybrid Logical Clock: `Now()` (send), `Update(remote)` (receive, drift-clamped), `CheckSkew` (ingress gate), `Snapshot`; monotonic even when physical clock regresses; counter-overflow rolls into next ms; `Timestamp` String/Parse handles hyphenated RFC3339 wall + reverse-DNS node ids
- [x] HLC persistence substrate — `storage.MetaGet`/`MetaPut` + `MetaKeyHLC`; `Clock` seeds from `WithInitial(Snapshot())`; restart-no-regression tested at clock level (daemon read/write wiring lands in 3d when the clock is instantiated)
- [x] `CheckSkew(remote, window)` is the `transport.clock_skew_window` mechanism (rejects ops outside the window either direction); call site is op ingress in 3d
- [x] `internal/crdt/hlc_test.go` — round-trip parse, compare, monotonicity (stuck + backward physical clock), causal update, drift rejection, skew gate, restart-no-regression

### Sprint 3b — Op set + projections (the core CRDT) ✓
- [x] `internal/crdt/opset.go` — grow-only set keyed by `op_id`; `Merge` = union; `Add` idempotent on replay; `CanonicalHash` (sorted op_id + payload_hash); in-memory (durability via WAL replay, driven by daemon — no `storage` import, no cycle)
- [x] `internal/crdt/project.go` — `present(op)` = not a control op AND not author-retracted AND `now < expires_at` (origin-declared, in the immutable payload — no resurrection of late-delivered expired ops); `ActiveThreats`, `PresentOps`, `IsPresent`. Record-TTL kept distinct from the quorum window (Phase 5, local-receive-time)
- [x] `internal/crdt/retraction.go` — author-only retraction (`node_id` == target author AND `seq` strictly greater); `op_type: "retraction"` payload = new `Retraction{target_op_id}` proto message
- [x] `internal/crdt/equivocation.go` — `(node_id → seq → op_id)` index; emits `MisbehaviorProof{op_a, op_b}` on a fork; both ops retained (evidence preserved); `detected_by/at` left for Phase 4 verify
- [x] `proto/v1/frien.proto` — added `Retraction` message; regenerated `pkg/proto/v1`
- [x] `internal/crdt/crdt_test.go` — behavioral: replay idempotent; expiry by origin `expires_at` (late expired op never present); retraction LWW-by-seq (author-only, lower/equal seq ignored, non-author ignored); equivocation evidence preserved (both ops retained, proof carries both); malformed-envelope rejection
- [x] `internal/crdt/convergence_test.go` — **CvRDT join-semilattice property tests** via stdlib `testing/quick` (500 iters, fixed seed, custom `opList` generator over a shared id space; no new dependency):
  - [x] **Idempotence** — `Merge(a, a) == a`
  - [x] **Commutativity** — `Merge(a, b) == Merge(b, a)`
  - [x] **Associativity** — `Merge(Merge(a, b), c) == Merge(a, Merge(b, c))`
  - [x] **Monotonicity / inflationary join** — state never shrinks under merge
  - [x] **Order-independent convergence** — 3 replicas, different orders + duplicate re-delivery → identical canonical hash
  - [x] equality via `CanonicalHash` (sorted by `op_id`, fixed encoding)

### Sprint 3c — Scope router ✓
- [x] `internal/scope/router.go` — `Parse` (`local`/`zone:<name>`/`fleet`, zone name validated alnum+hyphen ≤64); `Router` with per-node subscription set (own zone + fleet always; extra zones for aggregators)
- [x] Egress + ingress scope enforcement (defense in depth): `ShouldSend` never sends `local`, sends `zone` only to in-zone peers; `Accept` drops received `local` and unsubscribed-zone ops
- [x] `internal/scope/router_test.go` — parse/round-trip/validation, egress matrix, ingress matrix, aggregator multi-zone subscription

### Sprint 3d — Per-scope anti-entropy engine ✓ (algorithmic core)
- [x] `internal/crdt/merkle.go` — per-scope op index (maintained on `Add`); `ScopeDigest` (root + count), `OpIDsInScope`, `Scopes`; retraction inherits target scope, control ops are fleet
- [x] `internal/crdt/antientropy.go` — `SyncScope` (per-scope root short-circuit) → `Reconcile` (set-difference pull, scope-gated via `AcceptFunc`, surfaces equivocation proofs); `EnvelopeScope` for ingress acceptance. Checkpoint floor is a documented seam (Phase 4)
- [x] `internal/crdt/simulation_test.go` — deterministic gossip sim (4 nodes, 2 zones, seeded pairing + 30% drop + 60-round partition/heal) proving every Phase 3 exit criterion below

### Sprint 3e — Live integration ✓
- [x] `internal/gossip/dispatch.go` — typed request/response stream protocol over raw QUIC (kind byte + length-prefixed protobuf): ping / ping-req / anti-entropy
- [x] `internal/gossip/manager.go` — session pool: accept inbound + dial/reuse outbound; one connection serves both directions
- [x] `internal/gossip/prober.go` — QUIC-backed `membership.Prober` (closes the Phase 2 deferral); probes piggyback membership updates incl. the node's own address
- [x] `internal/gossip/engine.go` — orchestrator: SWIM `Run` + per-scope anti-entropy loop; `OnPing`/`OnPingReq`/`OnAntiEntropy` handlers; `ingest` (scope `Accept` + `CheckSkew` + clock `Update` + per-scope cap) before `Add`; `Publish` (HLC + seq stamped); per-peer HLC watermark recorded (in-memory, `Watermarks()`; bbolt `peer_watermark` persistence lands with Phase 4 compaction that consumes it)
- [x] Daemon bootstrap (`cmd/friend`): `buildMesh` wires transport + `crdt.Clock` (loads/persists via `storage.MetaGet/Put`+`MetaKeyHLC`, periodic + on shutdown) + `OpSet` + `scope.Router` + engine; `CheckSkew` enforced at ingress
- [x] `ListPeers` admin RPC implemented via `PeerSource` over the engine roster; `GetStatus` peer_count now live
- [x] Live QUIC cluster integration tests — `TestClusterConvergesByScope` (fleet reaches all, zone only same-zone, out-of-zone excluded) and `TestClusterDetectsFailure` (node down → dead) over real QUIC+mTLS
- Note: inbound protection is a per-scope op cap (memory bound); creation-time admission (`internal/admission`) belongs on the local `Publish`/detector path (Phase 6), not on the anti-entropy backfill path where rate-dropping would break convergence

### Phase 3 Exit Criteria (proven by the deterministic simulation; live-cluster counterpart is Sprint 3e)
- [x] Zone-scoped threat op converges on in-scope peers; out-of-scope peer never receives it (enforced on both egress and ingress) — `TestGossipSimulationConvergesPerScope`
- [x] 3–5 node local cluster syncs a zone-scoped op within 2s — `TestClusterConvergesByScope` over real QUIC converges well within the bound (~0.2s)
- [x] Replayed op (duplicate `op_id`) rejected — `TestAddIdempotentOnReplay`; clock-skew rejection mechanism = `Clock.CheckSkew` (ingress call site in 3e)
- [x] Two ops at same `(node_id, seq)` with different content → equivocation proof, evidence preserved — `TestEquivocationPreservesEvidence`, `TestGossipPropagatesEquivocation`
- [x] Expired op not resurrected by late anti-entropy — asserted in the sim after partition heal
- [x] Deterministic simulation: union converges under reorder/drop/delay/partition (seeded) — convergence suite + gossip sim

### Deferred to Phase 4 (consciously not in Phase 3)
- Merkle **DAG** parent tracking / causal-history tamper-evidence (`parents` field stays in the envelope but is not gated on); equivocation here uses the `(node_id, seq)` index, not the DAG
- Signed **checkpoint** creation and WAL/DAG **compaction** (Phase 3 computes the watermark; Phase 4 acts on it)
- Delta-interval ack buffers as a bandwidth optimization (correctness already comes from idempotent union + anti-entropy backstop)

---

## Phase 4: Tamper-Evidence, Compaction, and Revocation (Sprint 4)

> See `docs/HARDENING_ROADMAP.md` for the self-audit of Phase 1-3 gaps this phase must
> close, the membership/anti-entropy hardening patterns to retrofit alongside it, and
> the detailed exit-criteria rationale (supersedes the summary below).

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

**Completed:** Phase 0 ✓, Phase 1 ✓, Phase 2 ✓, and Phase 3 (scoped CRDT state mesh, incl. live QUIC gossip integration) ✓

**Verified:**
- `go build ./...` — clean
- `go vet ./...` — clean
- `gofmt -l` — no diffs
- `govulncheck ./...` — no vulnerabilities
- `go test -race ./...` — all pass (config, errors, version, identity, storage, middleware, health, grpc, oplog, transport, membership, admission)
- End-to-end smoke: daemon starts → `frienctl status` over socket → `/healthz`+`/readyz` 200 → SIGTERM clean shutdown
- Restart smoke: WAL replay recovers prior lifecycle records (seq continues); corrupt WAL → daemon refuses to start

**Phase 2 delivered:** raw QUIC + mTLS peer transport (`tls.X25519MLKEM768` default), length-prefixed protobuf framing, highest-common version negotiation at handshake, transport-layer revocation hook, SWIM membership (incarnation/refutation/indirect-probe/bounded dissemination), and the admission controller (token-bucket budgets, coalescing, priority shedding).

**Next step (Phase 3):** scoped CRDT state mesh — HLC, expiring delta OR-Set, zone/scope router, anti-entropy. This phase also wires the QUIC-backed `membership.Prober` and the gossip pump that ships membership Updates + CRDT deltas between live nodes, and enforces `transport.clock_skew_window` against operation HLCs. `ListPeers` becomes implementable against `membership.MemberList`.

---

## Known Limitations and Notes

- `golangci-lint` and `govulncheck` are not installed in the local dev image; both run in CI (`.github/workflows/ci.yml`). `.golangci.yml` uses schema v2 (version pinned in CI).
- TLA+ spec (`specs/frien.tla`) is a Phase 0 skeleton: state + safety invariants are defined; the `Next` action relation is abstract and will be refined as each protocol (membership, quorum, quarantine, revocation) is implemented. Not yet wired into a TLC model-check CI job.
- Admin API has no Auth/RBAC interceptor yet (Unix-socket file permissions are the current access control). Auth, RBAC, rate-limit, validation, and audit interceptors slot into `middleware.Chain` in later phases.
- `oplog` request/op IDs use random tokens, not ULIDs; a ULID is adopted in Phase 3 where lexical time-ordering matters. Cross-node signature verification on replay is deferred to the Phase 4 verify layer (all Phase 1 WAL records are self-authored).
- Envelope signing in `oplog` is ed25519-only for now; PQC (ML-DSA-65) envelope signing over the wire is wired with transport in Phase 2+.
- Peer transport uses raw QUIC streams with length-prefixed protobuf framing (reusing `pkg/proto/v1` PeerService message types as the wire schema), not gRPC-over-QUIC. gRPC remains the admin API only.
- `transport.clock_skew_window` is validated in config but not yet enforced — it gates operations by origin HLC, which arrives with the Phase 3 CRDT layer. No placeholder is carried in the transport package.
- `membership` is decoupled from QUIC via the `Prober` interface and an injected clock/RNG; the live QUIC-backed Prober and the Update/delta gossip pump are wired in Phase 3. The 3-node exit criterion is currently proven by deterministic in-process simulation.
- `admission.stormFillThreshold` (0.5 node-budget fill ratio) is an internal tuning constant, not a config/wire value.
- `frienctl` implements `version` and `status`; remaining subcommands track their server-side RPCs.
- nftables adapter requires Linux; tests on non-Linux CI should skip enforcer tests via build tags
- Kubernetes adapter deferred to Phase 7
- OPA/Rego policy integration deferred until YAML policy engine is stable
