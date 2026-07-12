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
> close, the membership/anti-entropy hardening patterns retrofitted alongside it, and
> the detailed exit-criteria rationale (supersedes the summary below).

- [x] `internal/verify/verify.go` — classical (ed25519) signature verification against a
      per-node/operator `KeyStore`, wired into `gossip.Engine.ingest` before an op is
      trusted; keys learned opportunistically from already CA-verified mTLS sessions
- [ ] Merkle DAG parent tracking / causal-history verification — **not built**. The
      `parents` field exists on the wire (`OperationEnvelope.parents`) but nothing reads
      or verifies it; equivocation detection uses the `(node_id, seq)` index instead (see
      below), which is what Phase 3 already committed to. Root-hash exchange for cheap
      divergence detection above a shared checkpoint is also not built — anti-entropy
      today always compares live per-scope Merkle digests (`crdt.ScopeDigest`), not a
      checkpoint-anchored root. Left as a deliberate scope decision (see rationale below).
- [x] Equivocation detection and proof — was already done in Phase 3
      (`crdt.detectEquivocation`); this phase completed it: `crdt.StampAttribution` fills
      `id`/`detected_by`/`detected_at`, called from `Engine.ingest` as soon as a proof
      surfaces
- [x] `internal/checkpoint/checkpoint.go` — signed, chained checkpoint creation
      (`Build`/`Verify`, `prev_checkpoint` chain, `tree_head` over exactly what a cut
      retired)
- [x] `internal/checkpoint/watermarks.go` + `compactor.go` — peer-acknowledged safe-floor
      computation (`PeerWatermarks.SafeFloor`, nil unless every live peer has been
      directly observed) and the `Compactor` loop wired into `cmd/friend/main.go`
- [x] `internal/crdt/opset.go` — `OpSet.CompactBelow` bounds the in-memory op set (the
      actual replicated-state growth point; the on-disk WAL is only ever used for
      `internal/oplog`'s self-authored lifecycle log, never for gossip ops, so there is no
      separate "WAL compaction" to build against — see `internal/storage/wal.go`'s own
      comment on this)
- [x] `internal/revocation/revocation.go` — two-phase (`tainted` → `revoked`)
      operator-signed revocation set, wired into `gossip.Engine.ingest` and the
      previously-nil `transport.RevocationChecker` seam; a fresh revocation also actively
      drops any already-open session

### Phase 4 Exit Criteria
- [x] Conflicting operations produce a complete misbehavior proof (with attribution) —
      `crdt.StampAttribution` + `Engine.ingest`; proven in `internal/gossip`'s
      `TestIngestStampsEquivocationAttribution`
- [x] Revoked cert rejected mesh-wide — proven over a live two-node QUIC cluster
      (`TestRevocationInjectPropagatesAndAppliesLocally`) and against a real transport
      handshake (`TestRevocationSetSatisfiesRevocationChecker`); "quarantine" in the sense
      of excluding a revoked node from a quorum vote has no home yet since quorum/policy
      is Phase 5 — noted as a Phase 5 dependency, not silently dropped
- [x] Op-set size stays bounded across a compaction cycle with a partitioned-then-healed
      peer — `SafeFloor` requires every live peer's direct confirmation before advancing,
      by construction never compacts past what an unconfirmed live peer might still need;
      proven end-to-end in `TestClusterCompactsFleetScopeOnceAllPeersConfirm`
- [x] A fault-injected panic in the membership tick loop is recovered and resumes — this
      was actually closed in the Phase 1-3 hardening pass (`internal/gossip/supervise.go`),
      not deferred to Phase 4 as the original placeholder implied

### Known Phase 4 scope decisions (not gaps left open by mistake)
- **Quorum-exclusion of a revoked/tainted node** ("remove from EligibleVoters") has no
  home yet — `internal/policy`/quorum don't exist until Phase 5. Revocation today
  guarantees transport-level rejection and mesh-wide propagation, not yet
  enforcement-quorum exclusion.
- ~~DAG/parents causal tracking~~ and ~~only-fleet-scope compaction~~ were both closed
  in the Phase 4 follow-up below the same day; struck through rather than deleted so the
  original rationale for deferring them stays visible.

### Phase 4 follow-up (2026-07-11, same day): DAG/parents and zone-scope compaction
Two of Phase 4's four scope decisions closed in a follow-up pass:
- [x] `internal/crdt/dag.go` — every op's `parents` names the publishing node's own
      immediately prior op in the *same scope* (a per-scope self-chain — crossing scopes
      broke a fleet op's convergence to an out-of-zone peer during testing, see the
      package's `LastOpIDInScope` doc comment for the mechanism). Admission is
      parent-gated: an op with an unseen parent is buffered (`OpSet.drainPending`,
      capped, fails open past the cap rather than dropping data or starving forever) and
      retried once the parent arrives or is found compacted-tombstoned.
      `OpSet.ChainRoot` gives a compaction-stable per-node digest.
- [x] Root-hash exchange anchored to a checkpoint — the `since_checkpoint`/`root_hash`
      fields already reserved on `AntiEntropyRequest` since Phase 3 are now populated
      from `checkpoint.Compactor.Latest(scopeKey)` and compared on the responder side: a
      matching checkpoint id with a mismatched `tree_head` is a cheap, op-list-free
      tamper/corruption signal, logged as a warning (`gossip.Engine.checkCheckpointDivergence`).
- [x] Zone-scope compaction — `membership.Member`/`Update` carry each peer's
      self-reported `Zone` (piggybacked on `PeerUpdate` like addresses already were);
      `gossip.Engine.LiveZonePeers(zone)` restricts a zone's SafeFloor requirement to
      that zone's actual live membership instead of the whole fleet.
      `checkpoint.PeerWatermarks` became scope-keyed (previously one number per peer,
      silently conflating separate scopes' anti-entropy rounds — a latent bug this pass
      found and fixed, not something zone compaction newly introduced).
      `checkpoint.Compactor` compacts every subscribed scope independently each round
      (its own `LivePeersFunc` dispatch, its own checkpoint chain per scope —
      `Checkpoint` gained a `scope` field so a zone checkpoint doesn't leak fleet-wide).
- [x] **Real bug found and fixed while wiring zone compaction**:
      `crdt.OpSet.CompactBelow` took a cut keyed only by `node_id`, applied across *all*
      scopes that node published into. A node's seq counter is global across scopes it
      publishes into, so a zone-confirmed cut and a fleet-confirmed cut for the same
      origin are evidenced completely independently — without a scope filter, compacting
      past a zone-confirmed cut would also have deleted that origin's interleaved
      fleet-scoped ops that no fleet peer had ever confirmed holding. `CompactBelow` now
      takes the scope it's compacting and only removes that scope's ops
      (`TestCompactBelowIsScopedNotGlobal` reproduces the bug against the pre-fix
      behavior).
- [x] Operator CLI/RPC to mint+inject revocations and checkpoints —
      `InjectOperatorOp`/`TriggerCompaction` admin RPCs (gated by
      `admin_api.read_only`) and `frienctl revoke sign|submit` / `frienctl
      compact`. `revoke sign` runs fully offline against the operator private
      key (never sent to a node); `revoke submit` only ever forwards
      already-signed bytes to `gossip.Engine.Ingest`.
- [x] CA/trust-bundle overlap-window rotation — `identity.TrustBundle` +
      `transport.Transport.RefreshTrust`/`RotateCA` admin RPC / `frienctl
      rotate-ca`. Proven over live QUIC/mTLS handshakes
      (`TestTrustRotationOverlapWindow`), not just pool algebra.

All four Phase 4 scope decisions are now closed as of 2026-07-11.

### Scope-seq follow-up (2026-07-11, later the same day): the interleaved-scope watermark stall — now fixed
The item above was originally shipped as "found and documented, deliberately not
fixed." The user asked for it to be closed properly before Phase 5, so it was:
- [x] `OperationEnvelope.scope_seq` (proto field 16) — a second per-node counter,
      distinct from the existing global `seq`, assigned per (node, scope) and covered by
      the envelope signature (`identity.CanonicalSignedContent` now takes it).
      `gossip.Engine.nextScopeSeq` hands these out starting at 1 per scope key; `seq`
      itself is unchanged and still backs equivocation detection, which stays
      global-per-node by design (a fork is a fork regardless of scope).
- [x] `crdt.OpSet.scopeSeqIndex` (scope → node → scope_seq → op_id, kept forever
      alongside `seqIndex`) — `indexScope` populates it; `ScopeState`'s contiguous
      watermark now scans this instead of the old scope-filtered view of `seqIndex`, so
      it's genuinely contiguous per scope regardless of what else that node published in
      between. `MissingInRange`'s watermark comparison and gap-fill ordering, and
      `CompactBelow`'s cut comparison, all switched from the envelope's global `seq` to
      `scope_seq` accordingly. Equivocation-sibling detection (the watermark-bypass for
      forked ops) stays keyed on global `seq`, unchanged — that's a different concern
      than watermark contiguity.
- [x] Proven at three levels: `crdt.TestScopeStateAdvancesDespiteInterleavedScopes`
      (OpSet layer, hand-built interleaved envelopes),
      `checkpoint.TestCompactorHandlesInterleavedScopesFromSingleOrigin` (whole
      Compactor, both scopes actually compact from one interleaved origin), and the full
      existing suite (`gossip.TestRevocationInjectPropagatesAndAppliesLocally` and the
      anti-entropy range-sync tests) re-validated against the new scope_seq-based
      watermark path — all green under `go test -race ./...`.
- **Rejected alternative, for the record**: a "global full-node-history contiguity"
  version was tried first and reverted — it fixes the single-origin interleaving case
  but breaks the cross-peer case instead (an out-of-zone peer that never receives that
  origin's zone ops sees a permanent gap and gets stuck computing even the *fleet*
  watermark for that origin). scope_seq as a genuinely separate counter is what avoids
  that trade-off.
- **Found while fixing this**: `scope_seq == 0` is a reserved sentinel (the same
  "nothing held yet" default `ScopeState` returns for an origin it has never observed),
  so a real op must never carry it — `nextScopeSeq` starts at 1 by construction, and one
  test helper that defaulted to 0 (`revocation_integration_test.go`) silently failed to
  converge via anti-entropy until fixed. Not a production-reachable bug (only
  hand-constructed envelopes can hit it), but worth knowing if a future admin/injection
  path ever constructs envelopes by hand again (see `cmd/frienctl/revoke.go`, which
  already sets `ScopeSeq: 1` for exactly this reason).

---

## Phase 5: Signed Policy and Fail-Safe Enforcement (Sprint 5)

Built in four tested sub-sprints (5a policy core, 5b enforcer, 5c audit/explain,
5d daemon+CLI+process wiring), mirroring the Phase 3/4 staging. All packages green
under `go test -race ./...`.

### 5a — Policy decision core (pure, no I/O)
- [x] `internal/policy/policy.go` — operator-signed, versioned `Policy` (YAML,
      matches FRIEN_ARCHITECTURE §Layer 5); `Load`/`Parse`/`validate`,
      `CanonicalBytes` (deterministic, number-form-stable), `Verify`/`Sign`/
      `SignDetached` against the pinned operator ed25519 key. A node never trusts
      an unsigned/forged policy.
- [x] `internal/policy/quorum.go` — partition-safe weighted quorum: distinct
      identities only (dedup by fingerprint→node), trust-tier weighting
      (`DefaultTrustWeights` standard/trusted/high = 1/3/5), bounded window by
      **local receive time**, revoked/tainted and sub-`min_confidence` excluded;
      `PartitionState.IsMajority` (strict majority of known distinct identities).
- [x] `internal/policy/protect.go` — protected-CIDR + self-plane checks;
      `DefaultProtectedCIDRs` (IPv6 mandatory — IPv4-only list is a config error),
      CIDR-overlap refusal, `deny_if_target_is_admin_endpoint`.
- [x] `internal/policy/engine.go` — `Evaluate`: no-record → protected(deny) →
      quorum → partition(fleet) → observe-vs-enforce → kernel-timeout gate, in
      that safety order; `Decision.ToProto`. Full unit tests (engine/quorum/
      protect/policy_test.go).

### 5b — Enforcer (owns rule lifetime; least-privilege split)
- [x] `internal/enforcer/adapter.go` — `Adapter` contract (fail-open removal,
      fail-closed apply; frien chains only, never host baseline).
- [x] `internal/enforcer/nftables.go` (`//go:build linux`) — nftables backend
      via `nft`: per-element kernel `timeout` (self-expiry), token stored as
      element comment, isolated `inet frien` table/sets/chain. Cross-compiles for
      linux; runtime-tested only on a real Linux host (documented).
- [x] `internal/enforcer/mem_adapter.go` — cross-platform in-memory adapter that
      **simulates kernel expiry** (injectable clock); the observe/dry-run and
      non-Linux backend, and what the exit-criteria unit tests run against.
- [x] `internal/enforcer/rollback.go` — durable rollback-token store (bbolt);
      persisted before the kernel write so a crash is always reconcilable.
- [x] `internal/enforcer/deadman.go` — dead-man's switch (heartbeat monitor,
      re-arming, `frien_deadman_triggered_total`).
- [x] `internal/enforcer/enforcer.go` — orchestrator: per-adapter mode, `Apply`
      (persist-then-write), `Rollback`, `FlushAll`, `ForceObserve`, `Reconcile`.
- [x] `internal/enforcer/ipc.go`+`client.go`+`server.go` — length-prefixed JSON
      IPC over a Unix socket between the unprivileged daemon and the privileged
      helper; one `Client` contract, two impls (`InProcClient`, `SocketClient`);
      every request is an implicit heartbeat. Tests exercise the socket path
      in-process.

### 5c — Audit + explain
- [x] `internal/audit/audit.go` — immutable, hash-linked audit log (bbolt);
      `Append`/`Get`/`List`/`Verify` (detects tamper and deletion).
- [x] `internal/audit/explain.go` — `Explanation` projection of a `policy.Decision`
      + rollback token + audit id → `ExplainDecisionResponse`.

### 5d — Wiring (daemon, RPCs, CLI, process, receive-time)
- [x] `internal/coordinator/coordinator.go` — gathers contributions from the op
      set + membership + receive-times, runs `policy.Evaluate`, applies enforced
      decisions through the `Client`, audits, publishes the `EnforcementDecision`
      op; dedupes so a standing threat enforces once. Injected interfaces; the
      five exit criteria are proven here end-to-end through the real client.
- [x] `internal/gossip/engine.go` — local receive-time seam (`noteReceived`/
      `ReceivedAt`), `PresentThreatOps`, `IsNodeExcluded`, `PartitionView`.
- [x] `internal/revocation` — `IsNodeExcluded(nodeID)` (quorum-eligibility query;
      closes the Phase 4 "revocation has no quorum effect yet" gap).
- [x] `internal/grpc/api.go` — `ExplainDecision`, `SetEnforceMode`,
      `RollbackEnforcement`, `ListEnforcements`, `Breakglass`, `TestPolicy` wired
      to an `EnforcementService` (read-only-guarded where mutating).
- [x] `cmd/friend` — `buildEnforcement` (in-process enforcer or socket client to
      a separate frien-enforcer), verified-policy load + self-plane protection,
      heartbeat + sweep loops, reconcile-on-start; `enforcementService` glue
      (mode-set/rollback/breakglass audited, 2/min breakglass limiter, TestPolicy
      dry-run). Service tests in `cmd/friend`.
- [x] `cmd/frien-enforcer` — the privileged helper process: own rollback store,
      nftables/mem backend, dead-man's switch, reconcile-on-start, IPC server.
- [x] `cmd/frienctl` — `explain`, `mode set`, `rollback`, `enforcements list`,
      `breakglass`, `policy sign` (offline), `policy test`.

### Phase 5 Exit Criteria
- [x] Observe mode logs/explains without applying rules —
      `coordinator.TestObserveModeExplainsWithoutApplying` (no rule, no publish);
      `cmd/friend.TestServiceExplainNoRecord`.
- [x] Enforce mode creates self-expiring nftables entry —
      `enforcer.TestRuleSelfExpires` (rule gone after timeout, no explicit
      removal) + `coordinator.TestEnforceModeAppliesAndPublishes` end-to-end
      through the client; nftables `timeout` on Linux is the production path.
- [x] Protected target is denied by policy with explanation —
      `coordinator.TestProtectedTargetDenied`,
      `policy.TestEvaluateProtectedBeatsQuorum`,
      `cmd/friend.TestServiceTestPolicyProtectedDenied`.
- [x] Minority partition refuses fleet-scoped enforcement —
      `coordinator.TestMinorityPartitionRefusesFleet` (local scope still enforces:
      `TestLocalScopeEnforcesUnderPartition`).
- [x] Daemon crash leaves no leaked rule past kernel timeout —
      `enforcer.TestReconcileAfterCrash` (token persisted pre-crash, kernel-expired
      while down, closed out on restart and never resurrected).

### Phase 5 hardening sprint (2026-07-12)
A grounded hardening pass (patterns extracted from mature OSS firewall/decision
layers — see private research notes, not named in-repo) closed four gaps found
after the initial Phase 5 build; all green under `go test -race ./...`, host +
`GOOS=linux` builds clean.
- [x] **New-rule rate cap (was: configured but unenforced).** `policy.max_new_rules_per_minute`
      is now enforced at the *privileged enforcer* boundary (`enforcer.rateLimiter`,
      token bucket), so even a runaway/compromised daemon cannot make frien install
      unbounded rules. Over-cap applies are shed fail-safe (no rule, no token, no
      audit). `enforcer.TestRateLimitShedsNewRules`.
- [x] **Dedup against real active rules (was: in-memory map, lost on restart, never
      re-enforced after expiry).** The coordinator now dedups by snapshotting the
      enforcer's *actual* active rules once per sweep (the "diff live state" pattern),
      which is crash-safe by construction, self-pruning, and re-enforces a still-present
      threat once its rule kernel-expires. `coordinator.TestReEnforcesAfterRuleExpires`,
      `TestRestartSafeDedup`.
- [x] **Forward-chain enforcement (was: input hook only — transit traffic on a gateway
      was never blocked).** The nft adapter now installs one filter chain per hook
      (input + forward by default; `chain_forward: "-"` disables), configurable
      DROP/REJECT verdict (`enforcement.nftables.deny_action`), all in one atomic
      `nft -f` transaction. `internal/enforcer/nftables.go` (Linux build; validated by
      cross-compile + inspection — runtime path needs the Linux integration env below).
- [x] **Sybil-resistant trust tiers (was: self-declared → every peer treated as
      `standard`).** A node's quorum trust tier is now bound to its CA-signed leaf
      certificate's OU (`identity.TrustTierFromCert`), learned at the mTLS handshake
      (`transport.Session.TrustTier` → `verify.KeyStore.RegisterTier`) and seeded for
      self from its own cert — a node cannot inflate its own weight past what its cert
      authorizes. `identity.TestTrustTierFromCert`, `verify.TestRegisterAndReadTier`.

---

## Phase 6: Detection, Visualization, and Demo (Sprint 6) ✓

Built as: threat data layer + log-file detectors + a **Go TUI** (replacing the
originally-planned Next.js panel — see the decision note below) + a local demo
cluster. All green under `go test -race ./...`, host + `GOOS=linux` builds clean.

### 6a — Threat ingest + observability RPCs
- [x] `internal/reporter/reporter.go` — the single local threat-ingest choke
      point: validate → admission (coalesce/shed/budget) → stamp ThreatRecord →
      publish signed op. Used by both the ReportThreat RPC and every detector.
- [x] `proto/v1/frien.proto` — added `ListThreats`, `GetStats`, `ListAudit` read
      RPCs + messages (`DecisionStat`, `AuditEntrySummary`); regenerated with
      **buf** (no `protoc` on this box — `buf.gen.yaml` mirrors the Makefile and
      reproduces the prior output byte-for-byte).
- [x] `internal/grpc/api.go` + `cmd/friend/observability.go` — implemented
      `ReportThreat` (admission→publish), `ListThreats`, `GetStats` (threats/
      membership/enforcement counters + quorum decision feed), `ListAudit`,
      behind an `ObservabilityService` the daemon backs with the engine + audit
      log + enforcement client.

### 6b — Detectors (log-file backends)
- [x] `internal/detector/detector.go` — `Detector` interface, poll-based
      `tailFile` (no inotify dep, restart-safe start-at-EOF, rotation-aware), a
      sliding-`windowCounter` with per-key cooldown, and a panic-recovering
      `Manager`.
- [x] `internal/detector/ssh_bruteforce.go` — auth-log failed-login detector
      (from/rhost IP extraction) → high-severity threat.
- [x] `internal/detector/http_rate_anomaly.go` — access-log request-rate
      detector → medium-severity threat. Both wired into `cmd/friend`.

### 6c — Operator TUI (Bubble Tea) — replaces the Next.js panel
- [x] `internal/tui/` — `frienctl dashboard` (alias `tui`): a live terminal
      dashboard over the local admin socket (same trust boundary as frienctl, no
      new network surface). `render.go` has pure, unit-tested primitives
      (eighth-block horizontal bar charts, sparklines, two-tone gauges, stat
      tiles); `model.go` is the Bubble Tea model with 4 tabs (Overview /
      Threats / Enforcement / Audit), history ring-buffers for sparklines, and a
      fault-tolerant fetch (per-RPC-tolerant, keeps last-good on disconnect).
      Render + model tests; frames visually verified.
- [x] `cmd/frienctl` — `dashboard` and `report` subcommands (`report` injects a
      threat through ReportThreat for demos/testing).

### 6d — Demo cluster
- [x] `scripts/gen-certs.go` — verified cross-platform PKI generator (CA +
      per-node leaf certs with the trust tier in the OU + operator keypair);
      proven to produce certs the identity layer loads with correct tiers.
- [x] `scripts/demo/` — `run-cluster.sh` (3-node mesh: core-1 trusted, edge-2/3
      standard), `attack.sh` (simulated SSH brute-force feeding every node's
      detector → distinct-identity quorum), `stop-cluster.sh`, `policy.yaml`,
      `README.md`. Orchestration scripts are Linux/macOS, validated by
      inspection (they wire together already-tested components).

### Decision: TUI instead of Next.js admin panel
The originally-listed "Dashboard BFF and Next.js admin panel" was **deliberately
replaced** by the Go TUI for the OSS core, because: frien is headless/local-first
(admin binds to a local socket — a web panel would add a network-exposed admin
surface); fleet-wide visualization is already the OTel→Grafana path (Layer 9
avoids a per-node dashboard BFF as a SPOF); the "managed dashboard/BFF" is a
**commercial** add-on in the business model, not OSS core; and a Go TUI keeps one
language/binary/supply-chain (no Node/npm). The Next.js dashboard is re-scoped as
the commercial, OTel-fed fleet dashboard — not part of the OSS Phase 6.

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

**Completed:** Phase 0 ✓, Phase 1 ✓, Phase 2 ✓, Phase 3 (scoped CRDT state mesh, incl. live
QUIC gossip integration) ✓, Phase 4 (tamper-evidence, compaction, revocation) ✓, and
Phase 5 (signed policy + fail-safe enforcement) ✓ — see the Phase 5 section above for the
four tested sub-sprints and how each of the five exit criteria is proven.

**Phase 5 delivered:** the pure policy decision core (`internal/policy`: signed/versioned
policy, partition-safe weighted quorum by local-receive-time, protected-CIDR/self-plane,
observe-first `Evaluate`); the fail-safe enforcer (`internal/enforcer`: kernel-timeout
nftables backend + kernel-expiry-simulating in-memory backend, dead-man's switch, durable
bbolt rollback tokens, crash reconciliation) split into an unprivileged daemon + a
privileged `frien-enforcer` helper over a length-prefixed-JSON Unix-socket IPC where every
request is a heartbeat; the immutable hash-linked audit log + explain projection
(`internal/audit`); the decision coordinator (`internal/coordinator`) that turns present
threats into audited, published, self-expiring enforcement; the six Phase-5 admin RPCs; and
the `frienctl explain / mode set / rollback / enforcements list / breakglass / policy
sign|test` commands. Revocation now has a quorum effect (`revocation.IsNodeExcluded`),
closing the Phase 4 dependency.

**Production hardening of Phases 1–3 ✓** (see `docs/HARDENING_ROADMAP.md` for the full
gap audit and rationale). Twelve validated sprints closed every self-audited fault-
tolerance gap: parallel indirect probing; local-health awareness scaling probe/suspicion
timing; address-conflict detection on rejoin; bounded/prioritized broadcast queue;
supervised (panic-recovering) gossip loops; self-managed admission coalescer expiry;
atomic per-scope op cap; jittered/exponential seed rejoin; capped+paged anti-entropy
responses; confirmation-accelerated suspicion (wire: `PeerUpdate.from_node_id`);
range-based anti-entropy requests (wire: `have_seqs`+`have_above`); and congestion-
adaptive (AIMD) gossip fan-out.

**Phase 4 delivered:** classical signature verification wired into gossip ingest
(`internal/verify`), equivocation proof attribution completed (`crdt.StampAttribution`),
peer-acknowledged compaction with signed chained checkpoints (`internal/checkpoint`),
and two-phase operator-signed revocation wired into both gossip ingest and the
previously-nil transport `RevocationChecker` seam (`internal/revocation`). Identity
certificate renewal also moved from a fixed threshold to a jittered half-life model
(`internal/identity`), closing a fleet-wide-renewal-storm risk found during this pass.

**Verified:**
- `go build ./...` — clean
- `go vet ./...` — clean
- `gofmt` — clean (content-level; the Windows dev checkout is CRLF on disk, which makes
  `gofmt -l` flag every file locally regardless of content — verified by stripping CR
  before comparing)
- `go test -race ./...` — all pass across every package (crdt, gossip, membership,
  admission, checkpoint, revocation, verify, identity, storage, transport, grpc, oplog,
  middleware, health, config, errors, version, scope)
- `govulncheck ./...` — **not clean**: flags 11 Go standard-library vulnerabilities, all
  fixed in go1.26.2 (this toolchain is go1.26.1) — an environment/toolchain gap, not
  something introduced by this session's changes. Bumping the Go toolchain is a
  follow-up, not done here since it's an environment change outside this task's scope.
- Live two-node/three-node QUIC cluster integration tests: scope-based convergence,
  failure detection, signed-op verification (accept/reject/tamper/forged-signer),
  equivocation attribution, compaction-with-peer-confirmation, and revocation
  inject→apply→propagate→re-apply-independently, all proven end-to-end, not just
  unit-tested in isolation
- End-to-end smoke: daemon starts → `frienctl status` over socket → `/healthz`+`/readyz` 200 → SIGTERM clean shutdown
- Restart smoke: WAL replay recovers prior lifecycle records (seq continues); corrupt WAL → daemon refuses to start

**Phase 2 delivered:** raw QUIC + mTLS peer transport (`tls.X25519MLKEM768` default), length-prefixed protobuf framing, highest-common version negotiation at handshake, transport-layer revocation hook, SWIM membership (incarnation/refutation/indirect-probe/bounded dissemination), and the admission controller (token-bucket budgets, coalescing, priority shedding).

**Next step (Phase 3):** scoped CRDT state mesh — HLC, expiring delta OR-Set, zone/scope router, anti-entropy. This phase also wires the QUIC-backed `membership.Prober` and the gossip pump that ships membership Updates + CRDT deltas between live nodes, and enforces `transport.clock_skew_window` against operation HLCs. `ListPeers` becomes implementable against `membership.MemberList`.

---

## Known Limitations and Notes

- `golangci-lint` and `govulncheck` are not installed in the local dev image; both run in CI (`.github/workflows/ci.yml`). `.golangci.yml` uses schema v2 (version pinned in CI).
- TLA+ spec (`specs/frien.tla`) is a Phase 0 skeleton: state + safety invariants are defined; the `Next` action relation is abstract and will be refined as each protocol (membership, quorum, quarantine, revocation) is implemented. Not yet wired into a TLC model-check CI job.
- Admin API has no Auth/RBAC interceptor yet (Unix-socket file permissions are the current access control). Auth, RBAC, rate-limit, validation, and audit interceptors slot into `middleware.Chain` in later phases.
- `oplog` request/op IDs use random tokens, not ULIDs; a ULID is adopted in Phase 3 where lexical time-ordering matters. `oplog`'s own WAL replay stays self-authored-only verification (it is the node-lifecycle log, never the gossip CRDT set) — this is unrelated to the Phase 4 `internal/verify` layer, which verifies cross-node envelopes on the gossip ingest path, not `oplog`'s WAL.
- Envelope signing in `oplog` is ed25519-only for now; PQC (ML-DSA-65) envelope signing over the wire is wired with transport in Phase 2+.
- Peer transport uses raw QUIC streams with length-prefixed protobuf framing (reusing `pkg/proto/v1` PeerService message types as the wire schema), not gRPC-over-QUIC. gRPC remains the admin API only.
- `transport.clock_skew_window` is validated in config but not yet enforced — it gates operations by origin HLC, which arrives with the Phase 3 CRDT layer. No placeholder is carried in the transport package.
- `membership` is decoupled from QUIC via the `Prober` interface and an injected clock/RNG; the live QUIC-backed Prober and the Update/delta gossip pump are wired in Phase 3. The 3-node exit criterion is currently proven by deterministic in-process simulation.
- `admission.stormFillThreshold` (0.5 node-budget fill ratio) is an internal tuning constant, not a config/wire value.
- `frienctl` implements `version` and `status`; remaining subcommands track their server-side RPCs.
- nftables adapter requires Linux; tests on non-Linux CI should skip enforcer tests via build tags
- Kubernetes adapter deferred to Phase 7
- OPA/Rego policy integration deferred until YAML policy engine is stable
- `internal/verify` checks the classical (ed25519) signature only; PQC (ML-DSA-65) envelope verification is not performed since PQC public keys are not yet distributed mesh-wide (tracked as a Phase 2/7 follow-up in the PQC notes above). A present `pqc_signature` field neither passes nor fails verification on its own.
- `internal/checkpoint`'s Compactor only compacts the fleet scope; see the package doc for why zone-scope compaction needs peer-zone metadata membership doesn't carry yet.
- ~~Revoking/tainting a node has no effect on quorum eligibility yet~~ — **closed in Phase 5**: `revocation.Set.IsNodeExcluded(nodeID)` is consulted by the coordinator so a tainted/revoked identity's reports no longer count toward `policy` quorum, on top of the existing mesh-wide propagation and transport-level rejection.
- An operator tool to actually mint and inject a `RevocationRecord` (a `frienctl revoke` subcommand or an admin RPC) does not exist yet; `internal/revocation.Build` and `gossip.Engine.Ingest` are the building blocks such a tool would call. Same story for `internal/checkpoint`'s `Build`/`Verify` if an operator ever needs to construct one out-of-band.
- CA/trust-bundle rotation still uses a single static pool loaded once at startup (`identity.LoadCACertPool`), not a prepare/activate overlap window; only per-node leaf-certificate renewal timing was hardened this pass (jittered half-life). Bundle rotation safety is a Phase 7+ CA-integration concern per the existing PQC/CA staging notes.
- `govulncheck` currently flags 11 Go standard-library vulnerabilities on this toolchain (go1.26.1; fixed in go1.26.2) — an environment gap, not a code issue; bumping the toolchain is a follow-up.
- ~~**Phase 5 — peer trust tiers not yet gossiped**~~ — **closed in the Phase 5 hardening sprint**: trust tiers are now bound to the CA-signed leaf certificate (`identity.TrustTierFromCert`, read from the OU), learned at the mTLS handshake and consulted by quorum. This is Sybil-resistant (a node cannot self-declare a higher tier than its cert authorizes) — strictly better than gossiping a mutable self-report. Issuing certs with a tier OU is a PKI/operator convention; a node with no tier OU weighs `standard`.
- **Phase 5 — nftables backend is Linux-runtime-only, and still shells out to `nft`:** `internal/enforcer/nftables.go` is `//go:build linux`; it cross-compiles and is correct-by-inspection (now with per-hook input+forward chains and DROP/REJECT), but is exercised only on a real Linux host with `CAP_NET_ADMIN`. All platform-independent logic (self-expiry, rollback, reconcile, rate cap, dead-man's switch, IPC) is unit-tested against the kernel-expiry-simulating `MemAdapter`, the default backend off-Linux and in observe/dry-run. **Tracked follow-up (deferred, not an oversight):** migrate the backend from shelling out to `nft` to the netlink library (`github.com/google/nftables`) for atomic transactions, no CLI-output parsing, and reconcile-by-`GetSetElements` — plus a privileged-Linux integration job (container/netns) that actually runs it. Deferred this pass because (a) the netlink dependency's transitive set does not resolve from the local module cache offline (version-mismatched `x/sys`, missing `vishvananda/*`), so adding it blind risks breaking the build, and (b) there is no Linux runtime here to test it against — the real prerequisite is that CI environment.
- **Phase 5 — enforcer process model:** production uses the least-privilege split (`enforcement.enforcer_socket` set → daemon forwards to a separate privileged `frien-enforcer`). With the socket unset the daemon runs an in-process enforcer (single-binary/dev, or observe-only where no real firewall exists). Both share one `enforcer.Client` contract.
- **Phase 5 — TestPolicy is single-sample + active-policy-only:** `frienctl policy test` evaluates one representative contribution against the *active* policy (no out-of-band policy store yet — a Phase 7 concern) and asks "would this enforce if the node were promoted and in a healthy partition", rather than replaying real fleet quorum.
