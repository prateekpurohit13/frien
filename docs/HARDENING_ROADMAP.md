# frien — Production Hardening Roadmap

This document records (1) concrete fault-tolerance gaps found by auditing frien's own
Phase 1–3 code, and (2) architectural patterns identified as worth adopting to make
frien production-grade — sourced from independent research into how comparable
distributed systems (gossip/CRDT mesh systems, SWIM-based membership libraries,
collaborative security-detection engines, runtime-security detectors and response
engines, and workload-identity/attestation systems) solve the same class of problems.
No specific external project names are recorded here by policy — this file states the
pattern and the rationale, not the source.

Last updated: 2026-07-10.

---

## 1. Known gaps in the current implementation (self-audit)

Found by direct code review of `internal/membership`, `internal/gossip`, `internal/crdt`,
`internal/storage`, `internal/oplog`, `internal/transport`, `internal/admission`.

| # | Gap | Location | Risk |
|---|---|---|---|
| 1 | No compaction/eviction anywhere — the op set, seq index, and scope index only ever grow | `internal/crdt/opset.go` (Add/Merge paths); `internal/storage/wal.go` (compaction explicitly deferred) | Unbounded memory/disk growth on a long-lived or high-churn mesh |
| 2 | Anti-entropy reconciliation sends the full missing-op list in one response, no chunking or backpressure | `internal/gossip/engine.go` (`OnAntiEntropy` handler) | A single very large message after a long partition heal; no incremental catch-up |
| 3 | Per-scope op cap is a check-then-act race and is optional (`0` = unlimited) | `internal/gossip/engine.go` (`ingest`) | A peer forging high sequence numbers can grow local state without bound |
| 4 | `RevocationChecker` defaults to nil (never revokes) until Phase 4 ships a real implementation | `internal/transport/tls.go`, `internal/transport/quic.go` | A compromised/pulled peer identity can keep connecting mesh-wide today |
| 5 | No cross-node signature verification on WAL/oplog replay — unknown keys are silently accepted | `internal/oplog/oplog.go` | A malicious or corrupted peer-authored envelope isn't cryptographically checked before being trusted locally |
| 6 | The SWIM driver's periodic tick runs in an unsupervised goroutine with no panic recovery or restart | `internal/gossip/engine.go` (`go e.swim.Run(ctx)`) | A single panic silently freezes failure detection fleet-wide for that node |
| 7 | The admission coalescer's `Expire()` needs to be verified as wired to a periodic caller | `internal/admission/admission.go`, `cmd/friend/main.go` | Possible unbounded growth of coalescing groups if never called |
| 8 | The causal-parent (`parents`) field referenced in planning docs is not actually used by `opset`/`equivocation`/`retraction` today | `internal/crdt/*.go` | Confirm the field exists and is wired before Phase 4's DAG work assumes it does |

**What already exists as a foundation for Phase 4** (so it isn't built twice):
a per-origin HLC watermark map built specifically for a stable compaction cut
(`internal/gossip/engine.go`), an end-to-end `MisbehaviorProof` struct already produced
on equivocation (missing only `detected_by`/`detected_at` stamping), a `CheckpointID`
field already reserved on the snapshot struct, and a nil-safe `RevocationChecker` seam
in the transport layer waiting for a real implementation to be injected.

---

## 2. Patterns to retrofit into Phase 2/3 (membership + anti-entropy hardening)

These close real correctness/availability gaps found above and should land before or
alongside Phase 4, since Phase 4's quorum/enforcement guarantees are only as strong as
the membership and state-sync layers underneath them.

1. **Local-health-aware adaptive timing.** Maintain a small local health score that
   increases when the node itself fails to respond to a probe in time (GC pause, CPU
   starvation, I/O stall) and decreases on successful probes. Scale the node's own
   probe interval and derived suspicion timeout by this score. This directly prevents
   a temporarily slow-but-alive node from spuriously accusing healthy peers, and is the
   fix for gap #6's failure mode class (a stalled goroutine currently has no self-
   correcting mechanism).

2. **Confirmation-accelerated suspicion.** Instead of a flat suspicion timeout, start
   at a conservative maximum and shrink the remaining wait (log-scaled toward a floor)
   each time an *independent* peer also reports suspecting the same node. This detects
   genuine failures faster while a single spurious suspicion doesn't kill a healthy node.

3. **Parallel indirect probing with a fast negative acknowledgment.** Today's indirect
   probe relays are tried sequentially, which multiplies detection latency by the relay
   count under packet loss. Fire all relays concurrently and race on the first success;
   add a "relay confirms it cannot reach the target" fast-path message so the prober
   doesn't have to wait for a full timeout when a relay already knows the answer.

4. **Byte-bounded broadcast queue with a hard prune ceiling**, not just a retransmit-
   count bound. An update storm (many distinct nodes changing state concurrently) can
   otherwise grow the gossip queue without limit even though each individual item is
   bounded by retransmit count.

5. **Address/identity conflict detection on rejoin.** When a higher-incarnation "alive"
   claim changes the network address associated with an existing node ID, treat it as
   a conflict event (log loudly, optionally run an internal confirmation query) instead
   of silently overwriting — this is currently unguarded and is a plausible spoofing or
   stale-rejoin vector.

6. **Chunked, range-based anti-entropy reconciliation.** Replace "send every missing op
   in one response" with compact per-peer version-range bookkeeping (what's the last
   known position, what specific ranges are missing) so repeat syncs against the same
   peer only exchange the incremental delta, and a single reconciliation round is
   naturally bounded in size. Directly resolves gap #2.

7. **Jittered restart/rejoin backoff.** On process restart, delay rejoin announcements
   by a randomized interval (e.g. tens of seconds, uniformly jittered) so a mass
   simultaneous restart across the fleet doesn't produce a synchronized rejoin storm.

8. **Congestion-adaptive gossip fan-out.** Scale broadcast fan-out down when recent
   rounds show rate-limiting/drop feedback, rather than using a static fan-out constant
   at all times.

---

## 3. Phase 4 implementation plan (tamper-evidence, compaction, revocation)

Phase 4 must close gaps #1, #4, #5, and #8 above, on top of the foundations already in
place (watermark map, `MisbehaviorProof`, `CheckpointID` seam, `RevocationChecker` seam).

### `internal/verify`
- Ed25519/hybrid signature verification on every replayed and peer-received op envelope
  (closes gap #5) — this is the missing check between "an op arrived" and "an op is
  trusted," and must run before an op is added to the local set, not just at ingest-time
  scope/skew checks.
- Merkle DAG parent-tracking: verify the `parents` field is actually present on the wire
  format (confirm against gap #8) and wire causal-history verification through it —
  root-hash exchange for cheap divergence detection above a shared checkpoint.
- Formalize equivocation-proof completion: stamp `detected_by`/`detected_at` on the
  existing `MisbehaviorProof` struct instead of leaving it partially filled.

### `internal/checkpoint`
- Signed checkpoint creation using the existing per-origin HLC watermark as the stable
  cut point — a checkpoint is only valid once every live node's contribution up to that
  watermark is durably represented.
- WAL and op-set compaction: a scheduled background task, not an inline synchronous
  step, that removes entries older than the checkpoint cut, with per-scope retention and
  an explicit orphaned-index sweep (dangling seq-index or scope-index entries whose
  underlying op was already compacted). This closes gap #1. Be conservative here —
  a documented failure class in comparable systems is compacting/reaping data that a
  slow-syncing peer still needs, causing "resurrection" bugs when that peer later
  delivers an op referencing already-reaped state. Compaction must never proceed past
  the minimum watermark actually acknowledged across the *whole* live membership, not
  just a quorum of it, or a partitioned-but-alive peer can be permanently desynced.

### `internal/revocation`
- Operator-signed revocation set, propagated mesh-wide via the same signed-gossip
  mechanism as threat ops (revocation is itself just a high-priority, quorum-exempt
  control op type).
- Two-phase revocation: a fast "tainted" signal (compromised, do not admit as a new
  quorum contributor, but don't yet hard-disconnect open sessions) followed by a formal
  "revoked" state (hard reject at transport, remove from `EligibleVoters`). This gives
  faster mesh-wide reaction than waiting for full revocation-set consensus, while still
  requiring the stronger signed state before fully cutting a node off — mirrors how
  short-lived-credential systems separate "flag as compromised" from "remove root of
  trust" to avoid an atomic-cutover race during propagation.
- Wire the result into the already-existing nil-safe `RevocationChecker` seam in
  `internal/transport` (closes gap #4) — no transport-layer changes should be needed
  beyond injecting a real implementation.
- Identity rotation should move from a fixed renewal threshold to a jittered
  half-life model (rotate at roughly half the cert lifetime, with a random jitter
  band) to avoid fleet-wide simultaneous renewal load, and any CA/trust-bundle refresh
  should keep the old and new trust material simultaneously valid during a bounded
  overlap window rather than an atomic cutover, so nodes that haven't yet observed the
  new bundle don't reject peers presenting it, and vice versa.

### Phase 4 exit criteria (supersedes the placeholder list in task-checklist.md)
- Conflicting operations produce a complete misbehavior proof (with attribution) and
  quarantine, verified end-to-end including signature checks.
- A revoked identity is rejected mesh-wide within one gossip round of the revocation
  op reaching quorum, and cannot re-enter as a quorum contributor even if it rejoins
  with a fresh session before the transport layer has processed the revocation.
- WAL and CRDT op-set size stay bounded in a soak test that includes at least one
  partitioned-then-healed slow peer, proving compaction does not resurrect or
  permanently desync it.
- A fault-injected panic in the membership tick loop is recovered and the loop resumes
  (closes gap #6) — this should be validated in the same soak test.

---

## 4. Lower-priority patterns (Phase 5–7, recorded for later)

- **Kernel-native TTL as the base enforcement safety net**, with userspace-side
  reconciliation as defense in depth, not the sole mechanism: on daemon start, actively
  diff live kernel enforcement state against the durable rollback-token ledger and
  correct any divergence, rather than only replaying tokens forward.
- **Per-rule dry-run as a first-class data field**, short-circuited before any
  enforcement action executes, matching frien's existing observe/enforce mode split.
- **Least-privilege capability set for the eBPF detector backend** — scope to the
  specific capabilities required for BPF program loading and perf/tracepoint attachment
  rather than a fully privileged container, when the runtime kernel supports it.
- **Ring-buffer/event-loss mitigation tuning** for the eBPF loader: bounded per-CPU or
  shared ring buffers, an explicit event-drop counter/alert threshold, and a syscall
  allow-list to limit instrumentation overhead to what detectors actually need.
