# frien — Testing Strategy

## Principles

- Tests are mandatory before marking any task complete
- No module is considered done until its tests pass
- Security-adjacent code requires adversarial tests, not just happy-path tests
- Distributed-correctness is verified through deterministic simulation and formal methods, not only integration tests

---

## Test Types and Locations

| Type | Location | Tool |
|------|----------|------|
| Unit tests | Co-located `*_test.go` | `go test` |
| Property-based tests | Co-located `*_test.go` | `pgregory.net/rapid` |
| Integration tests | `tests/integration/` | `go test -tags=integration` |
| Adversarial / security tests | `tests/adversarial/` | `go test -tags=adversarial` |
| Chaos tests | `tests/chaos/` | `go test -tags=chaos` |
| Deterministic simulation | `tests/simulation/` | Custom harness |
| Jepsen / partition tests | `tests/jepsen/` | Clojure/Jepsen |
| Formal verification | `specs/frien.tla` | TLC model checker |

---

## Unit Test Requirements

Every package must have tests for:

- Happy path
- Empty / nil / zero-value inputs
- Missing required fields
- Invalid enum values
- Length limit violations
- Numeric boundary conditions
- Error propagation (does the right error bubble up?)
- Context cancellation and timeout

### Per-Package Test Coverage Requirements

| Package | Coverage Target | Key Test Cases |
|---------|----------------|----------------|
| `internal/config` | 95% | missing required field, invalid format, env override, env secret injection |
| `internal/version` | 90% | same version match, upgrade path, downgrade rejection, unknown version |
| `internal/crdt` | 90% | convergence under reorder, idempotency, expiry, scope filter |
| `internal/verify` | 95% | valid sig, invalid sig, wrong key, expired cert, replay, equivocation |
| `internal/policy` | 95% | quorum met, quorum not met, partition, protected CIDR, self-plane, observe mode |
| `internal/admission` | 90% | burst, rate limit, coalescing, storm shed, priority |
| `internal/storage` | 90% | WAL append/replay, hash chain verify, compaction, crash recovery |
| `internal/checkpoint` | 90% | stable cut, materialization, peer ack, pruning |
| `internal/membership` | 85% | join, probe, suspect, dead, rejoin |
| `internal/transport` | 85% | mTLS success, revoked cert rejection, oversized message, skew window |
| `internal/enforcer` | 90% | observe-only, enforce rule, TTL expiry, rollback, dead-man switch |
| `internal/errors` | 100% | every error maps to correct gRPC code |

---

## Property-Based Tests

Required for correctness invariants that must hold under arbitrary operation ordering:

```go
// internal/crdt: convergence
// For any two nodes A, B with any order of operations applied:
// merge(stateA, stateB) == merge(stateB, stateA)  (commutativity)
// merge(stateA, merge(stateB, stateC)) == merge(merge(stateA, stateB), stateC)  (associativity)
// merge(stateA, stateA) == stateA  (idempotency)

// internal/verify: no false equivocation
// A single node sending operations in valid sequence never triggers equivocation detection

// internal/policy: quorum is safe under any subset of peers
// No minority subset of peers (< required_weight) can satisfy quorum
```

---

## Integration Tests

Location: `tests/integration/`

Required scenarios:

- [ ] 3 nodes join via seed nodes; all reach `alive` state
- [ ] Node A reports a zone-scoped threat; nodes B and C in same zone receive it; node D in different zone does not
- [ ] Node A reports `fleet`-scoped threat; all nodes receive it
- [ ] Replayed operation (same op_id) is rejected by receiving node
- [ ] Clock-skew outside configured window causes rejection
- [ ] After quorum is met, policy-approved record triggers EnforcementDecision (observe mode — not applied)
- [ ] After `SetEnforceMode(enforce)`, approved record creates nftables entry with kernel TTL
- [ ] `RollbackEnforcement` removes rule immediately
- [ ] Daemon restart replays WAL and recovers state
- [ ] Checkpoint + compaction: after compaction, anti-entropy reconciles correctly from checkpoint
- [ ] Admin API `GetStatus`, `ListPeers`, `ExplainDecision` return correct data
- [ ] `Breakglass` clears all rules and returns node to observe mode

---

## Adversarial Tests

Location: `tests/adversarial/`

Required scenarios:

- [ ] Malformed protobuf message at transport layer → rejected, peer score penalized
- [ ] Oversized message (> `max_message_bytes`) → rejected before deserialization
- [ ] Invalid signature → rejected; original signer not penalized
- [ ] Revoked cert used to establish session → session dropped at transport
- [ ] Revoked cert used in data-plane message → message rejected at policy layer
- [ ] Node A sends two operations with same `seq` but different payloads (equivocation) → misbehavior proof created, A quarantined
- [ ] Threat targeting protected CIDR (127.0.0.1) → rejected by policy with explanation
- [ ] Threat targeting frien's own admin socket address → rejected by self-plane protection
- [ ] Flood of operations from single detector → admission control coalesces/sheds; no crash
- [ ] Policy sent by peer (not operator-signed) → rejected; only operator-root-signed policies accepted
- [ ] Downgrade attack (peer sends lower proto_version than negotiated) → rejected

---

## Chaos Tests

Location: `tests/chaos/`

Required scenarios:

- [ ] Node B dies mid-gossip; A and C detect suspect → dead within configured multiplier
- [ ] Node B restarts; rejoins mesh; state converges
- [ ] Network partition splits cluster into {A} and {B, C}; no fleet-scoped enforcement from {A}
- [ ] Partition heals; anti-entropy reconciles correctly from shared checkpoint
- [ ] Daemon killed with active enforcement rule → rule self-expires via kernel timeout
- [ ] Enforcer process killed (dead-man switch test) → all frien-managed rules removed within `deadman_switch_timeout`

---

## Deterministic Simulation

Location: `tests/simulation/`

The simulation harness runs the full mesh (membership + CRDT + quorum + checkpoint + revocation) as a discrete-event simulation with a seeded PRNG. This allows reproducible regression testing of distributed scenarios.

Required simulation scenarios:

- [ ] N nodes, random operation order, eventual convergence of CRDT state
- [ ] Partition, heal, convergence — no lost confirmed operations
- [ ] Checkpoint-and-compact cycle — DAG/WAL bounded under sustained load
- [ ] Equivocating node detected, quarantined, revoked — honest peers not affected
- [ ] Threat storm — admission control bounds operation rate; mesh doesn't collapse

---

## Formal Verification

Location: `specs/frien.tla`

TLA+ model covers:

- Membership state machine safety: nodes reach consistent `alive`/`dead` conclusions
- Partition-safe quorum: no minority subset can satisfy quorum for fleet-scoped action
- Quarantine: once quarantined, a node cannot contribute to quorum
- Revocation: once revoked, a node's messages are rejected mesh-wide within bounded time
- No self-lockout: frien's own planes cannot be blocked by enforcement policy

---

## Test Infrastructure

```makefile
# Run all fast unit tests
make test

# Run unit + integration tests
make test-integration

# Run adversarial tests
make test-adversarial

# Run full simulation suite
make test-simulation

# Run formal verification (requires TLC)
make verify-tla

# Race detector (run on every CI commit)
make test-race

# Coverage report
make coverage
```

All tests must pass `go test -race` before merge. The race detector is enabled in CI.

---

## Edge Cases to Verify in Every Module

- [ ] Empty input / nil pointer
- [ ] Context cancellation mid-operation
- [ ] Database / WAL failure during write
- [ ] Concurrent requests (race detector)
- [ ] Graceful shutdown during in-flight request
- [ ] Config missing or malformed
- [ ] Protected CIDR match (IPv4 and IPv6)
- [ ] Cert expiry
- [ ] Token-bucket exhaustion
- [ ] Duplicate request (idempotency where required)
