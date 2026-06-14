# frien — End-to-End Workflow

## Event Lifecycle

```
Local detector observes event
  → Normalize evidence
  → Admission control (budget, coalesce, shed)
  → Create ThreatRecord with scope + evidence
  → Sign OperationEnvelope with node key
  → Append to local Merkle DAG
  → Store in WAL
  → Apply to local CRDT state
  → Gossip scoped delta to peers in zone/scope

Peer receives gossip delta:
  → Check proto_version compatibility
  → Verify sender cert is not revoked
  → Verify signature and schema
  → Check message size limits
  → Check clock-skew window (local receive clock)
  → Check replay / stale (by op_id + origin)
  → Verify DAG parents (request missing if needed)
  → Check equivocation (conflicting sequence from same node)
    [Yes] → Create misbehavior proof → quarantine peer → propose revocation to operator
    [No]  → Apply CRDT update

Policy evaluation:
  → Partition-safe quorum check (distinct identities, trust weight, receive window)
  → Check node enforce-mode (observe vs enforce)
  → Check protected CIDRs, self-plane addresses, service allowlists
  → Check confidence, TTL cap, severity threshold
  → Operator-signed policy evaluation

  [Mode = observe OR quorum not met OR policy denies]:
    → Store as intelligence only
    → Update audit log
    → Available via frienctl explain

  [Mode = enforce AND quorum met AND policy allows]:
    → Create EnforcementDecision with rollback token
    → Enforcer applies self-expiring rule (kernel timeout)
    → Audit log entry with contributing identities, quorum weight, policy version

Background processes (continuous):
  → Checkpoint: compute stable cut, materialize CRDT state, sign Checkpoint
  → Compact: prune DAG nodes + WAL entries below acknowledged checkpoint
  → Anti-entropy: exchange root hashes with peers, reconcile above shared checkpoint
  → Cert renewal: refresh short-lived node cert against private CA
  → Dead-man's switch: enforcer monitors daemon heartbeat; removes rules if heartbeat stops
```

---

## Enforcement Promotion Workflow

```
Initial state: node in observe mode

Operator decision to enforce:
  frienctl mode set enforce --adapter nftables --confirm --reason "rollout phase 2"
    → Audit log entry with operator identity and reason
    → Node transitions to enforce mode for that adapter
    → Future policy-approved decisions result in kernel rule creation

Operator rollback of a specific enforcement:
  frienctl enforcement rollback <rollback_token>
    → Enforcer removes the specific rule immediately
    → Audit log entry

Emergency breakglass (self-lockout recovery):
  frienctl --local breakglass --flush-enforcement --force-observe
    → Flushes ALL frien-managed rules from enforcer
    → Forces node to observe mode
    → Works even if mesh is partitioned or misbehaving
    → Local-only, no mesh communication required
```

---

## Compaction Workflow

```
Node reaches compaction trigger (time or DAG size threshold):
  → Identify stable cut (below all live causal frontiers visible to node)
  → Materialize CRDT state at cut into snapshot
  → Sign Checkpoint { tree_head, covers_through_hlc, prev_checkpoint, materialized_state_hash }
  → Append Checkpoint to DAG + WAL
  → Gossip Checkpoint to peers
  → Peers acknowledge Checkpoint

Once Checkpoint is acknowledged by configurable fraction of in-scope peers:
  → Prune DAG nodes below the checkpoint frontier
  → Prune WAL entries below the checkpoint frontier
  → Signed Checkpoint + materialized snapshot replace pruned history
  → Anti-entropy sync now bounded below by latest common checkpoint
```

---

## Node Restart Recovery

```
Daemon starts:
  → Load config and validate
  → Initialize logger
  → Load node identity + cert (renew if near expiry)
  → Load latest signed snapshot/checkpoint from storage
  → Replay WAL entries above checkpoint
  → Reconcile rollback tokens (apply pending rollbacks for any incomplete enforcement changes)
  → Reconnect to peers via seed nodes
  → Resume gossip + anti-entropy
  → Resume admission + detection
```

---

## Revocation Workflow

```
Equivocation detected by peer(s):
  → Misbehavior proof created
  → Offending node quarantined (behavioral, immediate, local)
  → Revocation proposal surfaced to operator via audit + frienctl alerts

Operator reviews and authorizes:
  frienctl revoke node_edge_12 --cert-fingerprint sha256:... --reason equivocation_proof_01HZX

  → Operator signs RevocationRecord with KMS/HSM-backed key
  → RevocationRecord gossiped as control-plane CRDT entry
  → Peers receive + verify operator signature (against pinned operator root)
  → Revocation set updated mesh-wide
  → Any active session from revoked fingerprint is dropped
  → Future reports from revoked identity are rejected at transport layer
```

---

## Threat Storm Handling

```
Detector generates high-volume signals (e.g., 10k brute-force hits):
  → Token-bucket per detector is exceeded
  → Many identical signals: coalescing collapses into single record (coalesced_count=N)
  → Under sustained storm: low-severity/low-confidence signals are priority-shed
  → High-confidence, high-severity signals still flow
  → Gossip and signature verification remain functional (mesh does not collapse)
  → shed_rate metric increments (observable as storm signal)
```
