# frien — Data Model and Storage

## Storage Architecture

frien uses three storage mechanisms, all local to the node. No external database is required for node operation.

| Storage | Purpose | Required |
|---------|---------|---------|
| Append-only WAL files | Operation durability; checkpoint-compacted | Yes |
| bbolt embedded DB | Indexed metadata, rollback tokens, revocation set, snapshots index | Yes |
| Signed snapshot + checkpoint files | Fast restart recovery; bounded history | Yes |
| PostgreSQL (optional) | Dashboard metadata, audit search, user management | No |

---

## Core Data Schemas

### OperationEnvelope

Every data-plane and control-plane object travels inside a signed versioned envelope.

```json
{
  "proto_version": 1,
  "op_id": "op_01HZX...",
  "op_type": "threat_record | enforcement_decision | retraction | checkpoint | revocation | policy",
  "node_id": "node.edge.eu-west.01",
  "hlc": "2026-05-16T10:20:30.000Z-4-node.edge.eu-west.01",
  "seq": 184,
  "parents": ["sha256:bafy..."],
  "payload_hash": "sha256:...",
  "payload": {},
  "signed_by": "node | operator",
  "key_id": "cert:sha256:...",
  "signature": "base64(ed25519_sig)"
}
```

Fields:
- `proto_version` — wire protocol version; peers reject mismatches that exceed negotiated window
- `op_id` — globally unique, URL-safe ID (ULID recommended)
- `hlc` — Hybrid Logical Clock timestamp: `<wall_time>-<counter>-<node_id>`
- `seq` — monotonically increasing per-node sequence number; used for equivocation detection
- `parents` — hashes of causal predecessor operations (Merkle DAG links)
- `payload_hash` — SHA-256 of canonical-encoded payload; verified before use
- `signed_by` — `node` for data-plane; `operator` for control-plane

---

### ThreatRecord

```json
{
  "id": "threat_01HZX...",
  "indicator": "203.0.113.44",
  "indicator_type": "ip | cidr | hostname | user | hash",
  "reason": "ssh_bruteforce",
  "severity": "low | medium | high | critical",
  "confidence": 0.91,
  "ttl": "1h",
  "scope": "local | zone:edge-eu-west | fleet",
  "detector": "ssh_bruteforce_v1",
  "evidence": {
    "failed_attempts": 128,
    "window": "60s",
    "target_service": "sshd"
  },
  "coalesced_count": 1,
  "reported_by": "node.edge.eu-west.01",
  "created_at": "2026-05-16T10:20:30Z",
  "expires_at": "2026-05-16T11:20:30Z"
}
```

`scope` controls replication:
- `local` — stored only on origin node; never gossiped
- `zone:<name>` — gossiped only to nodes in the same named zone
- `fleet` — gossiped to all nodes; reserved for high-confidence, high-severity indicators

---

### EnforcementDecision

```json
{
  "id": "decision_01HZY...",
  "threat_id": "threat_01HZX...",
  "action": "block | allow | rate_limit | alert",
  "target": "203.0.113.44",
  "adapter": "nftables | networkpolicy | cilium | envoy | siem",
  "mode": "observe | enforce",
  "created_at": "2026-05-16T10:20:30Z",
  "expires_at": "2026-05-16T11:20:30Z",
  "kernel_timeout": "1h",
  "approved_by_policy": "edge_block_v1",
  "policy_version": 7,
  "required_weight": 3.0,
  "matched_weight": 4.0,
  "contributing_identities": ["node.edge.eu-west.01", "node.edge.eu-west.02"],
  "rollback_token": "rollback_01HZZ...",
  "owner": "frien-enforcer",
  "applied": false,
  "rolled_back": false
}
```

`applied` is `false` in observe mode. `kernel_timeout` ensures the rule self-expires in the kernel even if the daemon dies. `rollback_token` enables explicit operator rollback.

**Immutable wire object vs. local columns.** The gossiped `EnforcementDecision` is immutable; only the fields above the `rollback_token` line travel in the signed envelope. `applied` and `rolled_back` are **local enforcer state**, stored as columns in the bbolt `decisions` bucket on the node that owns the rule — they are never merged into the replicated CRDT set. Two nodes may legitimately hold the same decision with different local `applied` flags.

---

### Policy (control-plane)

```json
{
  "id": "edge_block_v1",
  "version": 7,
  "signed_by": "operator",
  "operator_key_id": "kms:arn:aws:kms:us-east-1:123:key/...",
  "signature": "base64...",
  "created_at": "2026-05-16T00:00:00Z",
  "body": {
    "action": "block",
    "default_mode": "observe",
    "min_confidence": 0.85,
    "require_weight": 3.0,
    "quorum_window": "5m",
    "max_ttl": "1h",
    "kernel_timeout_required": true,
    "protected_cidrs": ["127.0.0.0/8", "10.0.0.0/8", "..."],
    "protect_self_planes": true
  }
}
```

Policies are versioned and monotonic: a node never downgrades to an older version for the same `policy.id`.

---

### RevocationRecord (control-plane)

```json
{
  "id": "revoke_01J0...",
  "cert_fingerprint": "sha256:...",
  "node_id": "node.edge.eu-west.07",
  "reason": "equivocation — proof op_id: equivoc_01HZX",
  "revoked_at": "2026-05-16T10:25:00Z",
  "signed_by": "operator",
  "operator_key_id": "kms:arn:...",
  "signature": "base64..."
}
```

Only operator/CA-signed RevocationRecords are accepted. Peer-initiated revocation is not permitted.

---

### Checkpoint

```json
{
  "checkpoint_id": "ckpt_01J0...",
  "tree_head": "sha256:...",
  "covers_through_hlc": "2026-05-16T10:00:00.000Z-0-*",
  "prev_checkpoint": "ckpt_01HZ...",
  "materialized_state_hash": "sha256:...",
  "peer_acks": ["node.edge.eu-west.01", "node.edge.eu-west.02"],
  "created_at": "2026-05-16T10:01:00Z",
  "signed_by": "node",
  "signature": "base64..."
}
```

Checkpoints are verifiable without retaining every operation (CT-style tree-head consistency proofs).

---

### PeerState

```json
{
  "node_id": "node.edge.eu-west.01",
  "role": "edge",
  "zone": "edge-eu-west",
  "trust_tier": "standard",
  "trust_weight": 1.0,
  "status": "alive | suspect | dead | left",
  "enforce_mode": "observe | enforce",
  "cert_fingerprint": "sha256:...",
  "cert_not_after": "2026-05-16T16:20:30Z",
  "revoked": false,
  "last_seen": "2026-05-16T10:20:30Z",
  "misbehavior_score": 0,
  "addresses": ["10.0.1.10:7443"]
}
```

---

## CRDT State Model

The replicated state is a **grow-only set of immutable signed `OperationEnvelope`s keyed by `op_id`**. This is the simplest correct CRDT for frien's data, and the choice is deliberate:

- Every op has a globally unique, single-author `op_id`, so two replicas never hold competing writes to the same key. **Merge is therefore pure set-union** — a join-semilattice that is commutative, associative, and idempotent, giving strong eventual consistency by construction. No OR-Set dots, no add-wins arbitration, no tombstone garbage collection.
- All mutable-looking behavior is a **projection** over the immutable set. Retraction, equivocation, and quorum-counting are pure functions of the set; expiry also reads the local clock, so it converges as clocks agree (the set itself always converges by union):
  - **Record TTL / expiry** — `present(op)` becomes false once `local_now ≥ expires_at`, where `expires_at` is the **origin-declared, policy-capped** field carried in the immutable op. Because the bound is in the op, every replica targets the same instant and a late-delivered already-expired op is never present (no resurrection); the checkpoint watermark prunes it so anti-entropy cannot re-offer it.
  - **Author retraction** — an `op_type: "retraction"` op referencing a target `op_id`, accepted only if signed by the original author with a higher `seq`. Single-writer LWW by `seq`; no cross-actor race. This is the one tombstone, but a causally-later single-writer one — no concurrent add/remove arbitration.
  - **Quorum window (separate from TTL)** — counts present ops per indicator by distinct identity within a window measured against the **local receive clock**, so origin skew cannot move quorum. TTL governs validity duration; the quorum window governs receive recency. The set is never collapsed by indicator: distinct reports stay distinct.

**Why not OR-Set or LWW-element-set.** An OR-Set solves concurrent same-key add/remove — impossible here, and its collapsing would erase the distinct-identity quorum signal. A keep-one LWW-element-set is unsafe for accountability: two ops at the same `(node_id, seq)` are **equivocation evidence**, and union preserves both while LWW would discard one.

**Equivocation index.** On apply, the node maintains `(node_id → seq → op_hash)`. A second, distinct `op_hash` at an existing `(node_id, seq)` is equivocation → portable proof → quarantine + revocation proposal (no causal parents-DAG required).

**Bounds.** The set is bounded by TTL expiry + checkpoint compaction below, and by admission control (inbound ops are rate- and size-bounded per scope, same path as locally-created ops) above. Distinct records cannot be coalesced (distinct ids), so inbound state has an explicit per-scope cap with shed-on-overflow.

## bbolt Bucket Layout

```
frien.db
├── bucket: "peers"          → node_id → PeerState (JSON)
├── bucket: "threats"        → threat_id → ThreatRecord (JSON)
├── bucket: "decisions"      → decision_id → EnforcementDecision (JSON)
├── bucket: "rollback_tokens"→ rollback_token → EnforcementDecision.id
├── bucket: "revocations"    → cert_fingerprint → RevocationRecord (JSON)
├── bucket: "policies"       → policy_id:version → Policy (JSON)
├── bucket: "checkpoints"    → checkpoint_id → Checkpoint (JSON)
├── bucket: "audit"          → audit_id → AuditEntry (JSON)
├── bucket: "op_dedup"       → op_id → "1" (replay window dedup)
├── bucket: "author_seq"     → node_id:seq → op_hash (equivocation index)
├── bucket: "peer_watermark" → node_id → highest observed HLC (compaction stable cut)
└── bucket: "meta"           → schema_version, persisted HLC, node bootstrap state
```

`op_dedup` keyed by `op_id` makes replay rejection a single lookup. `author_seq` makes equivocation a single lookup: a second distinct `op_hash` at an existing `node_id:seq` is a proof. The persisted HLC in `meta` is reloaded on startup so the clock never regresses across a restart.

---

## WAL Format

Each WAL entry is a fixed-header + variable-length payload:

```
[4 bytes magic]
[8 bytes: entry length (little-endian uint64)]
[32 bytes: SHA-256 of previous entry]
[N bytes: canonical-encoded OperationEnvelope (protobuf)]
[32 bytes: SHA-256 of this entry header+payload]
```

The chain of SHA-256 links makes the WAL tamper-evident. On startup, the WAL is replayed from the latest checkpoint and verified.

---

## Compaction

WAL entries and DAG nodes below an acknowledged Checkpoint are eligible for pruning:

1. Node reaches compaction trigger (configurable interval or size threshold)
2. Identifies the stable cut: earliest HLC below all live causal frontiers observable
3. Materializes CRDT state at the cut into a signed snapshot file
4. Creates and signs a Checkpoint referencing the snapshot hash and previous checkpoint
5. Gossips Checkpoint; waits for `compaction_peer_ack_fraction` of in-scope peers to ack
6. Prunes WAL entries and DAG nodes below the checkpoint frontier
7. Subsequent anti-entropy sync is bounded below by the latest common checkpoint

---

## Startup Recovery Sequence

1. Load latest Checkpoint from bbolt `checkpoints` bucket
2. Verify Checkpoint signature against node cert CA
3. Load materialized snapshot corresponding to Checkpoint
4. Replay WAL entries above `covers_through_hlc` in order, verifying hash chain
5. Rebuild in-memory CRDT state from snapshot + replayed WAL
6. Reconcile rollback tokens: any `applied=true, rolled_back=false` decisions are re-verified and re-applied or rolled back as needed
7. Resume normal operation
