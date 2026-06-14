# frien — gRPC Contracts

## Proto File Location

```
proto/v1/frien.proto
```

Generated Go code is placed in `pkg/proto/v1/`.

Generation command:
```bash
make proto-gen
# runs: protoc --go_out=pkg/proto/v1 --go-grpc_out=pkg/proto/v1 proto/v1/frien.proto
```

---

## Versioning Strategy

- All gRPC services and messages are versioned at the package level: `frien.v1`
- Breaking changes require a new package version (`frien.v2`)
- Within a major version, only additive, backward-compatible changes are allowed
- Mixed-version clusters must interoperate; see [UPGRADE.md](UPGRADE.md)
- Every `OperationEnvelope` carries a `proto_version` integer; peers negotiate the highest mutually-supported version at session handshake

---

## Services

```proto
package frien.v1;

service AdminService {
  rpc GetStatus(GetStatusRequest) returns (GetStatusResponse);
  rpc ListPeers(ListPeersRequest) returns (ListPeersResponse);
  rpc ReportThreat(ReportThreatRequest) returns (ReportThreatResponse);
  rpc ExplainDecision(ExplainDecisionRequest) returns (ExplainDecisionResponse);
  rpc SetEnforceMode(SetEnforceModeRequest) returns (SetEnforceModeResponse);
  rpc RollbackEnforcement(RollbackEnforcementRequest) returns (RollbackEnforcementResponse);
  rpc ListEnforcements(ListEnforcementsRequest) returns (ListEnforcementsResponse);
  rpc Breakglass(BreakglassRequest) returns (BreakglassResponse);
  rpc GetHardenReport(GetHardenReportRequest) returns (GetHardenReportResponse);
  rpc TestPolicy(TestPolicyRequest) returns (TestPolicyResponse);
}

service PeerService {
  // Internal peer-to-peer gossip; not exposed via admin API
  rpc Gossip(stream GossipMessage) returns (stream GossipMessage);
  rpc AntiEntropy(AntiEntropyRequest) returns (AntiEntropyResponse);
  rpc Negotiate(NegotiateRequest) returns (NegotiateResponse);
}
```

---

## Core Message Types

### OperationEnvelope

```proto
message OperationEnvelope {
  uint32 proto_version    = 1;  // wire protocol version
  string op_id            = 2;  // ULID; globally unique
  string op_type          = 3;  // "threat_record" | "enforcement_decision" | "checkpoint" | "revocation" | "policy"
  string node_id          = 4;
  string hlc              = 5;  // "<wall_time>-<counter>-<node_id>"
  uint64 seq              = 6;  // monotonic per-node sequence
  repeated string parents = 7;  // SHA-256 hashes of parent operations
  string payload_hash     = 8;  // SHA-256 of canonical payload bytes
  bytes  payload          = 9;  // serialized payload (ThreatRecord, etc.)
  string signed_by        = 10; // "node" | "operator"

  // Classical signature (always present)
  string key_id           = 11; // "cert:sha256:<fingerprint>"
  bytes  signature        = 12; // ed25519 signature (64 bytes) over canonical content

  // PQC signature (present when sender is configured for hybrid or PQC-only signing)
  string pqc_algorithm    = 13; // "ml-dsa-65" | "" (empty = no PQC)
  string pqc_key_id       = 14; // SHA-256 fingerprint of ML-DSA-65 public key (16 hex chars)
  bytes  pqc_signature    = 15; // ML-DSA-65 signature (3309 bytes) over same canonical content
}
```

#### Hybrid Signature Protocol

**Canonical signed content** is `SHA-256(length_prefixed_fields)` — the same byte sequence is signed by both algorithms:

```
canonical_content = SHA-256(
  writeField(proto_version)  +  // 4-byte big-endian length + value bytes
  writeField(op_id)          +
  writeField(op_type)        +
  writeField(node_id)        +
  writeField(hlc)            +
  writeField(seq)            +
  writeField(parents[0])     +  // each parent written as separate field
  ...
  writeField(payload_hash)   +
  writeField(signed_by)
)
```

Length-prefixed encoding prevents boundary ambiguity (a concatenation attack cannot produce the same canonical bytes as a different field sequence).

**Sender policy** (controlled by `identity.signing_algorithm` in config):

| `signing_algorithm` | `signature` (field 12) | `pqc_algorithm` (field 13) | `pqc_signature` (field 15) |
|--------------------|------------------------|---------------------------|---------------------------|
| `"ed25519"` | Present | Empty | Empty |
| `"hybrid-ed25519-ml-dsa-65"` (default) | Present | `"ml-dsa-65"` | Present |
| `"ml-dsa-65"` | Present (zero bytes) | `"ml-dsa-65"` | Present |

**Receiver verification policy** (applied in order):

1. `pqc_algorithm == "ml-dsa-65"` AND `pqc_signature` non-empty AND receiver has PQC public key → verify ML-DSA-65. If **valid**: accept (return). If **invalid**: **hard reject** — a valid classical signature cannot rescue a failed PQC signature. This prevents downgrade attacks.
2. `pqc_algorithm != ""` but unrecognized algorithm → **hard reject** (update frien to support it before accepting).
3. No PQC fields → verify ed25519 only.

This means classical-only receivers (that don't know the PQC public key) naturally fall through to step 3 and verify ed25519. PQC-capable receivers always use ML-DSA-65 when available.

**PQC public key distribution**: ML-DSA-65 public keys are distributed via a key-exchange message (type `pqc_key_announce`, op_type in `OperationEnvelope`) gossiped at startup and on key rotation. Keys are cached in the local bbolt `peer-pqc-keys` bucket, indexed by `(node_id, pqc_key_id)`.

**Implementation**: `internal/identity/signer.go` (signing) and `internal/identity/verifier.go` (verification). The `Signer`/`Verifier` interfaces hide the algorithm; swapping `cloudflare/circl` for Go stdlib ML-DSA requires changes only inside those files.

### ThreatRecord

```proto
message ThreatRecord {
  string id              = 1;
  string indicator       = 2;
  string indicator_type  = 3;  // "ip" | "cidr" | "hostname" | "user" | "hash"
  string reason          = 4;
  string severity        = 5;  // "low" | "medium" | "high" | "critical"
  double confidence      = 6;  // 0.0–1.0
  string ttl             = 7;  // duration string e.g. "1h"
  string scope           = 8;  // "local" | "zone:<name>" | "fleet"
  string detector        = 9;
  bytes  evidence_json   = 10; // JSON-encoded evidence blob
  uint32 coalesced_count = 11; // how many identical signals were merged
  string reported_by     = 12;
  string created_at      = 13; // RFC3339
  string expires_at      = 14; // RFC3339
}
```

### EnforcementDecision

```proto
message EnforcementDecision {
  string id                          = 1;
  string threat_id                   = 2;
  string action                      = 3;  // "block" | "allow" | "rate_limit" | "alert"
  string target                      = 4;
  string adapter                     = 5;
  string mode                        = 6;  // "observe" | "enforce"
  string created_at                  = 7;
  string expires_at                  = 8;
  string kernel_timeout              = 9;  // duration; must be set if mode=enforce
  string approved_by_policy          = 10;
  int64  policy_version              = 11;
  double required_weight             = 12;
  double matched_weight              = 13;
  repeated string contributing_identities = 14;
  string rollback_token              = 15;
  string owner                       = 16;  // "frien-enforcer"
  bool   applied                     = 17;
  bool   rolled_back                 = 18;
}
```

### PeerState

```proto
message PeerState {
  string node_id          = 1;
  string role             = 2;
  string zone             = 3;
  string trust_tier       = 4;
  double trust_weight     = 5;
  string status           = 6;  // "alive" | "suspect" | "dead" | "left"
  string enforce_mode     = 7;  // "observe" | "enforce"
  string cert_fingerprint = 8;
  string cert_not_after   = 9;  // RFC3339
  bool   revoked          = 10;
  string last_seen        = 11; // RFC3339
  int32  misbehavior_score = 12;
  repeated string addresses = 13; // "<ip>:<port>"
}
```

### Checkpoint

```proto
message Checkpoint {
  string checkpoint_id           = 1;
  string tree_head               = 2;  // SHA-256 of Merkle root at cut
  string covers_through_hlc      = 3;
  string prev_checkpoint         = 4;  // checkpoint_id of predecessor
  string materialized_state_hash = 5;
  repeated string peer_acks      = 6;
  string created_at              = 7;
  string signed_by               = 8;
  bytes  signature               = 9;
}
```

### RevocationRecord

```proto
message RevocationRecord {
  string id               = 1;
  string cert_fingerprint = 2;
  string node_id          = 3;
  string reason           = 4;
  string revoked_at       = 5;  // RFC3339
  string signed_by        = 6;  // must be "operator"
  string operator_key_id  = 7;
  bytes  signature        = 8;
}
```

---

## Gossip Messages

```proto
message GossipMessage {
  uint32 proto_version    = 1;
  string sender_node_id   = 2;
  string sender_zone      = 3;
  repeated OperationEnvelope deltas = 4;   // CRDT delta batch
  repeated string membership_updates = 5;  // piggybacked SWIM state
  repeated RevocationRecord revocation_hints = 6;  // piggybacked revocation set updates
  uint64 max_message_bytes_hint = 7;       // sender's configured limit
}

message AntiEntropyRequest {
  uint32 proto_version  = 1;
  string requester_id   = 2;
  string zone           = 3;
  string root_hash      = 4;        // current Merkle root for zone
  string since_checkpoint = 5;      // checkpoint_id; reconcile only above this
}

message AntiEntropyResponse {
  repeated OperationEnvelope missing_ops = 1;
  string your_checkpoint = 2;  // latest checkpoint sender knows about
}

message NegotiateRequest {
  repeated uint32 supported_versions = 1;
}

message NegotiateResponse {
  uint32 negotiated_version = 1;
}
```

---

## Field Constraints

| Field | Constraint |
|-------|-----------|
| `indicator` | Max 512 bytes; non-empty |
| `evidence_json` | Max 65536 bytes; valid JSON if non-empty |
| `ttl` | Valid Go duration; max from active policy `max_ttl` |
| `scope` | `local`, `zone:<alphanum-hyphen, max 64 chars>`, or `fleet` |
| `confidence` | Float in [0.0, 1.0] |
| `severity` | Enum: `low`, `medium`, `high`, `critical` |
| `op_id` | ULID format, max 26 chars |
| `node_id` | Reverse-DNS style, max 128 chars |
| `signature` | Ed25519 signature, 64 bytes |
| Entire `GossipMessage` | Max `transport.max_message_bytes` (default 1MB) |

---

## Backward Compatibility Rules

1. Never remove a field from an existing message within a major version
2. Never change the type of an existing field
3. New optional fields may be added; older peers ignore unknown fields (proto3 behavior)
4. New enum values must be handled gracefully by older peers (treat unknown as error or ignore, never panic)
5. Services may add new RPC methods; older clients return `UNIMPLEMENTED` if they call unknown methods
6. `proto_version` in `OperationEnvelope` must be incremented when wire format semantics change (not just additive field additions)

---

## Code Generation

```makefile
PROTO_DIR = proto/v1
OUT_DIR   = pkg/proto/v1

proto-gen:
	protoc \
	  --proto_path=$(PROTO_DIR) \
	  --go_out=$(OUT_DIR) \
	  --go_opt=paths=source_relative \
	  --go-grpc_out=$(OUT_DIR) \
	  --go-grpc_opt=paths=source_relative \
	  $(PROTO_DIR)/frien.proto
```

Generated files:
- `pkg/proto/v1/frien.pb.go` — message types
- `pkg/proto/v1/frien_grpc.pb.go` — service client + server interfaces

Do not edit generated files. Edit the `.proto` source and regenerate.
