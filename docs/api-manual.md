# frien — gRPC API Manual

## Overview

The frien local admin API is a gRPC service exposed over a Unix socket (`/run/frien/admin.sock`) by default. HTTP/TLS exposure is optional and must be explicitly configured. All API calls are authenticated, audited, and scoped.

**Default bind:** Unix socket `unix:///run/frien/admin.sock`
**Optional:** `127.0.0.1:9443` (TLS, local only)
**Protocol:** gRPC (Protocol Buffers, versioned)
**Auth:** Local Unix socket ownership check (default); optional OIDC for dashboard

---

## Proto File Location

All contracts are defined in [`proto/v1/frien.proto`](../proto/v1/frien.proto).

---

## Services

### `AdminService`

The primary admin service. All methods require a caller identity check (Unix socket peer credential or bearer token for OIDC path).

---

### RPC: `GetStatus`

**Purpose:** Return current node health and state.

**Request:** `GetStatusRequest`
```proto
message GetStatusRequest {}
```

**Response:** `GetStatusResponse`
```proto
message GetStatusResponse {
  string  node_id        = 1;
  string  status         = 2;  // "healthy" | "degraded" | "starting" | "stopping"
  string  enforce_mode   = 3;  // "observe" | "enforce"
  int64   peer_count     = 4;
  string  proto_version  = 5;
  string  cert_expires   = 6;  // RFC3339
  int64   wal_size_bytes = 7;
  string  uptime         = 8;
}
```

**Auth:** any authenticated caller
**Rate limit:** 60/min
**Errors:** none expected

---

### RPC: `ListPeers`

**Purpose:** List known peers with their current state, trust tier, and enforce mode.

**Request:** `ListPeersRequest`
```proto
message ListPeersRequest {
  string zone_filter = 1;  // optional; empty = all zones
}
```

**Response:** `ListPeersResponse`
```proto
message ListPeersResponse {
  repeated PeerState peers = 1;
}
```

**Auth:** `viewer` role minimum
**Rate limit:** 30/min
**Errors:**
- `UNAUTHENTICATED` — missing or invalid credentials

---

### RPC: `ReportThreat`

**Purpose:** Manually submit a threat record (operator report via CLI).

**Request:** `ReportThreatRequest`
```proto
message ReportThreatRequest {
  string indicator      = 1;  // required; IP, CIDR, hostname, etc.
  string indicator_type = 2;  // required; "ip" | "cidr" | "hostname" | "user"
  string reason         = 3;  // required; human-readable reason
  string severity       = 4;  // required; "low" | "medium" | "high" | "critical"
  double confidence     = 5;  // required; 0.0–1.0
  string ttl            = 6;  // required; e.g., "1h", "30m"
  string scope          = 7;  // required; "local" | "zone:<name>" | "fleet"
  string evidence_json  = 8;  // optional; JSON evidence blob
}
```

**Response:** `ReportThreatResponse`
```proto
message ReportThreatResponse {
  string op_id      = 1;
  string threat_id  = 2;
  string status     = 3;  // "accepted" | "coalesced" | "shed"
}
```

**Validation rules:**
- `indicator` must be non-empty, ≤512 chars
- `indicator_type` must be one of the allowed enum values
- `confidence` must be in [0.0, 1.0]
- `ttl` must parse as a duration; must not exceed `max_ttl` in active policy
- `scope` must be valid format
- `evidence_json` if provided must be valid JSON ≤64KB

**Auth:** `operator` role minimum
**Rate limit:** 10/min per caller
**Errors:**
- `INVALID_ARGUMENT` — validation failure (details in Status message)
- `RESOURCE_EXHAUSTED` — admission budget exhausted
- `PERMISSION_DENIED` — insufficient role

---

### RPC: `ExplainDecision`

**Purpose:** Return a human-readable explanation of why an enforcement decision was made (or not made) for an indicator.

**Request:** `ExplainDecisionRequest`
```proto
message ExplainDecisionRequest {
  string indicator = 1;  // required
}
```

**Response:** `ExplainDecisionResponse`
```proto
message ExplainDecisionResponse {
  string  indicator              = 1;
  string  decision               = 2;  // "enforced" | "observe_only" | "denied_by_policy" | "no_record"
  string  reason                 = 3;
  repeated string contributing_identities = 4;
  double  matched_weight         = 5;
  double  required_weight        = 6;
  string  policy_id              = 7;
  int64   policy_version         = 8;
  string  expires_at             = 9;  // RFC3339; empty if not enforced
  string  rollback_token         = 10;
  string  adapter                = 11;
  string  audit_entry_id         = 12;
}
```

**Auth:** `viewer` role minimum
**Rate limit:** 60/min
**Errors:**
- `NOT_FOUND` — no decision record for indicator

---

### RPC: `SetEnforceMode`

**Purpose:** Promote or demote a node's enforcement mode for a specific adapter.

**Request:** `SetEnforceModeRequest`
```proto
message SetEnforceModeRequest {
  string mode    = 1;  // required; "observe" | "enforce"
  string adapter = 2;  // required; "nftables" | "networkpolicy" | "cilium" | "envoy"
  string reason  = 3;  // required; audit reason
}
```

**Response:** `SetEnforceModeResponse`
```proto
message SetEnforceModeResponse {
  string previous_mode = 1;
  string current_mode  = 2;
  string audit_id      = 3;
}
```

**Auth:** `operator` role
**Rate limit:** 5/min
**Errors:**
- `INVALID_ARGUMENT` — unknown mode or adapter
- `PERMISSION_DENIED` — insufficient role

---

### RPC: `RollbackEnforcement`

**Purpose:** Immediately remove an enforcement rule by rollback token.

**Request:** `RollbackEnforcementRequest`
```proto
message RollbackEnforcementRequest {
  string rollback_token = 1;  // required
  string reason         = 2;  // required; audit reason
}
```

**Response:** `RollbackEnforcementResponse`
```proto
message RollbackEnforcementResponse {
  string status   = 1;  // "removed" | "already_expired" | "not_found"
  string audit_id = 2;
}
```

**Auth:** `operator` role
**Rate limit:** 20/min
**Errors:**
- `NOT_FOUND` — rollback token unknown

---

### RPC: `ListEnforcements`

**Purpose:** List all active enforcement rules managed by frien.

**Request:** `ListEnforcementsRequest`
```proto
message ListEnforcementsRequest {
  string adapter_filter = 1;  // optional
  bool   include_expired = 2; // default false
}
```

**Response:** `ListEnforcementsResponse`
```proto
message ListEnforcementsResponse {
  repeated EnforcementDecision enforcements = 1;
}
```

**Auth:** `viewer` role
**Rate limit:** 30/min

---

### RPC: `Breakglass`

**Purpose:** Emergency flush of all frien-managed enforcement rules and force observe mode. Works even when mesh is partitioned.

**Request:** `BreakglassRequest`
```proto
message BreakglassRequest {
  bool   flush_enforcement = 1;  // required true
  bool   force_observe     = 2;  // required true
  string reason            = 3;  // required; audit reason
  string confirmation_code = 4;  // required; prevents accidental invocation
}
```

**Response:** `BreakglassResponse`
```proto
message BreakglassResponse {
  int64  rules_removed  = 1;
  string new_mode       = 2;  // "observe"
  string audit_id       = 3;
}
```

**Auth:** `breakglass` role (or `admin`)
**Rate limit:** 2/min
**Errors:**
- `PERMISSION_DENIED` — insufficient role
- `FAILED_PRECONDITION` — confirmation_code invalid or required fields false

---

### RPC: `GetHardenReport`

**Purpose:** Run self-hardening checks and return posture report.

**Request:** `GetHardenReportRequest`
```proto
message GetHardenReportRequest {
  string profile = 1;  // optional; "dev" | "server" | "edge" | "kubernetes" | "strict"
}
```

**Response:** `GetHardenReportResponse`
```proto
message GetHardenReportResponse {
  string overall_status     = 1;  // "pass" | "warn" | "fail"
  repeated HardenCheck checks = 2;
}

message HardenCheck {
  string name     = 1;
  string status   = 2;  // "pass" | "warn" | "fail"
  string message  = 3;
  bool   self_lockout_risk = 4;
}
```

**Auth:** `operator` role
**Rate limit:** 10/min

---

### RPC: `TestPolicy`

**Purpose:** Simulate a threat record against the active policy and return what decision would be made.

**Request:** `TestPolicyRequest`
```proto
message TestPolicyRequest {
  string policy_id      = 1;  // optional; empty = active policy
  string threat_json    = 2;  // required; JSON ThreatRecord payload
}
```

**Response:** `TestPolicyResponse`
```proto
message TestPolicyResponse {
  string decision        = 1;  // "would_enforce" | "observe_only" | "denied"
  string reason          = 2;
  string matched_policy  = 3;
  double required_weight = 4;
  repeated string protected_reasons = 5;
}
```

**Auth:** `operator` role
**Rate limit:** 20/min

---

## gRPC Interceptors

All RPC calls pass through these interceptors in order:

1. **PanicRecovery** — converts panics to `INTERNAL` gRPC status
2. **RequestLogger** — logs method, status, latency, caller
3. **Auth** — verifies caller identity (socket peer cred or bearer token)
4. **RBAC** — checks caller role against method requirements
5. **RateLimit** — per-method, per-caller rate limiting
6. **Validation** — proto message validation
7. **RequestSizeLimit** — rejects requests exceeding configured max bytes
8. **MetricsHook** — increments method call counters and latency histograms
9. **AuditLog** — writes immutable audit entry for mutating methods

---

## Error Codes

| gRPC Code | When Used |
|-----------|-----------|
| `OK` | Success |
| `INVALID_ARGUMENT` | Validation failure; details in Status |
| `NOT_FOUND` | Resource does not exist |
| `ALREADY_EXISTS` | Duplicate resource |
| `PERMISSION_DENIED` | Authenticated but insufficient role |
| `UNAUTHENTICATED` | Missing or invalid credentials |
| `RESOURCE_EXHAUSTED` | Rate limit or budget exhausted |
| `FAILED_PRECONDITION` | Caller not in required state |
| `INTERNAL` | Unexpected server error (no internal details exposed) |
| `UNAVAILABLE` | Service temporarily unavailable |
| `DEADLINE_EXCEEDED` | Request timeout |

Internal errors are never exposed in response messages. Use audit logs for debug context.

---

## RBAC Roles

| Role | Permissions |
|------|-------------|
| `viewer` | GetStatus, ListPeers, ListEnforcements, ExplainDecision |
| `operator` | viewer + ReportThreat, SetEnforceMode, RollbackEnforcement, TestPolicy, GetHardenReport |
| `admin` | operator + policy management, trust tier assignment |
| `breakglass` | Breakglass only (for emergency access paths) |
