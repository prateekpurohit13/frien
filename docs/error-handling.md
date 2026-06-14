# frien — Error Handling

## Principles

1. **Fail fast on startup** — missing config, invalid cert, or unwritable storage causes immediate exit with a clear message
2. **Internal errors never leak to callers** — stack traces, DB paths, key material, and internal state are logged, not returned
3. **Every error has a safe user-facing message** and a request ID for log correlation
4. **gRPC status codes map directly from domain errors** — no string matching in error handlers

---

## Centralized Error Types

All domain errors are defined in `internal/errors/errors.go`:

```go
// Error kinds — map 1:1 to gRPC status codes
var (
    ErrNotFound          = &AppError{Code: codes.NotFound}
    ErrAlreadyExists     = &AppError{Code: codes.AlreadyExists}
    ErrInvalidArgument   = &AppError{Code: codes.InvalidArgument}
    ErrPermissionDenied  = &AppError{Code: codes.PermissionDenied}
    ErrUnauthenticated   = &AppError{Code: codes.Unauthenticated}
    ErrRateLimited       = &AppError{Code: codes.ResourceExhausted}
    ErrInternal          = &AppError{Code: codes.Internal}
    ErrUnavailable       = &AppError{Code: codes.Unavailable}
    ErrFailedPrecondition= &AppError{Code: codes.FailedPrecondition}
)

type AppError struct {
    Code    codes.Code
    Message string   // safe user-facing message
    Detail  string   // internal detail (logged, never returned)
}

func (e *AppError) GRPCStatus() *status.Status { ... }
```

Usage pattern:
```go
// In service layer:
return nil, errors.New(ErrNotFound, "indicator not found", "bbolt lookup returned nil for key: "+key)

// Interceptor converts AppError → gRPC status automatically.
// The Detail field is logged with the request ID; Message is returned to caller.
```

---

## gRPC Status Code Mapping

| Domain Condition | gRPC Code | User Message Pattern |
|-----------------|-----------|---------------------|
| Resource not found | `NOT_FOUND` | "record not found" |
| Duplicate resource | `ALREADY_EXISTS` | "already exists" |
| Validation failure | `INVALID_ARGUMENT` | "invalid argument: <field>" |
| Missing required field | `INVALID_ARGUMENT` | "required field missing: <field>" |
| Insufficient role | `PERMISSION_DENIED` | "permission denied" |
| Missing credentials | `UNAUTHENTICATED` | "authentication required" |
| Rate limit exceeded | `RESOURCE_EXHAUSTED` | "rate limit exceeded; retry after Ns" |
| Precondition not met | `FAILED_PRECONDITION` | "precondition not met: <reason>" |
| Unexpected internal error | `INTERNAL` | "internal error" (nothing else) |
| Temporarily unavailable | `UNAVAILABLE` | "service temporarily unavailable" |
| Request timeout | `DEADLINE_EXCEEDED` | "deadline exceeded" |

**Never** return `INTERNAL` with a message containing paths, keys, SQL, panics, or implementation details.

---

## Interceptor Error Pipeline

The `PanicRecovery` interceptor is always first in the chain:

```go
func panicRecoveryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
    defer func() {
        if r := recover(); r != nil {
            logger.ErrorContext(ctx, "panic recovered", "panic", r, "stack", debug.Stack())
            err = status.Error(codes.Internal, "internal error")
        }
    }()
    return handler(ctx, req)
}
```

All panics are recovered, logged with full stack trace (internal log only), and returned as `INTERNAL` to the caller.

---

## Structured Error Logging

Every error log entry must include:

```json
{
  "level": "error",
  "ts": "2026-05-16T10:20:30.123Z",
  "request_id": "req_01HZX...",
  "method": "/frien.v1.AdminService/ReportThreat",
  "caller_id": "unix:uid=1001",
  "error_kind": "invalid_argument",
  "error_detail": "confidence field: got 1.5, want 0.0–1.0",
  "latency_ms": 2
}
```

- `request_id` is generated at the request logger interceptor and propagated via context
- `error_detail` is internal; never returned to caller
- `error_kind` maps to the gRPC status code slug

---

## Startup Error Handling

Config and startup errors exit with code 1 and a clear human-readable message:

```
FATAL: config validation failed
  node.id: required, got empty string
  identity.cert_path: file not found: /etc/frien/keys/node.crt
  storage.wal_dir: not writable: /var/lib/frien (permission denied)
```

Partial initialization does not leave the process in a running-but-broken state. Either all components initialize successfully or the process exits.

---

## Storage Error Handling

- WAL append failure: log error with context; return `ErrInternal` to caller; do not silently drop the operation
- bbolt transaction failure: roll back; return `ErrInternal`; log full detail
- WAL hash chain corruption on startup: log the corruption point; refuse to start unless `--force-recover` flag is set (operator decision)
- Snapshot load failure: log and fall back to full WAL replay from earliest available entry

---

## Network / Transport Error Handling

- Peer session failure: log with peer_id, error, retry attempt count; apply exponential backoff; do not crash
- mTLS handshake failure (invalid cert): log with remote address; do not connect; do not penalize other peers
- Revoked cert session attempt: log as security event at WARN level; drop session; increment rejection metric
- Message too large: drop message; log with peer_id; increment over-size metric

---

## Enforcement Error Handling

- nftables command failure: log full detail; return error to enforcer caller; rollback any partial change; do not partially apply
- Rollback failure: log at ERROR level with rollback token and detail; alert via metrics (`frien_enforcement_rollback_failure_total`); dead-man switch will clean up on daemon restart
- Dead-man switch activation: log at WARN level; remove all frien-managed rules; decrement `frien_active_enforcement_rules`

---

## Request ID Propagation

Every gRPC call receives a `request_id` at the logging interceptor:

```go
func requestLoggerInterceptor(...) {
    reqID := newRequestID()   // ULID
    ctx = contextWithRequestID(ctx, reqID)
    // ... call handler ...
    log.Info("rpc completed", "request_id", reqID, "method", info.FullMethod, "latency_ms", latency, "status", statusCode)
}
```

The `request_id` is returned in the gRPC trailing metadata (`x-request-id`) so operators can correlate a client-visible error with server logs.

---

## Error Handling Checklist

Before marking any module complete, verify:

- [ ] All error paths return an `AppError` with correct code and safe message
- [ ] No internal details in user-facing messages
- [ ] Panics are recovered and logged (not silenced)
- [ ] Context cancellation is respected (no goroutine leaks)
- [ ] Request ID propagated through context and returned in metadata
- [ ] Storage failures do not corrupt state (WAL is append-only; bbolt transactions roll back)
- [ ] Enforcement partial-apply failures roll back
- [ ] Startup failures are fatal with clear diagnostic output
