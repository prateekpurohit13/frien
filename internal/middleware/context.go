package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// contextKey is unexported so no other package can collide with our context keys.
type contextKey int

const requestIDKey contextKey = iota

// ContextWithRequestID returns a copy of ctx carrying the given request ID.
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the request ID stored in ctx, or "" if none.
// Handlers and the error pipeline use this to correlate a caller-visible error
// with server logs (docs/error-handling.md §Request ID Propagation).
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// newRequestID returns a unique, log-correlatable request identifier.
//
// docs recommend ULIDs for globally-sortable operation IDs; a request ID has no
// such ordering requirement, so we avoid pulling in a ULID dependency here and
// use a random "req_<hex>" token. Operation IDs (Phase 3+) can adopt a real ULID
// implementation where lexical sortability actually matters.
func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failing is effectively fatal for the process, but a request ID
		// is not security-critical; fall back to a fixed marker rather than panic.
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b[:])
}
