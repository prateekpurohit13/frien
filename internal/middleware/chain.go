package middleware

import (
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// Chain builds the ordered unary interceptor chain for the admin gRPC server.
//
// Order matters and follows docs/api-manual.md §gRPC Interceptors. The interceptors
// implemented in Phase 1 are the two that are meaningful without the mesh, policy,
// or RBAC subsystems:
//
//  1. PanicRecovery — outermost, so it guards every later interceptor and the handler
//  2. RequestLogger — assigns the request ID and logs the call
//
// Auth, RBAC, RateLimit, Validation, RequestSizeLimit, MetricsHook, and AuditLog
// are intentionally not yet present; they depend on identity/policy/audit
// subsystems and slot into this same chain in their respective phases. extra lets
// the daemon append additional interceptors without this package importing them.
func Chain(log zerolog.Logger, extra ...grpc.UnaryServerInterceptor) grpc.ServerOption {
	interceptors := make([]grpc.UnaryServerInterceptor, 0, 2+len(extra))
	interceptors = append(interceptors, PanicRecovery(log), RequestLogger(log))
	interceptors = append(interceptors, extra...)
	return grpc.ChainUnaryInterceptor(interceptors...)
}
