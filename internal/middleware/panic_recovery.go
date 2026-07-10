package middleware

import (
	"context"
	"runtime/debug"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PanicRecovery returns a unary interceptor that converts any panic in a handler
// (or a later interceptor) into a safe INTERNAL gRPC status. The full stack trace
// is logged internally only; it is never returned to the caller (docs/error-handling.md).
//
// This is the outermost interceptor in the chain so it also guards the other
// interceptors, not just the handler.
func PanicRecovery(log zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error().
					Str("request_id", RequestIDFromContext(ctx)).
					Str("method", info.FullMethod).
					Interface("panic", r).
					Bytes("stack", debug.Stack()).
					Msg("panic recovered in gRPC handler")
				// Overwrite any partial response; return a generic error only.
				resp = nil
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}
