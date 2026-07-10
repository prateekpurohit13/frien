package middleware

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RequestLogger returns a unary interceptor that assigns a request ID, propagates
// it via context, logs the call's method/caller/status/latency, and echoes the
// request ID back in the gRPC trailing metadata as "x-request-id" so operators can
// correlate a client-visible error with server logs (docs/error-handling.md).
func RequestLogger(log zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		reqID := newRequestID()
		ctx = ContextWithRequestID(ctx, reqID)

		// Best-effort: send the request ID even if the handler later errors.
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", reqID))

		start := time.Now()
		resp, err := handler(ctx, req)
		latency := time.Since(start)

		code := status.Code(err)
		event := log.Info()
		if err != nil {
			// Domain errors are expected control flow; log at warn, not error.
			event = log.Warn()
		}
		event.
			Str("request_id", reqID).
			Str("method", info.FullMethod).
			Str("caller", callerFromContext(ctx)).
			Str("code", code.String()).
			Dur("latency", latency).
			Msg("rpc completed")

		return resp, err
	}
}

// callerFromContext extracts a best-effort caller label from the peer address.
// On a Unix socket this is the socket endpoint; full UID/credential extraction
// and RBAC arrive with the Auth interceptor in a later phase. Returning a stable
// label now keeps log shape consistent across phases.
func callerFromContext(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.Network() + ":" + p.Addr.String()
	}
	return "unknown"
}
