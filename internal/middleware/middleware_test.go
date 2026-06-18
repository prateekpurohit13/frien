package middleware

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unaryInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestPanicRecovery_ConvertsPanicToInternal(t *testing.T) {
	interceptor := PanicRecovery(zerolog.Nop())

	resp, err := interceptor(context.Background(), nil, unaryInfo("/test/Boom"),
		func(ctx context.Context, req any) (any, error) {
			panic("boom")
		})

	if resp != nil {
		t.Errorf("response must be nil after panic, got %v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected INTERNAL, got %v", status.Code(err))
	}
	// The safe message must not leak the panic value.
	if got := status.Convert(err).Message(); got != "internal error" {
		t.Errorf("panic detail leaked into message: %q", got)
	}
}

func TestPanicRecovery_PassesThroughNormalResponse(t *testing.T) {
	interceptor := PanicRecovery(zerolog.Nop())
	resp, err := interceptor(context.Background(), nil, unaryInfo("/test/Ok"),
		func(ctx context.Context, req any) (any, error) {
			return "ok", nil
		})
	if err != nil || resp != "ok" {
		t.Fatalf("normal handler should pass through: resp=%v err=%v", resp, err)
	}
}

func TestRequestLogger_InjectsRequestID(t *testing.T) {
	interceptor := RequestLogger(zerolog.Nop())

	var seen string
	_, err := interceptor(context.Background(), nil, unaryInfo("/test/Echo"),
		func(ctx context.Context, req any) (any, error) {
			seen = RequestIDFromContext(ctx)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("interceptor error: %v", err)
	}
	if seen == "" {
		t.Fatal("handler did not observe a request ID in context")
	}
	if len(seen) < 4 || seen[:4] != "req_" {
		t.Errorf("unexpected request ID format: %q", seen)
	}
}

func TestRequestID_UniquePerCall(t *testing.T) {
	a, b := newRequestID(), newRequestID()
	if a == b {
		t.Error("request IDs must be unique per call")
	}
}
