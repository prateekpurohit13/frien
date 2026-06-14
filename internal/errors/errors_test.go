package errors_test

import (
	"testing"

	frierr "github.com/prateekpurohit13/frien/internal/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAppError_Error(t *testing.T) {
	e := frierr.New(codes.NotFound, "record not found", "key=abc123")
	got := e.Error()
	if got == "" {
		t.Fatal("Error() returned empty string")
	}
}

func TestAppError_GRPCStatus(t *testing.T) {
	e := frierr.New(codes.InvalidArgument, "invalid confidence", "got 2.0")
	s := e.GRPCStatus()
	if s.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %s", s.Code())
	}
	// Safe message is returned; internal detail must NOT appear
	if s.Message() != "invalid confidence" {
		t.Errorf("unexpected message: %q", s.Message())
	}
}

func TestToGRPC_AppError(t *testing.T) {
	ae := frierr.PermissionDenied("caller has viewer role only")
	err := frierr.ToGRPC(ae)
	s, _ := status.FromError(err)
	if s.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %s", s.Code())
	}
	if s.Message() != "permission denied" {
		t.Errorf("unexpected message: %q", s.Message())
	}
}

func TestToGRPC_UnknownError(t *testing.T) {
	err := frierr.ToGRPC(frierr.Internal("db timeout: connection refused to /var/lib/frien/state.db"))
	s, _ := status.FromError(err)
	if s.Code() != codes.Internal {
		t.Errorf("expected Internal, got %s", s.Code())
	}
	// Internal detail must not leak
	if s.Message() != "internal error" {
		t.Errorf("unexpected message: %q", s.Message())
	}
}

func TestToGRPC_Nil(t *testing.T) {
	if err := frierr.ToGRPC(nil); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestIsCode(t *testing.T) {
	ae := frierr.NotFound("peer", "node_id=abc")
	if !frierr.IsCode(ae, codes.NotFound) {
		t.Error("expected IsCode(NotFound) = true")
	}
	if frierr.IsCode(ae, codes.Internal) {
		t.Error("expected IsCode(Internal) = false")
	}
	if frierr.IsCode(nil, codes.NotFound) {
		t.Error("expected IsCode(nil) = false")
	}
}

func TestSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  *frierr.AppError
		code codes.Code
	}{
		{"NotFound", frierr.NotFound("peer", ""), codes.NotFound},
		{"AlreadyExists", frierr.AlreadyExists("threat", ""), codes.AlreadyExists},
		{"InvalidArgument", frierr.InvalidArgument("confidence", ""), codes.InvalidArgument},
		{"RequiredField", frierr.RequiredField("node_id"), codes.InvalidArgument},
		{"PermissionDenied", frierr.PermissionDenied(""), codes.PermissionDenied},
		{"Unauthenticated", frierr.Unauthenticated(""), codes.Unauthenticated},
		{"RateLimited", frierr.RateLimited(""), codes.ResourceExhausted},
		{"Internal", frierr.Internal(""), codes.Internal},
		{"Unavailable", frierr.Unavailable(""), codes.Unavailable},
		{"FailedPrecondition", frierr.FailedPrecondition("flush_enforcement must be true", ""), codes.FailedPrecondition},
		{"DeadlineExceeded", frierr.DeadlineExceeded(""), codes.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != tc.code {
				t.Errorf("expected code %s, got %s", tc.code, tc.err.Code)
			}
			if tc.err.Message == "" {
				t.Error("Message should not be empty")
			}
		})
	}
}
