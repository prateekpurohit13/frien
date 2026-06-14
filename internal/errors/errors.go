package errors

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AppError struct {
	Code    codes.Code
	Message string
	Detail  string
}

func (e *AppError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// GRPCStatus converts the AppError into a gRPC status using only the safe Message.
func (e *AppError) GRPCStatus() *status.Status {
	return status.New(e.Code, e.Message)
}

// msg is returned to the caller; detail is logged internally only.
func New(code codes.Code, msg, detail string) *AppError {
	return &AppError{Code: code, Message: msg, Detail: detail}
}

// Wrap wraps an existing error, preserving the detail for logs.
func Wrap(code codes.Code, msg string, cause error) *AppError {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	return &AppError{Code: code, Message: msg, Detail: detail}
}

// IsCode reports whether err is an *AppError with the given code.
func IsCode(err error, code codes.Code) bool {
	if err == nil {
		return false
	}
	if ae, ok := err.(*AppError); ok {
		return ae.Code == code
	}
	return false
}

// ToGRPC converts any error to a gRPC status error safe for returning to callers.
// If err is already an *AppError, uses its Code and Message.
// Otherwise returns INTERNAL with a generic message (never leaks the original error text).
func ToGRPC(err error) error {
	if err == nil {
		return nil
	}
	if ae, ok := err.(*AppError); ok {
		return ae.GRPCStatus().Err()
	}
	return status.Error(codes.Internal, "internal error")
}

// ─── Sentinel constructors ────────────────────────────────────────────────────

func NotFound(resource, detail string) *AppError {
	return New(codes.NotFound, resource+" not found", detail)
}

func AlreadyExists(resource, detail string) *AppError {
	return New(codes.AlreadyExists, resource+" already exists", detail)
}

func InvalidArgument(field, detail string) *AppError {
	return New(codes.InvalidArgument, "invalid argument: "+field, detail)
}

func RequiredField(field string) *AppError {
	return New(codes.InvalidArgument, "required field missing: "+field, "")
}

func PermissionDenied(detail string) *AppError {
	return New(codes.PermissionDenied, "permission denied", detail)
}

func Unauthenticated(detail string) *AppError {
	return New(codes.Unauthenticated, "authentication required", detail)
}

func RateLimited(detail string) *AppError {
	return New(codes.ResourceExhausted, "rate limit exceeded", detail)
}

func Internal(detail string) *AppError {
	return New(codes.Internal, "internal error", detail)
}

func Unavailable(detail string) *AppError {
	return New(codes.Unavailable, "service temporarily unavailable", detail)
}

func FailedPrecondition(reason, detail string) *AppError {
	return New(codes.FailedPrecondition, "precondition not met: "+reason, detail)
}

func DeadlineExceeded(detail string) *AppError {
	return New(codes.DeadlineExceeded, "deadline exceeded", detail)
}
