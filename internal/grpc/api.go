package grpc

import (
	"context"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/prateekpurohit13/frien/internal/version"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// StatusInfo is the point-in-time node state reported by GetStatus. It is a plain
// data struct so the AdminService stays decoupled from the daemon's concrete
// subsystems (identity, storage, membership) — the daemon supplies a StatusSource
// that assembles this from live state on each call.
type StatusInfo struct {
	NodeID       string
	EnforceMode  string
	PeerCount    int64
	CertExpiry   time.Time
	WALSizeBytes int64
	StartedAt    time.Time
}

// StatusSource supplies live node status to the AdminService.
type StatusSource interface {
	Status() StatusInfo
}

// StatusFunc adapts a function to a StatusSource, so the daemon can pass a closure
// over its live subsystems without defining a named type.
type StatusFunc func() StatusInfo

// Status implements StatusSource.
func (f StatusFunc) Status() StatusInfo { return f() }

// AdminService implements the local admin gRPC API (proto/v1 AdminService).
//
// Phase 1 implements GetStatus, which needs only config, identity, and storage —
// all of which exist now. The remaining RPCs depend on subsystems built in later
// phases (mesh, policy, enforcement, audit) and return codes.Unimplemented with a
// clear message rather than a misleading empty success. This is deliberate: a stub
// that silently returns OK would be a worse production lie than an explicit
// Unimplemented.
type AdminService struct {
	frienv1.UnimplementedAdminServiceServer
	src      StatusSource
	readOnly bool
	log      zerolog.Logger
}

// NewAdminService constructs the admin service. readOnly mirrors admin_api.read_only
// and is enforced server-side (not only in the UI) once mutating RPCs exist.
func NewAdminService(src StatusSource, readOnly bool, log zerolog.Logger) *AdminService {
	return &AdminService{src: src, readOnly: readOnly, log: log}
}

// GetStatus returns current node health and state. Available to any authenticated
// caller (RBAC enforcement arrives with the Auth interceptor in a later phase).
func (s *AdminService) GetStatus(_ context.Context, _ *frienv1.GetStatusRequest) (*frienv1.GetStatusResponse, error) {
	info := s.src.Status()

	// Health reflects certificate validity: an expired cert means the node can no
	// longer authenticate to peers, which is a degraded (not healthy) state.
	health := "healthy"
	if !info.CertExpiry.IsZero() && time.Now().After(info.CertExpiry) {
		health = "degraded"
	}

	certExpires := ""
	if !info.CertExpiry.IsZero() {
		certExpires = info.CertExpiry.UTC().Format(time.RFC3339)
	}

	uptime := ""
	if !info.StartedAt.IsZero() {
		uptime = time.Since(info.StartedAt).Truncate(time.Second).String()
	}

	return &frienv1.GetStatusResponse{
		NodeId:       info.NodeID,
		Status:       health,
		EnforceMode:  info.EnforceMode,
		PeerCount:    info.PeerCount,
		ProtoVersion: strconv.FormatUint(uint64(version.ProtoVersion), 10),
		CertExpires:  certExpires,
		WalSizeBytes: info.WALSizeBytes,
		Uptime:       uptime,
	}, nil
}

// notYet returns a uniform Unimplemented error naming the phase that delivers the
// RPC, so an operator calling it early gets an actionable message.
func notYet(rpc, phase string) error {
	return status.Errorf(codes.Unimplemented, "%s is not available yet (delivered in %s)", rpc, phase)
}

func (s *AdminService) ListPeers(context.Context, *frienv1.ListPeersRequest) (*frienv1.ListPeersResponse, error) {
	return nil, notYet("ListPeers", "Phase 2 (membership)")
}

func (s *AdminService) ReportThreat(context.Context, *frienv1.ReportThreatRequest) (*frienv1.ReportThreatResponse, error) {
	return nil, notYet("ReportThreat", "Phase 3 (CRDT state mesh)")
}

func (s *AdminService) ExplainDecision(context.Context, *frienv1.ExplainDecisionRequest) (*frienv1.ExplainDecisionResponse, error) {
	return nil, notYet("ExplainDecision", "Phase 5 (policy + enforcement)")
}

func (s *AdminService) SetEnforceMode(context.Context, *frienv1.SetEnforceModeRequest) (*frienv1.SetEnforceModeResponse, error) {
	return nil, notYet("SetEnforceMode", "Phase 5 (policy + enforcement)")
}

func (s *AdminService) RollbackEnforcement(context.Context, *frienv1.RollbackEnforcementRequest) (*frienv1.RollbackEnforcementResponse, error) {
	return nil, notYet("RollbackEnforcement", "Phase 5 (policy + enforcement)")
}

func (s *AdminService) ListEnforcements(context.Context, *frienv1.ListEnforcementsRequest) (*frienv1.ListEnforcementsResponse, error) {
	return nil, notYet("ListEnforcements", "Phase 5 (policy + enforcement)")
}

func (s *AdminService) Breakglass(context.Context, *frienv1.BreakglassRequest) (*frienv1.BreakglassResponse, error) {
	return nil, notYet("Breakglass", "Phase 5 (enforcement)")
}

func (s *AdminService) GetHardenReport(context.Context, *frienv1.GetHardenReportRequest) (*frienv1.GetHardenReportResponse, error) {
	return nil, notYet("GetHardenReport", "Phase 7 (hardening)")
}

func (s *AdminService) TestPolicy(context.Context, *frienv1.TestPolicyRequest) (*frienv1.TestPolicyResponse, error) {
	return nil, notYet("TestPolicy", "Phase 5 (policy)")
}
