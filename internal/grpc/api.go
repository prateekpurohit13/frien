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

// PeerInfo is one entry of the membership roster, as reported by ListPeers. It is
// a plain struct so the AdminService stays decoupled from the membership package.
type PeerInfo struct {
	NodeID    string
	Status    string
	Addresses []string
	LastSeen  time.Time
}

// PeerSource supplies the live membership roster. The daemon backs it with the
// gossip engine once the mesh is running; until then it is nil and ListPeers
// reports Unimplemented.
type PeerSource interface {
	Peers() []PeerInfo
}

// OperatorOpInjector admits an externally-supplied, already-signed envelope
// into local state through the same verification/admission path a
// peer-received op takes. gossip.Engine.Ingest satisfies this.
type OperatorOpInjector interface {
	Ingest(env *frienv1.OperationEnvelope) error
}

// CompactionTrigger runs one compaction pass on demand, for scopeKey (empty
// = every subscribed scope), and reports which scopes actually compacted
// something. internal/checkpoint's Compactor, adapted by cmd/friend, satisfies
// this.
type CompactionTrigger interface {
	TriggerCompaction(scopeKey string) []string
}

// CARotator stages a new CA bundle for the overlap window (see
// internal/identity.TrustBundle) and makes it take effect on the live
// transport. cmd/friend adapts a TrustBundle + transport.Transport pair to
// satisfy this (staging alone isn't enough -- the transport must also be
// told to re-read the bundle).
type CARotator interface {
	PrepareNext(nextCAPEM []byte) error
}

// EnforcementService is the daemon-side backing for the Phase 5 policy and
// enforcement RPCs. cmd/friend implements it over the coordinator, the
// enforcement client, and the audit log, keeping this package decoupled from
// those subsystems. It is nil until the daemon wires it, in which case the
// enforcement RPCs report Unimplemented.
type EnforcementService interface {
	Explain(indicator string) (*frienv1.ExplainDecisionResponse, error)
	SetMode(adapter, mode, reason string) (prev, cur, auditID string, err error)
	Rollback(token, reason string) (status, auditID string, err error)
	ListEnforcements(adapterFilter string, includeExpired bool) ([]*frienv1.EnforcementDecision, error)
	Breakglass(reason, confirmationCode string) (rulesRemoved int64, newMode, auditID string, err error)
	TestPolicy(policyID, threatJSON string) (*frienv1.TestPolicyResponse, error)
}

// ObservabilityService backs the Phase 6 read RPCs and the ReportThreat ingest
// path. cmd/friend implements it over the reporter, the mesh engine, the audit
// log, and the enforcement client. Nil until wired, in which case these RPCs
// report Unimplemented.
type ObservabilityService interface {
	ReportThreat(req *frienv1.ReportThreatRequest) (*frienv1.ReportThreatResponse, error)
	ListThreats(scopeFilter, severityFilter string) ([]*frienv1.ThreatRecord, error)
	GetStats() (*frienv1.GetStatsResponse, error)
	ListAudit(limit int) ([]*frienv1.AuditEntrySummary, error)
}

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
	src       StatusSource
	peers     PeerSource
	injector  OperatorOpInjector
	compactor CompactionTrigger
	rotator   CARotator
	enforce   EnforcementService
	obs       ObservabilityService
	readOnly  bool
	log       zerolog.Logger
}

// NewAdminService constructs the admin service. readOnly mirrors admin_api.read_only
// and is enforced server-side (not only in the UI): InjectOperatorOp and
// TriggerCompaction are the first mutating RPCs and check it before doing anything.
func NewAdminService(src StatusSource, readOnly bool, log zerolog.Logger) *AdminService {
	return &AdminService{src: src, readOnly: readOnly, log: log}
}

// SetPeerSource wires the membership roster into ListPeers once the mesh engine
// is running.
func (s *AdminService) SetPeerSource(p PeerSource) { s.peers = p }

// SetOperatorOpInjector wires InjectOperatorOp once the mesh engine is running.
func (s *AdminService) SetOperatorOpInjector(i OperatorOpInjector) { s.injector = i }

// SetCompactionTrigger wires TriggerCompaction once the compactor is running.
func (s *AdminService) SetCompactionTrigger(c CompactionTrigger) { s.compactor = c }

// SetCARotator wires RotateCA once the trust bundle and transport are running.
func (s *AdminService) SetCARotator(r CARotator) { s.rotator = r }

// SetEnforcementService wires the Phase 5 policy/enforcement RPCs.
func (s *AdminService) SetEnforcementService(e EnforcementService) { s.enforce = e }

// SetObservabilityService wires the Phase 6 ReportThreat + read RPCs.
func (s *AdminService) SetObservabilityService(o ObservabilityService) { s.obs = o }

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
	if s.peers == nil {
		return nil, notYet("ListPeers", "Phase 3e (mesh wiring)")
	}
	peers := s.peers.Peers()
	out := make([]*frienv1.PeerState, 0, len(peers))
	for _, p := range peers {
		ps := &frienv1.PeerState{NodeId: p.NodeID, Status: p.Status, Addresses: p.Addresses}
		if !p.LastSeen.IsZero() {
			ps.LastSeen = p.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, ps)
	}
	return &frienv1.ListPeersResponse{Peers: out}, nil
}

// ReportThreat ingests one observation through admission and, if admitted,
// publishes it as a signed threat op. It is the entry point for both detectors
// and manual operator reports. It is not gated by read_only: threat ingestion is
// the detection data path, not an administrative mutation of enforcement state.
func (s *AdminService) ReportThreat(_ context.Context, req *frienv1.ReportThreatRequest) (*frienv1.ReportThreatResponse, error) {
	if s.obs == nil {
		return nil, notYet("ReportThreat", "Phase 6 (detection)")
	}
	if req.GetIndicator() == "" || req.GetIndicatorType() == "" || req.GetSeverity() == "" {
		return nil, status.Error(codes.InvalidArgument, "indicator, indicator_type, and severity are required")
	}
	resp, err := s.obs.ReportThreat(req)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "report threat: %v", err)
	}
	return resp, nil
}

// ListThreats returns the present threat records (read-only).
func (s *AdminService) ListThreats(_ context.Context, req *frienv1.ListThreatsRequest) (*frienv1.ListThreatsResponse, error) {
	if s.obs == nil {
		return nil, notYet("ListThreats", "Phase 6 (detection)")
	}
	threats, err := s.obs.ListThreats(req.GetScopeFilter(), req.GetSeverityFilter())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list threats: %v", err)
	}
	return &frienv1.ListThreatsResponse{Threats: threats}, nil
}

// GetStats returns aggregate counters for the operator dashboard (read-only).
func (s *AdminService) GetStats(_ context.Context, _ *frienv1.GetStatsRequest) (*frienv1.GetStatsResponse, error) {
	if s.obs == nil {
		return nil, notYet("GetStats", "Phase 6 (detection)")
	}
	stats, err := s.obs.GetStats()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get stats: %v", err)
	}
	return stats, nil
}

// ListAudit returns the recent audit tail, newest first (read-only).
func (s *AdminService) ListAudit(_ context.Context, req *frienv1.ListAuditRequest) (*frienv1.ListAuditResponse, error) {
	if s.obs == nil {
		return nil, notYet("ListAudit", "Phase 6 (detection)")
	}
	entries, err := s.obs.ListAudit(int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list audit: %v", err)
	}
	return &frienv1.ListAuditResponse{Entries: entries}, nil
}

// ExplainDecision returns the full decision trail for an indicator (read-only).
func (s *AdminService) ExplainDecision(_ context.Context, req *frienv1.ExplainDecisionRequest) (*frienv1.ExplainDecisionResponse, error) {
	if s.enforce == nil {
		return nil, notYet("ExplainDecision", "Phase 5 (policy + enforcement)")
	}
	if req.GetIndicator() == "" {
		return nil, status.Error(codes.InvalidArgument, "indicator is required")
	}
	resp, err := s.enforce.Explain(req.GetIndicator())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "explain: %v", err)
	}
	return resp, nil
}

// SetEnforceMode promotes/demotes an adapter's enforcement mode. Mutating, so it
// is refused under admin_api.read_only and writes an audit entry.
func (s *AdminService) SetEnforceMode(_ context.Context, req *frienv1.SetEnforceModeRequest) (*frienv1.SetEnforceModeResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.enforce == nil {
		return nil, notYet("SetEnforceMode", "Phase 5 (policy + enforcement)")
	}
	if req.GetMode() != "observe" && req.GetMode() != "enforce" {
		return nil, status.Error(codes.InvalidArgument, "mode must be observe|enforce")
	}
	if req.GetAdapter() == "" || req.GetReason() == "" {
		return nil, status.Error(codes.InvalidArgument, "adapter and reason are required")
	}
	prev, cur, auditID, err := s.enforce.SetMode(req.GetAdapter(), req.GetMode(), req.GetReason())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "set mode: %v", err)
	}
	s.log.Warn().Str("adapter", req.GetAdapter()).Str("from", prev).Str("to", cur).
		Str("reason", req.GetReason()).Msg("admin: enforce mode changed")
	return &frienv1.SetEnforceModeResponse{PreviousMode: prev, CurrentMode: cur, AuditId: auditID}, nil
}

// RollbackEnforcement removes an applied rule by its rollback token.
func (s *AdminService) RollbackEnforcement(_ context.Context, req *frienv1.RollbackEnforcementRequest) (*frienv1.RollbackEnforcementResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.enforce == nil {
		return nil, notYet("RollbackEnforcement", "Phase 5 (policy + enforcement)")
	}
	if req.GetRollbackToken() == "" || req.GetReason() == "" {
		return nil, status.Error(codes.InvalidArgument, "rollback_token and reason are required")
	}
	st, auditID, err := s.enforce.Rollback(req.GetRollbackToken(), req.GetReason())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "rollback: %v", err)
	}
	return &frienv1.RollbackEnforcementResponse{Status: st, AuditId: auditID}, nil
}

// ListEnforcements returns the node's active (and optionally expired) rules.
func (s *AdminService) ListEnforcements(_ context.Context, req *frienv1.ListEnforcementsRequest) (*frienv1.ListEnforcementsResponse, error) {
	if s.enforce == nil {
		return nil, notYet("ListEnforcements", "Phase 5 (policy + enforcement)")
	}
	list, err := s.enforce.ListEnforcements(req.GetAdapterFilter(), req.GetIncludeExpired())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list enforcements: %v", err)
	}
	return &frienv1.ListEnforcementsResponse{Enforcements: list}, nil
}

// Breakglass flushes all frien-managed rules and forces observe mode. It is the
// self-lockout escape hatch and requires both explicit flags and a confirmation
// code (see docs/ENFORCEMENT_SAFETY.md §Breakglass).
func (s *AdminService) Breakglass(_ context.Context, req *frienv1.BreakglassRequest) (*frienv1.BreakglassResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.enforce == nil {
		return nil, notYet("Breakglass", "Phase 5 (enforcement)")
	}
	if !req.GetFlushEnforcement() || !req.GetForceObserve() {
		return nil, status.Error(codes.InvalidArgument, "breakglass requires flush_enforcement=true and force_observe=true")
	}
	if req.GetReason() == "" || req.GetConfirmationCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "reason and confirmation_code are required")
	}
	removed, newMode, auditID, err := s.enforce.Breakglass(req.GetReason(), req.GetConfirmationCode())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "breakglass: %v", err)
	}
	s.log.Warn().Int64("rules_removed", removed).Str("reason", req.GetReason()).Msg("admin: BREAKGLASS invoked")
	return &frienv1.BreakglassResponse{RulesRemoved: removed, NewMode: newMode, AuditId: auditID}, nil
}

func (s *AdminService) GetHardenReport(context.Context, *frienv1.GetHardenReportRequest) (*frienv1.GetHardenReportResponse, error) {
	return nil, notYet("GetHardenReport", "Phase 7 (hardening)")
}

// TestPolicy dry-runs a threat sample against a policy without touching state.
func (s *AdminService) TestPolicy(_ context.Context, req *frienv1.TestPolicyRequest) (*frienv1.TestPolicyResponse, error) {
	if s.enforce == nil {
		return nil, notYet("TestPolicy", "Phase 5 (policy)")
	}
	if req.GetThreatJson() == "" {
		return nil, status.Error(codes.InvalidArgument, "threat_json is required")
	}
	resp, err := s.enforce.TestPolicy(req.GetPolicyId(), req.GetThreatJson())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "test policy: %v", err)
	}
	return resp, nil
}

// InjectOperatorOp admits an operator-signed envelope (built offline; see the
// proto doc comment). It never signs anything itself -- the node holds no
// operator key -- it only routes the already-signed bytes through the same
// verify-then-admit path anti-entropy uses, so an envelope that doesn't
// actually verify against the pinned operator key is rejected exactly as it
// would be if a peer had gossiped it.
func (s *AdminService) InjectOperatorOp(_ context.Context, req *frienv1.InjectOperatorOpRequest) (*frienv1.InjectOperatorOpResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.injector == nil {
		return nil, notYet("InjectOperatorOp", "Phase 4 follow-up (mesh wiring)")
	}
	env := req.GetEnvelope()
	if env.GetOpId() == "" {
		return nil, status.Error(codes.InvalidArgument, "envelope missing op_id")
	}
	if err := s.injector.Ingest(env); err != nil {
		s.log.Warn().Err(err).Str("op", env.GetOpId()).Msg("admin: InjectOperatorOp rejected")
		return nil, status.Errorf(codes.InvalidArgument, "envelope rejected: %v", err)
	}
	s.log.Info().Str("op", env.GetOpId()).Str("op_type", env.GetOpType()).Msg("admin: operator op injected")
	return &frienv1.InjectOperatorOpResponse{OpId: env.GetOpId()}, nil
}

// TriggerCompaction runs one compaction pass immediately rather than waiting
// for the configured interval -- useful before a maintenance window, or to
// inspect the resulting checkpoint on demand.
func (s *AdminService) TriggerCompaction(_ context.Context, req *frienv1.TriggerCompactionRequest) (*frienv1.TriggerCompactionResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.compactor == nil {
		return nil, notYet("TriggerCompaction", "Phase 4 follow-up (mesh wiring)")
	}
	compacted := s.compactor.TriggerCompaction(req.GetScope())
	return &frienv1.TriggerCompactionResponse{CompactedScopes: compacted}, nil
}

// RotateCA stages a new CA bundle for the overlap window. It never performs
// an atomic cutover itself -- the old bundle stays valid until the window
// configured on the trust bundle elapses (see identity.TrustBundle), so
// callers must run this on every node before rolling out any new-CA-issued
// leaf certificate, not as a substitute for that rollout.
func (s *AdminService) RotateCA(_ context.Context, req *frienv1.RotateCARequest) (*frienv1.RotateCAResponse, error) {
	if err := s.rejectIfReadOnly(); err != nil {
		return nil, err
	}
	if s.rotator == nil {
		return nil, notYet("RotateCA", "Phase 4 follow-up (mesh wiring)")
	}
	if len(req.GetNextCaPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "next_ca_pem is required")
	}
	if err := s.rotator.PrepareNext(req.GetNextCaPem()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "staging new CA bundle: %v", err)
	}
	s.log.Info().Msg("admin: new CA bundle staged for overlap-window rotation")
	return &frienv1.RotateCAResponse{InOverlap: true}, nil
}

// rejectIfReadOnly guards every mutating RPC against admin_api.read_only.
func (s *AdminService) rejectIfReadOnly() error {
	if s.readOnly {
		return status.Error(codes.FailedPrecondition, "admin API is read-only (admin_api.read_only)")
	}
	return nil
}
