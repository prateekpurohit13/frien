package main

import (
	"sort"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/gossip"
	"github.com/prateekpurohit13/frien/internal/reporter"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// observabilityService backs internal/grpc.ObservabilityService: the Phase 6
// ReportThreat ingest path plus the read RPCs (ListThreats/GetStats/ListAudit)
// that feed the operator TUI. It aggregates live state from the mesh engine,
// the audit log, and the enforcement client — all read-only except ReportThreat,
// which routes through the reporter's admission control.
type observabilityService struct {
	rep      *reporter.Reporter
	mesh     *gossip.Engine
	auditLog *audit.Log
	client   enforcer.Client
	adapter  string
	now      func() time.Time
}

func newObservabilityService(rep *reporter.Reporter, mesh *gossip.Engine, auditLog *audit.Log, client enforcer.Client, adapter string) *observabilityService {
	return &observabilityService{rep: rep, mesh: mesh, auditLog: auditLog, client: client, adapter: adapter, now: time.Now}
}

func (s *observabilityService) ReportThreat(req *frienv1.ReportThreatRequest) (*frienv1.ReportThreatResponse, error) {
	res, err := s.rep.Report(reporter.Params{
		Indicator:     req.GetIndicator(),
		IndicatorType: req.GetIndicatorType(),
		Reason:        req.GetReason(),
		Severity:      req.GetSeverity(),
		Confidence:    req.GetConfidence(),
		TTL:           req.GetTtl(),
		Scope:         req.GetScope(),
		Detector:      "operator",
		EvidenceJSON:  []byte(req.GetEvidenceJson()),
	})
	if err != nil {
		return nil, err
	}
	return &frienv1.ReportThreatResponse{OpId: res.OpID, ThreatId: res.ThreatID, Status: res.Status}, nil
}

func (s *observabilityService) ListThreats(scopeFilter, severityFilter string) ([]*frienv1.ThreatRecord, error) {
	now := s.now()
	var out []*frienv1.ThreatRecord
	for _, env := range s.mesh.PresentThreatOps(now) {
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) != nil {
			continue
		}
		if scopeFilter != "" && tr.GetScope() != scopeFilter {
			continue
		}
		if severityFilter != "" && tr.GetSeverity() != severityFilter {
			continue
		}
		out = append(out, &tr)
	}
	// Newest first by created_at.
	sort.Slice(out, func(i, j int) bool { return out[i].GetCreatedAt() > out[j].GetCreatedAt() })
	return out, nil
}

func (s *observabilityService) GetStats() (*frienv1.GetStatsResponse, error) {
	now := s.now()
	stats := &frienv1.GetStatsResponse{
		ThreatsBySeverity:    map[string]int64{},
		ThreatsByScope:       map[string]int64{},
		ThreatsByDetector:    map[string]int64{},
		EnforcementsByAction: map[string]int64{},
		PeersByState:         map[string]int64{},
	}

	// Threats.
	for _, env := range s.mesh.PresentThreatOps(now) {
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) != nil {
			continue
		}
		stats.ThreatsTotal++
		stats.ThreatsBySeverity[nonEmpty(tr.GetSeverity(), "unknown")]++
		stats.ThreatsByScope[nonEmpty(tr.GetScope(), "unknown")]++
		stats.ThreatsByDetector[nonEmpty(tr.GetDetector(), "unknown")]++
	}

	// Active enforcements (by action).
	if rules, err := s.client.List(); err == nil {
		stats.ActiveEnforcements = int64(len(rules))
		for _, r := range rules {
			stats.EnforcementsByAction[nonEmpty(r.Action, "block")]++
		}
	}

	// Membership (self + peers) by state.
	stats.PeersByState["alive"]++ // self is alive
	for _, m := range s.mesh.Peers() {
		stats.PeersByState[m.State.String()]++
	}

	// Recent decisions (quorum feed), newest first, capped.
	decisions := s.recentDecisions(now, 12)
	stats.RecentDecisions = decisions

	// Audit + mode.
	if s.auditLog != nil {
		if entries, err := s.auditLog.List(0); err == nil {
			stats.AuditEntries = int64(len(entries))
		}
	}
	if s.client != nil {
		if m, err := s.client.GetMode(s.adapter); err == nil {
			stats.EnforceMode = m
		}
	}
	return stats, nil
}

func (s *observabilityService) recentDecisions(now time.Time, limit int) []*frienv1.DecisionStat {
	var out []*frienv1.DecisionStat
	for _, env := range s.mesh.PresentDecisionOps(now) {
		var d frienv1.EnforcementDecision
		if proto.Unmarshal(env.GetPayload(), &d) != nil {
			continue
		}
		out = append(out, &frienv1.DecisionStat{
			Indicator:      d.GetTarget(),
			Outcome:        "enforced", // present published decisions were applied
			MatchedWeight:  d.GetMatchedWeight(),
			RequiredWeight: d.GetRequiredWeight(),
			CreatedAt:      d.GetCreatedAt(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetCreatedAt() > out[j].GetCreatedAt() })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *observabilityService) ListAudit(limit int) ([]*frienv1.AuditEntrySummary, error) {
	if s.auditLog == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	entries, err := s.auditLog.List(limit)
	if err != nil {
		return nil, err
	}
	out := make([]*frienv1.AuditEntrySummary, 0, len(entries))
	for _, e := range entries {
		out = append(out, &frienv1.AuditEntrySummary{
			Id:      e.ID,
			Time:    e.Time.UTC().Format(time.RFC3339),
			Actor:   e.Actor,
			Action:  e.Action,
			Adapter: e.Adapter,
			Target:  e.Target,
			Outcome: e.Outcome,
			Reason:  e.Reason,
		})
	}
	return out, nil
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
