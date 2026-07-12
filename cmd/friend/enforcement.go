package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/coordinator"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// enforcementService backs internal/grpc.EnforcementService with the live
// coordinator, enforcement client, and audit log. It is the daemon-side glue
// for the Phase 5 admin RPCs.
type enforcementService struct {
	coord    *coordinator.Coordinator
	client   enforcer.Client
	auditLog *audit.Log
	adapters []string // adapters breakglass/force-observe iterates
	log      zerolog.Logger

	bgMu    sync.Mutex
	bgTimes []time.Time // breakglass invocation timestamps for the 2/min limiter
}

func newEnforcementService(coord *coordinator.Coordinator, client enforcer.Client, auditLog *audit.Log, adapters []string, log zerolog.Logger) *enforcementService {
	return &enforcementService{coord: coord, client: client, auditLog: auditLog, adapters: adapters, log: log}
}

func (s *enforcementService) Explain(indicator string) (*frienv1.ExplainDecisionResponse, error) {
	ex, err := s.coord.Explain(indicator)
	if err != nil {
		return nil, err
	}
	return ex.ToProto(), nil
}

func (s *enforcementService) SetMode(adapter, mode, reason string) (prev, cur, auditID string, err error) {
	prev, err = s.client.SetMode(adapter, mode)
	if err != nil {
		return "", "", "", err
	}
	auditID = s.audit(audit.Entry{
		Actor: "operator", Action: audit.ActionModeSet, Adapter: adapter,
		Reason: reason, Details: map[string]string{"from": prev, "to": mode},
	})
	return prev, mode, auditID, nil
}

func (s *enforcementService) Rollback(token, reason string) (status, auditID string, err error) {
	status, err = s.client.Rollback(token, reason)
	if err != nil {
		return "", "", err
	}
	auditID = s.audit(audit.Entry{
		Actor: "operator", Action: audit.ActionRollback, Reason: reason,
		Details: map[string]string{"token": token, "status": status},
	})
	return status, auditID, nil
}

func (s *enforcementService) ListEnforcements(adapterFilter string, _ bool) ([]*frienv1.EnforcementDecision, error) {
	rules, err := s.client.List()
	if err != nil {
		return nil, err
	}
	out := make([]*frienv1.EnforcementDecision, 0, len(rules))
	for _, r := range rules {
		dec := &frienv1.EnforcementDecision{
			Id:            r.Token,
			RollbackToken: r.Token,
			Target:        r.Target,
			Action:        r.Action,
			Adapter:       "nftables",
			Mode:          "enforce",
			Owner:         "frien-enforcer",
			Applied:       true,
		}
		if adapterFilter != "" && dec.Adapter != adapterFilter {
			continue
		}
		if !r.ExpiresAt.IsZero() {
			dec.ExpiresAt = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dec)
	}
	return out, nil
}

func (s *enforcementService) Breakglass(reason, confirmationCode string) (rulesRemoved int64, newMode, auditID string, err error) {
	if !s.allowBreakglass() {
		return 0, "", "", fmt.Errorf("breakglass rate limit exceeded (2/min)")
	}
	n, err := s.client.Flush(reason)
	if err != nil {
		return 0, "", "", err
	}
	// Force observe on every adapter so nothing re-applies after the flush.
	for _, a := range s.adapters {
		if _, merr := s.client.SetMode(a, enforcer.ModeObserve); merr != nil {
			s.log.Warn().Err(merr).Str("adapter", a).Msg("breakglass: forcing observe")
		}
	}
	auditID = s.audit(audit.Entry{
		Actor: "operator", Action: audit.ActionBreakglass, Reason: reason,
		Outcome: "flushed", Details: map[string]string{"rules_removed": fmt.Sprintf("%d", n), "confirmation": confirmationCode},
	})
	return int64(n), enforcer.ModeObserve, auditID, nil
}

// TestPolicy dry-runs a single sample threat against a policy. It never touches
// live state: it builds one representative contribution and asks the pure policy
// engine what it would do if the node were promoted to enforce and were in a
// healthy (majority) partition.
func (s *enforcementService) TestPolicy(policyID, threatJSON string) (*frienv1.TestPolicyResponse, error) {
	p := s.coord.ActivePolicy()
	if p == nil {
		return nil, fmt.Errorf("no active policy to test against")
	}
	if policyID != "" && policyID != p.ID {
		return nil, fmt.Errorf("only the active policy (%s) can be tested; policy stores are Phase 7", p.ID)
	}
	var tr frienv1.ThreatRecord
	if err := protojson.Unmarshal([]byte(threatJSON), &tr); err != nil {
		return nil, fmt.Errorf("parsing threat_json: %w", err)
	}
	protected, err := policy.FromPolicy(p)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ttl := time.Duration(0)
	if tr.GetTtl() != "" {
		if d, perr := time.ParseDuration(tr.GetTtl()); perr == nil {
			ttl = d
		}
	}
	in := policy.EvalInput{
		Indicator:     tr.GetIndicator(),
		IndicatorType: tr.GetIndicatorType(),
		Scope:         orDefaultScope(tr.GetScope()),
		Contributions: []policy.Contribution{{
			OpID:        "sample",
			OriginNode:  orDefault(tr.GetReportedBy(), "sample-node"),
			Fingerprint: orDefault(tr.GetReportedBy(), "sample-node"),
			TrustTier:   "standard",
			Confidence:  tr.GetConfidence(),
			ReceivedAt:  now,
		}},
		NodeMode:  policy.ModeEnforce, // dry-run asks "would it enforce if promoted"
		Partition: policy.PartitionState{LiveDistinct: 1, KnownDistinct: 1},
		Protected: protected,
		RecordTTL: ttl,
		Now:       now,
	}
	d := policy.Evaluate(p, in)

	resp := &frienv1.TestPolicyResponse{
		Reason:         d.Reason,
		MatchedPolicy:  p.ID,
		RequiredWeight: d.RequiredWeight,
	}
	switch d.Outcome {
	case policy.OutcomeEnforced:
		resp.Decision = policy.OutcomeWouldEnforce
	case policy.OutcomeDeniedByPolicy:
		resp.Decision = policy.OutcomeDeniedTestPolicy
		resp.ProtectedReasons = d.ProtectedReasons
	default:
		resp.Decision = policy.OutcomeObserveOnly
	}
	return resp, nil
}

// allowBreakglass enforces the 2-per-minute breakglass rate limit.
func (s *enforcementService) allowBreakglass() bool {
	s.bgMu.Lock()
	defer s.bgMu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	kept := s.bgTimes[:0]
	for _, t := range s.bgTimes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	s.bgTimes = kept
	if len(s.bgTimes) >= 2 {
		return false
	}
	s.bgTimes = append(s.bgTimes, time.Now())
	return true
}

func (s *enforcementService) audit(e audit.Entry) string {
	if s.auditLog == nil {
		return ""
	}
	entry, err := s.auditLog.Append(e)
	if err != nil {
		s.log.Warn().Err(err).Str("action", e.Action).Msg("audit append failed")
		return ""
	}
	return entry.ID
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orDefaultScope(s string) string {
	if s == "" {
		return "fleet"
	}
	return s
}
