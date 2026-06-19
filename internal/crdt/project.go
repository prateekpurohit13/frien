package crdt

import (
	"time"

	"google.golang.org/protobuf/proto"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// PresentOps returns the envelopes that are live at now: not retracted, not a
// control op, and not past their origin-declared expiry. Expiry compares the
// op's expires_at (carried in the immutable payload) against now, so a replica
// targets the same instant regardless of when it received the op.
func (s *OpSet) PresentOps(now time.Time) []*frienv1.OperationEnvelope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	retracted := s.retractedSet()

	var out []*frienv1.OperationEnvelope
	for _, env := range s.ops {
		if present(env, now, retracted) {
			out = append(out, env)
		}
	}
	return out
}

// ActiveThreats returns the live ThreatRecords, decoded from the present ops.
func (s *OpSet) ActiveThreats(now time.Time) []*frienv1.ThreatRecord {
	var out []*frienv1.ThreatRecord
	for _, env := range s.PresentOps(now) {
		if env.GetOpType() != OpThreatRecord {
			continue
		}
		var tr frienv1.ThreatRecord
		if err := proto.Unmarshal(env.GetPayload(), &tr); err == nil {
			out = append(out, &tr)
		}
	}
	return out
}

// IsPresent reports whether a single op is live at now.
func (s *OpSet) IsPresent(opID string, now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	env, ok := s.ops[opID]
	if !ok {
		return false
	}
	return present(env, now, s.retractedSet())
}

func present(env *frienv1.OperationEnvelope, now time.Time, retracted map[string]bool) bool {
	if env.GetOpType() == OpRetraction {
		return false
	}
	if retracted[env.GetOpId()] {
		return false
	}
	if exp, ok := expiresAt(env); ok && !now.Before(exp) {
		return false
	}
	return true
}

// expiresAt extracts the expiry instant from an op's payload, if its type
// carries one. Records with no expiry never age out by TTL.
func expiresAt(env *frienv1.OperationEnvelope) (time.Time, bool) {
	switch env.GetOpType() {
	case OpThreatRecord:
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) == nil {
			return parseRFC3339(tr.GetExpiresAt())
		}
	case OpEnforcementDecision:
		var d frienv1.EnforcementDecision
		if proto.Unmarshal(env.GetPayload(), &d) == nil {
			return parseRFC3339(d.GetExpiresAt())
		}
	}
	return time.Time{}, false
}

func parseRFC3339(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
