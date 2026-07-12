package policy

import (
	"testing"
	"time"
)

func mkContrib(id, fp, tier string, conf float64, age time.Duration, now time.Time) Contribution {
	return Contribution{
		OpID:        "op-" + id,
		OriginNode:  id,
		Fingerprint: fp,
		TrustTier:   tier,
		Confidence:  conf,
		ReceivedAt:  now.Add(-age),
	}
}

func TestQuorumDistinctIdentitiesWeighted(t *testing.T) {
	p := samplePolicy() // require_weight 3.0, min_conf 0.85
	now := time.Now()
	// Three distinct standard identities → weight 3.0 → met.
	c := []Contribution{
		mkContrib("a", "fpA", "standard", 0.9, time.Minute, now),
		mkContrib("b", "fpB", "standard", 0.9, time.Minute, now),
		mkContrib("c", "fpC", "standard", 0.9, time.Minute, now),
	}
	q := EvaluateQuorum(p, c, now)
	if !q.Met || q.MatchedWeight != 3.0 {
		t.Fatalf("expected met with weight 3.0, got %+v", q)
	}
	if len(q.Identities) != 3 {
		t.Fatalf("expected 3 identities, got %v", q.Identities)
	}
}

func TestQuorumNoDoubleCountSameIdentity(t *testing.T) {
	p := samplePolicy()
	now := time.Now()
	// Same fingerprint reporting three times must count once (weight 1.0).
	c := []Contribution{
		mkContrib("a", "fpA", "standard", 0.9, time.Minute, now),
		{OpID: "op2", OriginNode: "a", Fingerprint: "fpA", TrustTier: "standard", Confidence: 0.9, ReceivedAt: now},
		{OpID: "op3", OriginNode: "a", Fingerprint: "fpA", TrustTier: "standard", Confidence: 0.9, ReceivedAt: now},
	}
	q := EvaluateQuorum(p, c, now)
	if q.Met || q.MatchedWeight != 1.0 {
		t.Fatalf("expected one contributor weight 1.0, got %+v", q)
	}
}

func TestQuorumTrustTierWeighting(t *testing.T) {
	p := samplePolicy()
	now := time.Now()
	// One "trusted" identity (weight 3.0) meets require_weight 3.0 alone.
	c := []Contribution{mkContrib("a", "fpA", "trusted", 0.9, time.Minute, now)}
	q := EvaluateQuorum(p, c, now)
	if !q.Met || q.MatchedWeight != 3.0 {
		t.Fatalf("trusted tier should weigh 3.0, got %+v", q)
	}
}

func TestQuorumExcludesRevokedLowConfAndStale(t *testing.T) {
	p := samplePolicy()
	now := time.Now()
	c := []Contribution{
		{OpID: "1", OriginNode: "a", Fingerprint: "fpA", TrustTier: "trusted", Confidence: 0.9, ReceivedAt: now, Revoked: true},         // revoked
		{OpID: "2", OriginNode: "b", Fingerprint: "fpB", TrustTier: "trusted", Confidence: 0.5, ReceivedAt: now},                        // low confidence
		{OpID: "3", OriginNode: "c", Fingerprint: "fpC", TrustTier: "trusted", Confidence: 0.9, ReceivedAt: now.Add(-10 * time.Minute)}, // stale (window 5m)
		mkContrib("d", "fpD", "standard", 0.9, time.Minute, now),                                                                        // counts (1.0)
	}
	q := EvaluateQuorum(p, c, now)
	if q.MatchedWeight != 1.0 || q.Met {
		t.Fatalf("only the one valid standard identity should count, got %+v", q)
	}
	if len(q.Identities) != 1 || q.Identities[0] != "fpD" {
		t.Fatalf("expected only fpD, got %v", q.Identities)
	}
}

func TestPartitionMajority(t *testing.T) {
	cases := []struct {
		live, known int
		want        bool
	}{
		{1, 1, true},  // single-node fleet: trivially majority
		{2, 3, true},  // 2 of 3 observable
		{1, 3, false}, // minority
		{2, 4, false}, // exactly half is NOT a strict majority
		{3, 4, true},  // 3 of 4
		{0, 0, true},  // nothing known
	}
	for _, tc := range cases {
		got := PartitionState{LiveDistinct: tc.live, KnownDistinct: tc.known}.IsMajority()
		if got != tc.want {
			t.Errorf("live=%d known=%d: IsMajority=%v want %v", tc.live, tc.known, got, tc.want)
		}
	}
}

// baseInput is a fully-enforceable input the individual tests then perturb.
func baseInput(now time.Time) EvalInput {
	return EvalInput{
		Indicator:     "203.0.113.7",
		IndicatorType: "ip",
		Scope:         "fleet",
		Contributions: []Contribution{
			mkContrib("a", "fpA", "standard", 0.9, time.Minute, now),
			mkContrib("b", "fpB", "standard", 0.9, time.Minute, now),
			mkContrib("c", "fpC", "standard", 0.9, time.Minute, now),
		},
		NodeMode:  ModeEnforce,
		Partition: PartitionState{LiveDistinct: 3, KnownDistinct: 3},
		RecordTTL: 30 * time.Minute,
		Now:       now,
	}
}

func TestEvaluateEnforced(t *testing.T) {
	now := time.Now()
	d := Evaluate(samplePolicy(), baseInput(now))
	if d.Outcome != OutcomeEnforced {
		t.Fatalf("expected enforced, got %s (%s)", d.Outcome, d.Reason)
	}
	if d.Mode != ModeEnforce {
		t.Fatalf("mode = %s", d.Mode)
	}
	// TTL 30m under max_ttl 1h → kernel timeout 30m.
	if d.KernelTimeout != 30*time.Minute {
		t.Fatalf("kernel timeout = %v", d.KernelTimeout)
	}
	if d.ExpiresAt.IsZero() {
		t.Fatal("expires_at not set")
	}
}

func TestEvaluateObserveMode(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.NodeMode = ModeObserve
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeObserveOnly {
		t.Fatalf("observe mode should be observe_only, got %s", d.Outcome)
	}
	// Decision still fully computed for explainability.
	if d.MatchedWeight != 3.0 || len(d.Identities) != 3 {
		t.Fatalf("observe decision should still carry quorum detail, got %+v", d)
	}
}

func TestEvaluateNoRecord(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.Contributions = nil
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeNoRecord {
		t.Fatalf("expected no_record, got %s", d.Outcome)
	}
}

func TestEvaluateProtectedDenied(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.Indicator = "10.1.2.3" // inside protected 10.0.0.0/8
	ps, err := NewProtectedSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Protected = ps
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeDeniedByPolicy {
		t.Fatalf("protected target should be denied, got %s (%s)", d.Outcome, d.Reason)
	}
	if len(d.ProtectedReasons) == 0 {
		t.Fatal("expected a protected reason")
	}
}

func TestEvaluateProtectedBeatsQuorum(t *testing.T) {
	// Even with unanimous, fresh, high-trust quorum, a protected target is denied.
	now := time.Now()
	in := baseInput(now)
	in.Indicator = "127.0.0.1"
	ps, _ := NewProtectedSet(nil)
	in.Protected = ps
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeDeniedByPolicy {
		t.Fatalf("loopback must never be blockable, got %s", d.Outcome)
	}
}

func TestEvaluateMinorityPartitionWithholdsFleet(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.Partition = PartitionState{LiveDistinct: 2, KnownDistinct: 5} // minority
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeObserveOnly {
		t.Fatalf("minority partition should withhold fleet enforcement, got %s (%s)", d.Outcome, d.Reason)
	}
}

func TestEvaluateMinorityPartitionAllowsLocalScope(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.Scope = "local"
	in.Partition = PartitionState{LiveDistinct: 1, KnownDistinct: 5} // minority, but local scope
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeEnforced {
		t.Fatalf("local-scope enforcement should proceed under partition, got %s (%s)", d.Outcome, d.Reason)
	}
}

func TestEvaluateQuorumNotMetObserves(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.Contributions = in.Contributions[:1] // weight 1.0 < 3.0
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeObserveOnly {
		t.Fatalf("insufficient quorum should be observe_only, got %s", d.Outcome)
	}
}

func TestEvaluateKernelTimeoutRequiredNoTTLDenied(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.RecordTTL = 0
	p := samplePolicy()
	p.MaxTTL = "" // no policy cap either → no timeout available
	d := Evaluate(p, in)
	if d.Outcome != OutcomeDeniedByPolicy {
		t.Fatalf("kernel_timeout_required with no TTL should deny, got %s (%s)", d.Outcome, d.Reason)
	}
}

func TestEvaluateTTLCappedByMaxTTL(t *testing.T) {
	now := time.Now()
	in := baseInput(now)
	in.RecordTTL = 6 * time.Hour // exceeds max_ttl 1h
	d := Evaluate(samplePolicy(), in)
	if d.Outcome != OutcomeEnforced {
		t.Fatalf("expected enforced, got %s", d.Outcome)
	}
	if d.KernelTimeout != time.Hour {
		t.Fatalf("TTL should be capped to max_ttl 1h, got %v", d.KernelTimeout)
	}
}
