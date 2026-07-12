package coordinator

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// ── fakes ───────────────────────────────────────────────────────────────────

type fakeState struct {
	ops  []*frienv1.OperationEnvelope
	recv map[string]time.Time
}

func (f *fakeState) PresentThreatOps(time.Time) []*frienv1.OperationEnvelope { return f.ops }
func (f *fakeState) ReceivedAt(opID string) time.Time                        { return f.recv[opID] }

type fakeTrust struct {
	tiers   map[string]string
	revoked map[string]bool
}

func (f *fakeTrust) TrustTier(node, _ string) string {
	if t, ok := f.tiers[node]; ok {
		return t
	}
	return "standard"
}
func (f *fakeTrust) Excluded(node, _ string) bool { return f.revoked[node] }

type fakePartition struct{ ps policy.PartitionState }

func (f fakePartition) Partition() policy.PartitionState { return f.ps }

type fakePublisher struct{ published []*frienv1.OperationEnvelope }

func (f *fakePublisher) Publish(opType string, payload proto.Message, scope string) (*frienv1.OperationEnvelope, error) {
	body, _ := proto.Marshal(payload)
	env := &frienv1.OperationEnvelope{OpType: opType, Payload: body}
	f.published = append(f.published, env)
	return env, nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

func threatOp(opID, node, indicator, scope string, conf float64, ttl string) *frienv1.OperationEnvelope {
	tr := &frienv1.ThreatRecord{
		IndicatorType: "ip",
		Id:            "threat-" + opID,
		Indicator:     indicator,
		Confidence:    conf,
		Ttl:           ttl,
		Scope:         scope,
	}
	body, _ := proto.Marshal(tr)
	return &frienv1.OperationEnvelope{
		OpId:    opID,
		OpType:  crdt.OpThreatRecord,
		NodeId:  node,
		KeyId:   "ed25519:" + node,
		Payload: body,
	}
}

func testDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "c.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// harness builds a coordinator over a real in-process enforcement client
// (MemAdapter) plus the fakes, and returns the pieces tests assert on.
func harness(t *testing.T, mode string, ops []*frienv1.OperationEnvelope, part policy.PartitionState, revoked map[string]bool) (*Coordinator, *fakePublisher, enforcer.Client) {
	t.Helper()
	db := testDB(t)
	rb, _ := enforcer.NewRollbackStore(db)
	e := enforcer.New(rb, nil, zerolog.Nop())
	e.Register(enforcer.NewMemAdapter("nftables", nil), mode)
	client := enforcer.NewInProcClient(e, nil)

	auditLog, _ := audit.NewLog(db, nil)
	now := time.Now()
	recv := make(map[string]time.Time)
	for _, o := range ops {
		recv[o.GetOpId()] = now.Add(-time.Minute)
	}
	pub := &fakePublisher{}
	c := New(Deps{
		NodeID:    "self",
		Client:    client,
		Audit:     auditLog,
		State:     &fakeState{ops: ops, recv: recv},
		Publisher: pub,
		Trust:     &fakeTrust{tiers: map[string]string{}, revoked: revoked},
		Partition: fakePartition{ps: part},
		Log:       zerolog.Nop(),
	})

	p := &policy.Policy{
		ID: "edge_block_v1", Version: 7, Action: "block", MinConfidence: 0.85,
		RequireWeight: 3.0, QuorumWindow: "5m", MaxTTL: "1h", KernelTimeoutRequired: true,
	}
	protected, _ := policy.NewProtectedSet(nil)
	c.SetPolicy(p, protected)
	return c, pub, client
}

// three distinct standard reporters for one indicator → weight 3.0.
func threeReports(indicator, scope string) []*frienv1.OperationEnvelope {
	return []*frienv1.OperationEnvelope{
		threatOp("op-a", "node-a", indicator, scope, 0.9, "30m"),
		threatOp("op-b", "node-b", indicator, scope, 0.9, "30m"),
		threatOp("op-c", "node-c", indicator, scope, 0.9, "30m"),
	}
}

// ── tests ───────────────────────────────────────────────────────────────────

// Exit criterion: observe mode logs/explains without applying rules.
func TestObserveModeExplainsWithoutApplying(t *testing.T) {
	c, pub, client := harness(t, enforcer.ModeObserve, threeReports("203.0.113.7", "fleet"),
		policy.PartitionState{LiveDistinct: 3, KnownDistinct: 3}, nil)

	ex, err := c.Explain("203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Decision != policy.OutcomeObserveOnly {
		t.Fatalf("observe: expected observe_only, got %s (%s)", ex.Decision, ex.Reason)
	}
	// Enforce path is a no-op in observe mode: no rule, no publish.
	d, token, _ := c.EvaluateAndEnforce("203.0.113.7")
	if d.Outcome != policy.OutcomeObserveOnly || token != "" {
		t.Fatalf("observe enforce should not apply: %s token=%q", d.Outcome, token)
	}
	if rules, _ := client.List(); len(rules) != 0 {
		t.Fatalf("no rule should exist in observe mode, got %+v", rules)
	}
	if len(pub.published) != 0 {
		t.Fatal("no decision should be published in observe mode")
	}
}

// Exit criterion: enforce mode creates a self-expiring entry (through the real client).
func TestEnforceModeAppliesAndPublishes(t *testing.T) {
	c, pub, client := harness(t, enforcer.ModeEnforce, threeReports("203.0.113.7", "fleet"),
		policy.PartitionState{LiveDistinct: 3, KnownDistinct: 3}, nil)

	d, token, err := c.EvaluateAndEnforce("203.0.113.7")
	if err != nil || d.Outcome != policy.OutcomeEnforced || token == "" {
		t.Fatalf("enforce: outcome=%s token=%q err=%v", d.Outcome, token, err)
	}
	rules, _ := client.List()
	if len(rules) != 1 || rules[0].Target != "203.0.113.7" {
		t.Fatalf("expected one applied rule, got %+v", rules)
	}
	if rules[0].ExpiresAt.IsZero() {
		t.Fatal("applied rule must carry a kernel expiry")
	}
	if len(pub.published) != 1 || pub.published[0].GetOpType() != crdt.OpEnforcementDecision {
		t.Fatalf("expected a published enforcement decision, got %+v", pub.published)
	}

	// Idempotent: a second sweep does not double-apply.
	c.Sweep()
	if rules, _ := client.List(); len(rules) != 1 {
		t.Fatalf("sweep should not double-apply, got %d rules", len(rules))
	}
}

// Exit criterion: protected target is denied by policy with explanation.
func TestProtectedTargetDenied(t *testing.T) {
	c, _, client := harness(t, enforcer.ModeEnforce, threeReports("10.1.2.3", "fleet"),
		policy.PartitionState{LiveDistinct: 3, KnownDistinct: 3}, nil)

	ex, _ := c.Explain("10.1.2.3")
	if ex.Decision != policy.OutcomeDeniedByPolicy {
		t.Fatalf("protected target should be denied, got %s (%s)", ex.Decision, ex.Reason)
	}
	d, token, _ := c.EvaluateAndEnforce("10.1.2.3")
	if d.Outcome != policy.OutcomeDeniedByPolicy || token != "" {
		t.Fatalf("protected enforce should be denied, got %s token=%q", d.Outcome, token)
	}
	if rules, _ := client.List(); len(rules) != 0 {
		t.Fatal("protected target must never be applied")
	}
}

// Exit criterion: minority partition refuses fleet-scoped enforcement.
func TestMinorityPartitionRefusesFleet(t *testing.T) {
	c, _, client := harness(t, enforcer.ModeEnforce, threeReports("203.0.113.7", "fleet"),
		policy.PartitionState{LiveDistinct: 2, KnownDistinct: 5}, nil) // minority

	d, token, _ := c.EvaluateAndEnforce("203.0.113.7")
	if d.Outcome != policy.OutcomeObserveOnly || token != "" {
		t.Fatalf("minority partition should withhold fleet enforcement, got %s token=%q (%s)", d.Outcome, token, d.Reason)
	}
	if rules, _ := client.List(); len(rules) != 0 {
		t.Fatal("no rule should be applied from a minority partition")
	}
}

// A local-scope decision on directly-observed evidence still enforces under partition.
func TestLocalScopeEnforcesUnderPartition(t *testing.T) {
	c, _, client := harness(t, enforcer.ModeEnforce, threeReports("203.0.113.8", "local"),
		policy.PartitionState{LiveDistinct: 1, KnownDistinct: 9}, nil)

	d, token, _ := c.EvaluateAndEnforce("203.0.113.8")
	if d.Outcome != policy.OutcomeEnforced || token == "" {
		t.Fatalf("local scope should enforce under partition, got %s (%s)", d.Outcome, d.Reason)
	}
	if rules, _ := client.List(); len(rules) != 1 {
		t.Fatal("local-scope rule should be applied")
	}
}

// A revoked reporter's weight does not count toward quorum.
func TestRevokedReporterExcluded(t *testing.T) {
	ops := threeReports("203.0.113.7", "fleet")
	c, _, client := harness(t, enforcer.ModeEnforce, ops,
		policy.PartitionState{LiveDistinct: 3, KnownDistinct: 3},
		map[string]bool{"node-c": true}) // one of three revoked → weight 2.0 < 3.0

	d, token, _ := c.EvaluateAndEnforce("203.0.113.7")
	if d.Outcome != policy.OutcomeObserveOnly || token != "" {
		t.Fatalf("revoked reporter should drop quorum below threshold, got %s (%s)", d.Outcome, d.Reason)
	}
	if rules, _ := client.List(); len(rules) != 0 {
		t.Fatal("no rule should be applied when quorum is not met")
	}
}

func TestNoActivePolicyDoesNotEnforce(t *testing.T) {
	db := testDB(t)
	rb, _ := enforcer.NewRollbackStore(db)
	e := enforcer.New(rb, nil, zerolog.Nop())
	e.Register(enforcer.NewMemAdapter("nftables", nil), enforcer.ModeEnforce)
	auditLog, _ := audit.NewLog(db, nil)
	c := New(Deps{
		NodeID: "self", Client: enforcer.NewInProcClient(e, nil), Audit: auditLog,
		State:     &fakeState{ops: threeReports("203.0.113.7", "fleet"), recv: map[string]time.Time{}},
		Publisher: &fakePublisher{}, Trust: &fakeTrust{}, Partition: fakePartition{}, Log: zerolog.Nop(),
	})
	// No SetPolicy called.
	d, token, _ := c.EvaluateAndEnforce("203.0.113.7")
	if d.Outcome != policy.OutcomeNoRecord || token != "" {
		t.Fatalf("no policy should mean no enforcement, got %s", d.Outcome)
	}
}
