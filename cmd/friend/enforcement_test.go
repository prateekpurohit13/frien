package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/coordinator"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// minimal coordinator fakes (the daemon backs these with the live mesh).
type noState struct{}

func (noState) PresentThreatOps(time.Time) []*frienv1.OperationEnvelope { return nil }
func (noState) ReceivedAt(string) time.Time                             { return time.Time{} }

type noPublisher struct{}

func (noPublisher) Publish(string, proto.Message, string) (*frienv1.OperationEnvelope, error) {
	return &frienv1.OperationEnvelope{}, nil
}

type openTrust struct{}

func (openTrust) TrustTier(string, string) string { return "standard" }
func (openTrust) Excluded(string, string) bool    { return false }

type healthyPartition struct{}

func (healthyPartition) Partition() policy.PartitionState {
	return policy.PartitionState{LiveDistinct: 1, KnownDistinct: 1}
}

func buildService(t *testing.T) *enforcementService {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "svc.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rb, _ := enforcer.NewRollbackStore(db)
	e := enforcer.New(rb, nil, zerolog.Nop())
	e.Register(enforcer.NewMemAdapter("nftables", nil), enforcer.ModeObserve)
	client := enforcer.NewInProcClient(e, nil)
	auditLog, _ := audit.NewLog(db, nil)

	coord := coordinator.New(coordinator.Deps{
		NodeID: "self", Client: client, Audit: auditLog,
		State: noState{}, Publisher: noPublisher{}, Trust: openTrust{}, Partition: healthyPartition{},
		Log: zerolog.Nop(),
	})
	// A low-threshold policy so a single sample contribution can meet quorum in
	// TestPolicy.
	p := &policy.Policy{
		ID: "test_v1", Version: 1, Action: "block", MinConfidence: 0.5,
		RequireWeight: 1.0, QuorumWindow: "5m", MaxTTL: "1h", KernelTimeoutRequired: true,
	}
	protected, _ := policy.FromPolicy(p)
	coord.SetPolicy(p, protected)

	return newEnforcementService(coord, client, auditLog, []string{"nftables"}, zerolog.Nop())
}

func TestServiceSetModeAudited(t *testing.T) {
	svc := buildService(t)
	prev, cur, auditID, err := svc.SetMode("nftables", "enforce", "rollout")
	if err != nil || prev != "observe" || cur != "enforce" || auditID == "" {
		t.Fatalf("SetMode: prev=%s cur=%s audit=%s err=%v", prev, cur, auditID, err)
	}
	// The audit entry exists and the chain verifies.
	if _, ok, _ := svc.auditLog.Get(auditID); !ok {
		t.Fatal("mode change not audited")
	}
	if err := svc.auditLog.Verify(); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestServiceBreakglassRateLimited(t *testing.T) {
	svc := buildService(t)
	if _, _, _, err := svc.Breakglass("first", "code1"); err != nil {
		t.Fatalf("first breakglass: %v", err)
	}
	if _, _, _, err := svc.Breakglass("second", "code2"); err != nil {
		t.Fatalf("second breakglass: %v", err)
	}
	if _, _, _, err := svc.Breakglass("third", "code3"); err == nil {
		t.Fatal("third breakglass within a minute should be rate-limited")
	}
	// Breakglass forces observe mode.
	if m, _ := svc.client.GetMode("nftables"); m != "observe" {
		t.Fatalf("breakglass should force observe, got %s", m)
	}
}

func TestServiceTestPolicyWouldEnforce(t *testing.T) {
	svc := buildService(t)
	tr := `{"indicatorType":"ip","indicator":"203.0.113.9","confidence":0.9,"ttl":"30m","scope":"fleet"}`
	resp, err := svc.TestPolicy("", tr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDecision() != policy.OutcomeWouldEnforce {
		t.Fatalf("expected would_enforce, got %s (%s)", resp.GetDecision(), resp.GetReason())
	}
}

func TestServiceTestPolicyProtectedDenied(t *testing.T) {
	svc := buildService(t)
	tr := `{"indicatorType":"ip","indicator":"127.0.0.1","confidence":0.9,"ttl":"30m","scope":"fleet"}`
	resp, err := svc.TestPolicy("", tr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDecision() != policy.OutcomeDeniedTestPolicy {
		t.Fatalf("expected denied for loopback, got %s", resp.GetDecision())
	}
	if len(resp.GetProtectedReasons()) == 0 {
		t.Fatal("expected a protected reason")
	}
}

func TestServiceExplainNoRecord(t *testing.T) {
	svc := buildService(t)
	resp, err := svc.Explain("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetDecision() != policy.OutcomeNoRecord {
		t.Fatalf("expected no_record with no threats present, got %s", resp.GetDecision())
	}
}
