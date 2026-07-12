package reporter

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/admission"
	"github.com/prateekpurohit13/frien/internal/crdt"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type fakePub struct {
	published []*frienv1.ThreatRecord
}

func (f *fakePub) Publish(opType string, payload proto.Message, _ string) (*frienv1.OperationEnvelope, error) {
	if opType == crdt.OpThreatRecord {
		if tr, ok := payload.(*frienv1.ThreatRecord); ok {
			f.published = append(f.published, tr)
		}
	}
	return &frienv1.OperationEnvelope{OpId: "op-" + string(rune('a'+len(f.published)))}, nil
}

func ctrl() *admission.Controller {
	return admission.New(admission.Config{
		Budget:            admission.BudgetConfig{PerDetectorRate: 100, PerDetectorBurst: 100, PerNodeRate: 100, PerNodeBurst: 100},
		CoalesceWindow:    time.Minute,
		ShedMinConfidence: 0.3,
	}, nil)
}

func goodParams() Params {
	return Params{
		Indicator: "203.0.113.7", IndicatorType: "ip", Reason: "ssh brute force",
		Severity: "high", Confidence: 0.9, TTL: "1h", Scope: "fleet", Detector: "ssh_bruteforce",
	}
}

func TestReportAcceptedPublishes(t *testing.T) {
	pub := &fakePub{}
	r := New(ctrl(), pub, "self", nil)
	res, err := r.Report(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusAccepted || res.OpID == "" || res.ThreatID == "" {
		t.Fatalf("expected accepted with ids, got %+v", res)
	}
	if len(pub.published) != 1 {
		t.Fatalf("expected 1 published threat, got %d", len(pub.published))
	}
	tr := pub.published[0]
	if tr.GetReportedBy() != "self" || tr.GetExpiresAt() == "" || tr.GetCoalescedCount() != 1 {
		t.Fatalf("threat record not stamped correctly: %+v", tr)
	}
}

func TestReportCoalesces(t *testing.T) {
	pub := &fakePub{}
	r := New(ctrl(), pub, "self", nil)
	if _, err := r.Report(goodParams()); err != nil {
		t.Fatal(err)
	}
	// Same key again → coalesced, no second publish.
	res, err := r.Report(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusCoalesced {
		t.Fatalf("expected coalesced, got %s", res.Status)
	}
	if len(pub.published) != 1 {
		t.Fatalf("coalesced report must not publish again, got %d", len(pub.published))
	}
}

func TestReportBudgetShed(t *testing.T) {
	pub := &fakePub{}
	// Tiny budget: 1 token, no refill within the test.
	c := admission.New(admission.Config{
		Budget:            admission.BudgetConfig{PerDetectorRate: 0, PerDetectorBurst: 1, PerNodeRate: 0, PerNodeBurst: 1},
		CoalesceWindow:    time.Minute,
		ShedMinConfidence: 0.3,
	}, nil)
	r := New(c, pub, "self", nil)

	// First distinct indicator consumes the single token.
	p1 := goodParams()
	if res, _ := r.Report(p1); res.Status != StatusAccepted {
		t.Fatalf("first report should be accepted, got %s", res.Status)
	}
	// Second distinct indicator has no budget → shed.
	p2 := goodParams()
	p2.Indicator = "203.0.113.8"
	res, _ := r.Report(p2)
	if res.Status != StatusShed {
		t.Fatalf("second report should be shed by budget, got %s", res.Status)
	}
	if len(pub.published) != 1 {
		t.Fatalf("shed report must not publish, got %d", len(pub.published))
	}
}

func TestReportValidation(t *testing.T) {
	r := New(ctrl(), &fakePub{}, "self", nil)
	bad := []func(*Params){
		func(p *Params) { p.Indicator = "" },
		func(p *Params) { p.IndicatorType = "bogus" },
		func(p *Params) { p.Severity = "extreme" },
		func(p *Params) { p.Confidence = 2 },
		func(p *Params) { p.Indicator = "not-an-ip" }, // type ip
		func(p *Params) { p.Scope = "galaxy" },
		func(p *Params) { p.TTL = "5" },
	}
	for i, mut := range bad {
		p := goodParams()
		mut(&p)
		if _, err := r.Report(p); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

// Works with a nil controller (admission disabled) — always admits.
func TestReportNilController(t *testing.T) {
	pub := &fakePub{}
	r := New(nil, pub, "self", nil)
	if res, err := r.Report(goodParams()); err != nil || res.Status != StatusAccepted {
		t.Fatalf("nil controller should admit: %+v err=%v", res, err)
	}
}
