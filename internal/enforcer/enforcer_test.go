package enforcer

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func testDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "test.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeClock is a manually-advanced clock for deterministic expiry tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func blockDecision(id, target, timeout string) *frienv1.EnforcementDecision {
	return &frienv1.EnforcementDecision{
		Id:            id,
		Adapter:       "nftables",
		Action:        "block",
		Target:        target,
		Mode:          "enforce",
		KernelTimeout: timeout,
		RollbackToken: "tok-" + id,
	}
}

func TestApplyInEnforceModeInstallsRule(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, clk.now, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)

	applied, err := e.Apply(blockDecision("d1", "203.0.113.5", "30m"))
	if err != nil || !applied {
		t.Fatalf("Apply: applied=%v err=%v", applied, err)
	}
	rules, _ := e.adapters["nftables"].List()
	if len(rules) != 1 || rules[0].Target != "203.0.113.5" {
		t.Fatalf("expected one rule, got %+v", rules)
	}
	// Rollback token persisted.
	rec, ok, _ := rb.Get("tok-d1")
	if !ok || !rec.Applied || rec.RolledBack {
		t.Fatalf("token not persisted correctly: %+v ok=%v", rec, ok)
	}
}

func TestApplyInObserveModeIsNoop(t *testing.T) {
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, nil, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", nil), ModeObserve)

	applied, err := e.Apply(blockDecision("d1", "203.0.113.5", "30m"))
	if err != nil || applied {
		t.Fatalf("observe mode should not apply: applied=%v err=%v", applied, err)
	}
	rules, _ := e.adapters["nftables"].List()
	if len(rules) != 0 {
		t.Fatalf("no rule should exist in observe mode, got %+v", rules)
	}
}

// TestRuleSelfExpires proves the "enforce mode creates a self-expiring entry"
// criterion: after the kernel timeout elapses the rule is gone with no explicit
// removal.
func TestRuleSelfExpires(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	e := New(nil, clk.now, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)

	if _, err := e.Apply(blockDecision("d1", "203.0.113.5", "30m")); err != nil {
		t.Fatal(err)
	}
	if rules, _ := e.adapters["nftables"].List(); len(rules) != 1 {
		t.Fatalf("rule should be active before expiry, got %+v", rules)
	}
	clk.advance(31 * time.Minute)
	if rules, _ := e.adapters["nftables"].List(); len(rules) != 0 {
		t.Fatalf("rule should self-expire after timeout, got %+v", rules)
	}
}

func TestApplyRefusesNoTimeout(t *testing.T) {
	e := New(nil, nil, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", nil), ModeEnforce)
	d := blockDecision("d1", "203.0.113.5", "") // no kernel timeout, no expires_at
	if applied, err := e.Apply(d); err == nil || applied {
		t.Fatalf("expected refusal for no-timeout rule, applied=%v err=%v", applied, err)
	}
}

func TestRollback(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, clk.now, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)
	_, _ = e.Apply(blockDecision("d1", "203.0.113.5", "30m"))

	status, err := e.Rollback("tok-d1")
	if err != nil || status != RollbackRemoved {
		t.Fatalf("rollback: status=%s err=%v", status, err)
	}
	if rules, _ := e.adapters["nftables"].List(); len(rules) != 0 {
		t.Fatalf("rule should be gone after rollback, got %+v", rules)
	}

	// Rolling back an unknown token reports not_found.
	if status, _ := e.Rollback("nope"); status != RollbackNotFound {
		t.Fatalf("expected not_found, got %s", status)
	}
}

func TestRollbackAfterExpiryReportsExpired(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, clk.now, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)
	_, _ = e.Apply(blockDecision("d1", "203.0.113.5", "30m"))
	clk.advance(31 * time.Minute) // kernel expired it

	status, err := e.Rollback("tok-d1")
	if err != nil || status != RollbackExpired {
		t.Fatalf("expected already_expired, got status=%s err=%v", status, err)
	}
}

func TestFlushAllAndForceObserve(t *testing.T) {
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, nil, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", nil), ModeEnforce)
	_, _ = e.Apply(blockDecision("d1", "203.0.113.5", "30m"))
	_, _ = e.Apply(blockDecision("d2", "203.0.113.6", "30m"))

	n := e.FlushAll("breakglass test")
	if n != 2 {
		t.Fatalf("expected 2 rules flushed, got %d", n)
	}
	e.ForceObserve()
	if e.Mode("nftables") != ModeObserve {
		t.Fatal("ForceObserve should set observe mode")
	}
}

// TestReconcileAfterCrash proves "a daemon crash leaves no leaked rule past the
// kernel timeout": a token persisted before the crash, whose kernel rule has
// since expired, is closed out on restart and never re-applied.
func TestReconcileAfterCrash(t *testing.T) {
	db := testDB(t)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}

	// First "process": apply a rule, then crash (drop the enforcer, keep the DB
	// and simulate the kernel reaping the rule while we were down).
	rb1, _ := NewRollbackStore(db)
	e1 := New(rb1, clk.now, zerolog.Nop())
	e1.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)
	_, _ = e1.Apply(blockDecision("d1", "203.0.113.5", "30m"))

	clk.advance(31 * time.Minute) // kernel timeout fires while daemon is down

	// Second "process": fresh enforcer + fresh (empty) adapter, same DB. The
	// token is outstanding in the store but the kernel has no matching rule.
	rb2, _ := NewRollbackStore(db)
	e2 := New(rb2, clk.now, zerolog.Nop())
	e2.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)

	closed, err := e2.Reconcile()
	if err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Fatalf("expected 1 token reconciled/closed, got %d", closed)
	}
	// The token is now closed and no rule was re-applied.
	rec, _, _ := rb2.Get("tok-d1")
	if !rec.RolledBack {
		t.Fatal("expired token should be marked rolled back after reconcile")
	}
	if rules, _ := e2.adapters["nftables"].List(); len(rules) != 0 {
		t.Fatalf("reconcile must not resurrect an expired rule, got %+v", rules)
	}
}

func TestDeadmanFires(t *testing.T) {
	var mu sync.Mutex
	fired := 0
	dm := NewDeadman(20*time.Millisecond, func() {
		mu.Lock()
		fired++
		mu.Unlock()
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go dm.Run(ctx)

	// No heartbeat: it should fire within a couple of windows.
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := fired
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("dead-man's switch never fired")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if dm.TriggeredCount() < 1 {
		t.Fatal("TriggeredCount should be >= 1")
	}
}

func TestDeadmanHeartbeatPreventsFire(t *testing.T) {
	var mu sync.Mutex
	fired := 0
	dm := NewDeadman(50*time.Millisecond, func() {
		mu.Lock()
		fired++
		mu.Unlock()
	}, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	go dm.Run(ctx)

	// Beat steadily for a while; the switch must not fire.
	for i := 0; i < 10; i++ {
		dm.Beat()
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	mu.Lock()
	n := fired
	mu.Unlock()
	if n != 0 {
		t.Fatalf("switch fired despite heartbeats: %d", n)
	}
}
