package admission

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestTokenBucketRefill(t *testing.T) {
	clk := newFakeClock()
	b := newTokenBucket(10, 2, clk.Now) // 10/sec, burst 2

	if !b.take() || !b.take() {
		t.Fatal("burst of 2 should be immediately available")
	}
	if b.take() {
		t.Fatal("third take should fail before refill")
	}
	clk.Advance(100 * time.Millisecond) // 10/sec * 0.1s = 1 token
	if !b.take() {
		t.Fatal("one token should have refilled after 100ms")
	}
}

func TestBudgetPerDetectorAndNode(t *testing.T) {
	clk := newFakeClock()
	b := NewBudget(BudgetConfig{
		PerDetectorRate: 0, PerDetectorBurst: 5,
		PerNodeRate: 0, PerNodeBurst: 3,
	}, clk.Now)

	// Node burst (3) is the binding constraint across detectors.
	admitted := 0
	for i := 0; i < 5; i++ {
		if b.Allow("det-a") {
			admitted++
		}
	}
	if admitted != 3 {
		t.Fatalf("node burst should cap admissions at 3, got %d", admitted)
	}
}

func TestBudgetDetectorIsolation(t *testing.T) {
	clk := newFakeClock()
	b := NewBudget(BudgetConfig{
		PerDetectorRate: 0, PerDetectorBurst: 1,
		PerNodeRate: 0, PerNodeBurst: 10,
	}, clk.Now)

	if !b.Allow("noisy") {
		t.Fatal("first from noisy detector should pass")
	}
	if b.Allow("noisy") {
		t.Fatal("noisy detector burst (1) should be exhausted")
	}
	if !b.Allow("quiet") {
		t.Fatal("a different detector must still have its own budget")
	}
}

func TestBudgetRefundsDetectorWhenNodeExhausted(t *testing.T) {
	clk := newFakeClock()
	b := NewBudget(BudgetConfig{
		PerDetectorRate: 0, PerDetectorBurst: 5,
		PerNodeRate: 0, PerNodeBurst: 1,
	}, clk.Now)

	if !b.Allow("det") {
		t.Fatal("first admission should pass")
	}
	// Node bucket now empty; detector should be refunded so it keeps 4 tokens.
	if b.Allow("det") {
		t.Fatal("node budget exhausted, admission must fail")
	}
	if r := b.detectorBucket("det").fillRatio(); r < 0.79 {
		t.Fatalf("detector token should have been refunded, fill ratio = %.2f", r)
	}
}

func TestCoalescer(t *testing.T) {
	clk := newFakeClock()
	c := NewCoalescer(5*time.Second, clk.Now)

	if count, newGroup := c.Observe("k"); !newGroup || count != 1 {
		t.Fatalf("first observe = (%d, %v), want (1, true)", count, newGroup)
	}
	if count, newGroup := c.Observe("k"); newGroup || count != 2 {
		t.Fatalf("second observe = (%d, %v), want (2, false)", count, newGroup)
	}
	if count, _ := c.Observe("k"); count != 3 {
		t.Fatalf("third observe count = %d, want 3", count)
	}

	// After the window elapses a fresh group starts.
	clk.Advance(5 * time.Second)
	if count, newGroup := c.Observe("k"); !newGroup || count != 1 {
		t.Fatalf("post-window observe = (%d, %v), want (1, true)", count, newGroup)
	}
}

func TestCoalescerExpire(t *testing.T) {
	clk := newFakeClock()
	c := NewCoalescer(time.Second, clk.Now)
	c.Observe("k1")
	c.Observe("k2")
	if removed := c.Expire(); removed != 0 {
		t.Fatalf("nothing should expire yet, removed %d", removed)
	}
	clk.Advance(time.Second)
	if removed := c.Expire(); removed != 2 {
		t.Fatalf("both groups should expire, removed %d", removed)
	}
}

func TestShedder(t *testing.T) {
	s := NewShedder(0.5)

	if !s.Keep("low", 0.1, false) {
		t.Error("outside storm, everything is kept")
	}
	if s.Keep("low", 0.1, true) {
		t.Error("under storm, low-severity low-confidence must be shed")
	}
	if !s.Keep("low", 0.9, true) {
		t.Error("under storm, high-confidence low-severity should survive")
	}
	if !s.Keep("critical", 0.0, true) {
		t.Error("critical is never shed, even at zero confidence")
	}
}

func TestControllerDecisionOrder(t *testing.T) {
	clk := newFakeClock()
	ctrl := New(Config{
		Budget:            BudgetConfig{PerDetectorBurst: 100, PerNodeBurst: 100},
		CoalesceWindow:    5 * time.Second,
		ShedMinConfidence: 0.5,
	}, clk.Now)

	// First sighting of a key is admitted.
	if d, count := ctrl.Admit(Signal{Detector: "ssh", Key: "ssh|1.2.3.4", Severity: "high", Confidence: 0.9}); d != Admit || count != 1 {
		t.Fatalf("first signal = (%s, %d), want (admit, 1)", d, count)
	}
	// A duplicate within the window coalesces and does not spend budget.
	if d, count := ctrl.Admit(Signal{Detector: "ssh", Key: "ssh|1.2.3.4", Severity: "high", Confidence: 0.9}); d != Coalesced || count != 2 {
		t.Fatalf("duplicate = (%s, %d), want (coalesced, 2)", d, count)
	}
}

func TestControllerShedsUnderStorm(t *testing.T) {
	clk := newFakeClock()
	// Tiny node budget so it depletes immediately and we enter "storm".
	ctrl := New(Config{
		Budget:            BudgetConfig{PerDetectorRate: 0, PerDetectorBurst: 100, PerNodeRate: 0, PerNodeBurst: 2},
		CoalesceWindow:    time.Second,
		ShedMinConfidence: 0.5,
	}, clk.Now)

	// Drain the node budget with two distinct high-severity signals.
	ctrl.Admit(Signal{Detector: "d", Key: "k1", Severity: "high", Confidence: 0.9})
	ctrl.Admit(Signal{Detector: "d", Key: "k2", Severity: "high", Confidence: 0.9})

	// Now under storm: a low/low-confidence signal is shed before budget.
	if d, _ := ctrl.Admit(Signal{Detector: "d", Key: "k3", Severity: "low", Confidence: 0.1}); d != DroppedShed {
		t.Fatalf("low-priority signal under storm = %s, want dropped_shed", d)
	}
	// A critical signal is never shed; with no budget left it fails on budget.
	if d, _ := ctrl.Admit(Signal{Detector: "d", Key: "k4", Severity: "critical", Confidence: 0.9}); d != DroppedBudget {
		t.Fatalf("critical signal with no budget = %s, want dropped_budget", d)
	}
}
