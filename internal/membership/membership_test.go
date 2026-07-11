package membership

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
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

// world is a shared liveness map; a probe succeeds only if the node is up.
type world struct {
	mu sync.Mutex
	up map[string]bool
}

func (w *world) set(id string, up bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.up[id] = up
}

func (w *world) alive(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.up[id]
}

type fakeProber struct{ w *world }

func (p fakeProber) Ping(_ context.Context, target Member) error {
	if p.w.alive(target.NodeID) {
		return nil
	}
	return context.DeadlineExceeded
}

func (p fakeProber) PingReq(_ context.Context, relay, target Member) error {
	if p.w.alive(relay.NodeID) && p.w.alive(target.NodeID) {
		return nil
	}
	return context.DeadlineExceeded
}

func TestApplyAddsUnknownMember(t *testing.T) {
	ml := NewMemberList("self", newFakeClock().Now)
	if !ml.Apply(Update{NodeID: "a", State: StateAlive}).Changed {
		t.Fatal("first sighting of a member must register a change")
	}
	if m, ok := ml.Get("a"); !ok || m.State != StateAlive {
		t.Fatalf("member a = %+v, ok=%v", m, ok)
	}
}

func TestApplyRecordsAndUpdatesZone(t *testing.T) {
	ml := NewMemberList("self", newFakeClock().Now)
	ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 1, Zone: "eu"})
	if m, ok := ml.Get("a"); !ok || m.Zone != "eu" {
		t.Fatalf("member a = %+v, want zone eu", m)
	}

	// A higher-incarnation alive claim updates the zone, mirroring how
	// Addresses is handled.
	ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 2, Zone: "us"})
	if m, _ := ml.Get("a"); m.Zone != "us" {
		t.Fatalf("zone should update to us on a higher-incarnation alive claim, got %q", m.Zone)
	}

	// An empty zone on a later claim (e.g. a bare self-refutation broadcast
	// that never learned the zone) must not erase what's already known.
	ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 3})
	if m, _ := ml.Get("a"); m.Zone != "us" {
		t.Fatalf("an empty zone on a later claim should not erase the known zone, got %q", m.Zone)
	}
}

func TestApplyIncarnationRules(t *testing.T) {
	ml := NewMemberList("self", newFakeClock().Now)
	ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 5})

	// Lower-incarnation alive is ignored.
	if ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 4}).Changed {
		t.Error("stale alive (lower incarnation) must not change state")
	}
	// Suspect at equal incarnation transitions alive -> suspect.
	if !ml.Apply(Update{NodeID: "a", State: StateSuspect, Incarnation: 5}).Changed {
		t.Error("suspect at equal incarnation should transition alive->suspect")
	}
	// Higher-incarnation alive refutes the suspicion.
	if !ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 6}).Changed {
		t.Error("higher-incarnation alive should refute suspicion")
	}
	if m, _ := ml.Get("a"); m.State != StateAlive || m.Incarnation != 6 {
		t.Fatalf("member a = %+v, want alive@6", m)
	}
}

func TestApplySelfRefutation(t *testing.T) {
	ml := NewMemberList("self", newFakeClock().Now)
	res := ml.Apply(Update{NodeID: "self", State: StateSuspect, Incarnation: 3})
	if !res.SelfRefute || res.Incarnation != 4 {
		t.Fatalf("self-accusation should refute with incarnation 4, got %+v", res)
	}
	if ml.LocalIncarnation() != 4 {
		t.Fatalf("local incarnation = %d, want 4", ml.LocalIncarnation())
	}
}

func TestApplyDetectsAddressConflict(t *testing.T) {
	ml := NewMemberList("self", newFakeClock().Now)

	// First sighting carries an address but is not a conflict.
	if res := ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 1, Addresses: []string{"10.0.0.1:9000"}}); res.AddrConflict {
		t.Fatal("first sighting must not be flagged as an address conflict")
	}
	// Same address at a higher incarnation is a normal re-announce.
	if res := ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 2, Addresses: []string{"10.0.0.1:9000"}}); res.AddrConflict {
		t.Fatal("unchanged address must not be flagged")
	}
	// A different address at a higher incarnation is accepted but flagged.
	res := ml.Apply(Update{NodeID: "a", State: StateAlive, Incarnation: 3, Addresses: []string{"10.0.0.9:9000"}})
	if !res.AddrConflict {
		t.Fatal("a moved address at higher incarnation must be flagged")
	}
	if len(res.PrevAddresses) != 1 || res.PrevAddresses[0] != "10.0.0.1:9000" {
		t.Fatalf("conflict should report the prior address, got %v", res.PrevAddresses)
	}
	if m, _ := ml.Get("a"); m.Addresses[0] != "10.0.0.9:9000" {
		t.Fatalf("higher incarnation should still win the address, got %v", m.Addresses)
	}
}

func TestSameAddrsIgnoresOrder(t *testing.T) {
	if !sameAddrs([]string{"a:1", "b:2"}, []string{"b:2", "a:1"}) {
		t.Fatal("reordered address sets should compare equal")
	}
	if sameAddrs([]string{"a:1"}, []string{"a:1", "b:2"}) {
		t.Fatal("different-length address sets must not compare equal")
	}
}

func TestExpireSuspects(t *testing.T) {
	clk := newFakeClock()
	ml := NewMemberList("self", clk.Now)
	ml.Apply(Update{NodeID: "a", State: StateAlive})
	ml.Apply(Update{NodeID: "a", State: StateSuspect})

	fixed := func(int) time.Duration { return time.Second }
	if got := ml.ExpireSuspects(fixed); len(got) != 0 {
		t.Fatalf("nothing should expire before the timeout, got %v", got)
	}
	clk.Advance(time.Second)
	if got := ml.ExpireSuspects(fixed); len(got) != 1 || got[0].State != StateDead {
		t.Fatalf("suspect should expire to dead, got %v", got)
	}
}

func TestProbeFailureMarksSuspect(t *testing.T) {
	clk := newFakeClock()
	w := &world{up: map[string]bool{"b": false}}
	s := New("a", fakeProber{w}, Config{
		ProbeInterval:     100 * time.Millisecond,
		ProbeTimeout:      10 * time.Millisecond,
		SuspectMultiplier: 4,
		IndirectProbes:    2,
	}, zerolog.Nop(), WithClock(clk.Now), WithRand(rand.New(rand.NewSource(1))))

	s.Seed("b", []string{"127.0.0.1:1"})
	s.ProbeOnce(context.Background())

	if m, _ := s.List().Get("b"); m.State != StateSuspect {
		t.Fatalf("unreachable peer should be suspect, got %s", m.State)
	}

	clk.Advance(500 * time.Millisecond)
	s.Tick()
	if m, _ := s.List().Get("b"); m.State != StateDead {
		t.Fatalf("suspect should expire to dead, got %s", m.State)
	}
}

// barrierProber fails every direct probe and holds each indirect probe at a
// barrier, so ProbeOnce only completes if all relays are in flight at once.
type barrierProber struct {
	arrived chan struct{}
	release chan struct{}
	ok      bool
}

func (p barrierProber) Ping(_ context.Context, _ Member) error {
	return context.DeadlineExceeded
}

func (p barrierProber) PingReq(ctx context.Context, _, _ Member) error {
	p.arrived <- struct{}{}
	select {
	case <-p.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	if p.ok {
		return nil
	}
	return context.DeadlineExceeded
}

func TestIndirectProbeRunsRelaysConcurrently(t *testing.T) {
	const relays = 3
	p := barrierProber{arrived: make(chan struct{}, relays), release: make(chan struct{}), ok: true}
	s := New("self", p, Config{
		ProbeInterval:  100 * time.Millisecond,
		ProbeTimeout:   2 * time.Second,
		IndirectProbes: relays,
	}, zerolog.Nop(), WithRand(rand.New(rand.NewSource(1))))

	s.Seed("target", []string{"target:1"})
	for i := 0; i < relays; i++ {
		s.Seed(string(rune('a'+i)), []string{"r:1"})
	}

	done := make(chan struct{})
	go func() { s.ProbeOnce(context.Background()); close(done) }()

	for i := 0; i < relays; i++ {
		select {
		case <-p.arrived:
		case <-time.After(time.Second):
			t.Fatalf("only %d of %d relays in flight; probes are not concurrent", i, relays)
		}
	}
	close(p.release)
	<-done

	if m, _ := s.List().Get("target"); m.State != StateAlive {
		t.Fatalf("target reachable via a relay should stay alive, got %s", m.State)
	}
}

func TestAwarenessRisesOnSelfRefuteAndDecays(t *testing.T) {
	w := &world{up: map[string]bool{"peer": true}}
	s := New("self", fakeProber{w}, Config{
		ProbeInterval:  100 * time.Millisecond,
		ProbeTimeout:   10 * time.Millisecond,
		IndirectProbes: 1,
	}, zerolog.Nop(), WithRand(rand.New(rand.NewSource(1))))

	if s.Awareness() != 0 {
		t.Fatalf("fresh node should be healthy, got awareness %d", s.Awareness())
	}
	s.Apply(Update{NodeID: "self", State: StateSuspect, Incarnation: 1})
	if s.Awareness() != 1 {
		t.Fatalf("self-refutation should raise awareness, got %d", s.Awareness())
	}

	s.Seed("peer", []string{"peer:1"})
	s.ProbeOnce(context.Background())
	if s.Awareness() != 0 {
		t.Fatalf("a healthy direct probe should decay awareness, got %d", s.Awareness())
	}
}

func TestAwarenessExtendsSuspicionTimeout(t *testing.T) {
	clk := newFakeClock()
	s := New("self", fakeProber{&world{up: map[string]bool{}}}, Config{
		ProbeInterval:     100 * time.Millisecond,
		ProbeTimeout:      10 * time.Millisecond,
		SuspectMultiplier: 4, // base suspicion timeout = 400ms
		IndirectProbes:    1,
	}, zerolog.Nop(), WithClock(clk.Now), WithRand(rand.New(rand.NewSource(1))))

	for i := 1; i <= 3; i++ {
		s.Apply(Update{NodeID: "self", State: StateSuspect, Incarnation: uint64(i * 10)})
	}
	if s.Awareness() != 3 {
		t.Fatalf("awareness = %d, want 3", s.Awareness())
	}

	s.Apply(Update{NodeID: "b", State: StateAlive})
	s.Apply(Update{NodeID: "b", State: StateSuspect})

	// Scaled timeout is 400ms * (3+1) = 1600ms; a healthy node would have
	// declared b dead by 500ms, but a degraded one must still hold it suspect.
	clk.Advance(500 * time.Millisecond)
	s.Tick()
	if m, _ := s.List().Get("b"); m.State != StateSuspect {
		t.Fatalf("degraded node must hold suspect past the base timeout, got %s", m.State)
	}
	clk.Advance(1200 * time.Millisecond)
	s.Tick()
	if m, _ := s.List().Get("b"); m.State != StateDead {
		t.Fatalf("suspect should expire once the scaled timeout passes, got %s", m.State)
	}
}

func TestBroadcastQueueCapsAtDepth(t *testing.T) {
	s := New("self", nil, Config{QueueDepth: 3}, zerolog.Nop())
	for i := 0; i < 10; i++ {
		s.enqueue(Update{NodeID: fmt.Sprintf("n%d", i), State: StateAlive})
	}
	s.queueMu.Lock()
	n := len(s.queue)
	s.queueMu.Unlock()
	if n != 3 {
		t.Fatalf("queue should be capped at depth 3, got %d", n)
	}
}

func TestBroadcastQueuePrunesMostTransmitted(t *testing.T) {
	s := New("self", nil, Config{QueueDepth: 2}, zerolog.Nop())
	s.enqueue(Update{NodeID: "old", State: StateAlive})
	s.Updates(10) // charges "old" a retransmit; it now leads on sends
	s.enqueue(Update{NodeID: "b", State: StateAlive})
	s.enqueue(Update{NodeID: "c", State: StateAlive}) // exceeds cap, prunes most-transmitted

	s.queueMu.Lock()
	_, hasOld := s.queue["old"]
	n := len(s.queue)
	s.queueMu.Unlock()
	if n != 2 {
		t.Fatalf("queue should stay at cap 2, got %d", n)
	}
	if hasOld {
		t.Fatal("the most-transmitted entry should have been pruned first")
	}
}

func TestUpdatesDrainLeastTransmittedFirst(t *testing.T) {
	s := New("self", nil, Config{}, zerolog.Nop())
	s.enqueue(Update{NodeID: "a", State: StateAlive})
	s.Updates(1) // a now has one send
	s.enqueue(Update{NodeID: "b", State: StateAlive})

	got := s.Updates(1)
	if len(got) != 1 || got[0].NodeID != "b" {
		t.Fatalf("least-transmitted update should drain first, got %v", got)
	}
}

func TestUpdatesRetireAtRetransmitLimit(t *testing.T) {
	s := New("self", nil, Config{}, zerolog.Nop())
	s.enqueue(Update{NodeID: "a", State: StateAlive})
	limit := s.retransmitLimit()
	for i := 0; i < limit; i++ {
		s.Updates(10)
	}
	s.queueMu.Lock()
	_, present := s.queue["a"]
	s.queueMu.Unlock()
	if present {
		t.Fatalf("update should retire after %d retransmits", limit)
	}
}

func TestSuspicionTimeoutInterpolatesWithConfirmers(t *testing.T) {
	cfg := Config{ProbeInterval: 100 * time.Millisecond, SuspectMultiplier: 10, ConfirmationTarget: 3}

	if got := cfg.suspicionTimeout(0); got != time.Second {
		t.Fatalf("no confirmer should wait the full max, got %v", got)
	}
	if got := cfg.suspicionTimeout(1); got != time.Second {
		t.Fatalf("one confirmer should wait the full max, got %v", got)
	}
	if got := cfg.suspicionTimeout(4); got != 100*time.Millisecond {
		t.Fatalf("reaching the target should collapse to the min, got %v", got)
	}
	t2, t3 := cfg.suspicionTimeout(2), cfg.suspicionTimeout(3)
	if !(t2 > t3 && t3 > 100*time.Millisecond && t2 < time.Second) {
		t.Fatalf("more confirmers must monotonically shorten the timeout: 2->%v 3->%v", t2, t3)
	}
}

func TestMemberListCountsDistinctConfirmers(t *testing.T) {
	clk := newFakeClock()
	ml := NewMemberList("self", clk.Now)
	ml.Apply(Update{NodeID: "x", State: StateAlive})
	ml.Apply(Update{NodeID: "x", State: StateSuspect, From: "a"})
	ml.Apply(Update{NodeID: "x", State: StateSuspect, From: "b"})
	ml.Apply(Update{NodeID: "x", State: StateSuspect, From: "b"}) // duplicate asserter, ignored

	if m, _ := ml.Get("x"); m.ConfirmerCount() != 2 {
		t.Fatalf("distinct confirmers = %d, want 2", m.ConfirmerCount())
	}

	timeoutFor := func(confirmers int) time.Duration {
		if confirmers >= 2 {
			return 100 * time.Millisecond
		}
		return time.Hour
	}
	if got := ml.ExpireSuspects(timeoutFor); len(got) != 0 {
		t.Fatal("should not expire before its deadline")
	}
	clk.Advance(100 * time.Millisecond)
	if got := ml.ExpireSuspects(timeoutFor); len(got) != 1 || got[0].State != StateDead {
		t.Fatalf("a two-confirmer suspect should expire at its shortened deadline, got %v", got)
	}

	// A refuting alive claim clears the confirmer set.
	ml.Apply(Update{NodeID: "x", State: StateAlive, Incarnation: 5})
	ml.Apply(Update{NodeID: "x", State: StateSuspect, Incarnation: 5, From: "a"})
	if m, _ := ml.Get("x"); m.ConfirmerCount() != 1 {
		t.Fatalf("confirmers should reset after refutation, got %d", m.ConfirmerCount())
	}
}

func TestThreeNodeDiscoveryAndFailure(t *testing.T) {
	clk := newFakeClock()
	w := &world{up: map[string]bool{"a": true, "b": true, "c": true}}
	cfg := Config{
		ProbeInterval:     100 * time.Millisecond,
		ProbeTimeout:      10 * time.Millisecond,
		SuspectMultiplier: 3,
		IndirectProbes:    2,
	}
	mk := func(id string, seed int64) *SWIM {
		return New(id, fakeProber{w}, cfg, zerolog.Nop(), WithClock(clk.Now), WithRand(rand.New(rand.NewSource(seed))))
	}
	a, b, c := mk("a", 1), mk("b", 2), mk("c", 3)

	// Seed a partial topology: a<->b and b<->c. c and a have never met.
	a.Seed("b", []string{"b:1"})
	b.Seed("a", []string{"a:1"})
	b.Seed("c", []string{"c:1"})
	c.Seed("b", []string{"b:1"})

	// round drives only the live nodes: a downed node sends no probes and
	// gossips nothing, which is what lets its peers detect the failure.
	round := func(live ...*SWIM) {
		updates := map[*SWIM][]Update{}
		for _, n := range live {
			n.ProbeOnce(context.Background())
			n.Tick()
			updates[n] = n.Updates(10)
		}
		for src, ups := range updates {
			for _, dst := range live {
				if dst == src {
					continue
				}
				for _, u := range ups {
					dst.Apply(u)
				}
			}
		}
		clk.Advance(cfg.ProbeInterval)
	}

	for i := 0; i < 5; i++ {
		round(a, b, c)
	}

	// Discovery: a learned about c (and vice-versa) purely through b's gossip.
	if m, ok := a.List().Get("c"); !ok || m.State == StateDead {
		t.Fatalf("a should have discovered c as live, got %+v ok=%v", m, ok)
	}
	if _, ok := c.List().Get("a"); !ok {
		t.Fatal("c should have discovered a")
	}

	// Now b dies: it stops probing and gossiping. a and c must detect and
	// converge on b=dead.
	w.set("b", false)
	for i := 0; i < 30; i++ {
		round(a, c)
	}

	for _, n := range []*SWIM{a, c} {
		if m, ok := n.List().Get("b"); !ok || m.State != StateDead {
			t.Fatalf("%s should see b as dead, got %+v ok=%v", n.localID, m, ok)
		}
	}
}
