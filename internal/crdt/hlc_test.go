package crdt

import (
	"sync"
	"testing"
	"time"
)

type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (m *manualClock) now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.t
}

func (m *manualClock) set(t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.t = t
}

func atMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func TestTimestampRoundTrip(t *testing.T) {
	// Node id with hyphens and dots must survive parsing.
	in := Timestamp{Wall: atMillis(1_700_000_123_000).UnixMilli(), Counter: 7, NodeID: "node.edge.eu-west.01"}
	out, err := ParseTimestamp(in.String())
	if err != nil {
		t.Fatalf("ParseTimestamp(%q): %v", in.String(), err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}

func TestTimestampCompare(t *testing.T) {
	base := Timestamp{Wall: 100, Counter: 1, NodeID: "a"}
	cases := []struct {
		name string
		o    Timestamp
		want int
	}{
		{"higher wall", Timestamp{Wall: 101, Counter: 0, NodeID: "a"}, -1},
		{"higher counter", Timestamp{Wall: 100, Counter: 2, NodeID: "a"}, -1},
		{"higher node", Timestamp{Wall: 100, Counter: 1, NodeID: "b"}, -1},
		{"equal", base, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := base.Compare(tc.o); got != tc.want {
				t.Errorf("Compare = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestClockMonotonicWithStuckPhysicalClock(t *testing.T) {
	mc := &manualClock{t: atMillis(1000)}
	c := NewClock("a", WithPhysicalClock(mc.now))

	prev := c.Now()
	for i := 0; i < 1000; i++ {
		ts := c.Now()
		if ts.Compare(prev) <= 0 {
			t.Fatalf("timestamp did not advance: %v after %v", ts, prev)
		}
		prev = ts
	}
}

func TestClockMonotonicWhenPhysicalGoesBackwards(t *testing.T) {
	mc := &manualClock{t: atMillis(5000)}
	c := NewClock("a", WithPhysicalClock(mc.now))

	first := c.Now()
	mc.set(atMillis(1000)) // physical clock jumps backwards
	second := c.Now()
	if second.Compare(first) <= 0 {
		t.Fatalf("clock regressed on backward physical jump: %v then %v", first, second)
	}
}

func TestClockUpdateAdoptsRemote(t *testing.T) {
	mc := &manualClock{t: atMillis(1000)}
	c := NewClock("a", WithPhysicalClock(mc.now), WithMaxDrift(time.Minute))

	remote := Timestamp{Wall: atMillis(1500).UnixMilli(), Counter: 9, NodeID: "b"}
	got, err := c.Update(remote)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got.Wall != remote.Wall || got.Counter != 10 {
		t.Fatalf("update should adopt remote wall and bump counter: got %+v", got)
	}
	// A subsequent local event must still advance.
	if next := c.Now(); next.Compare(got) <= 0 {
		t.Fatalf("local event did not advance after update: %v then %v", got, next)
	}
}

func TestClockUpdateRejectsExcessiveDrift(t *testing.T) {
	mc := &manualClock{t: atMillis(1000)}
	c := NewClock("a", WithPhysicalClock(mc.now), WithMaxDrift(10*time.Second))

	remote := Timestamp{Wall: atMillis(1000 + 60_000).UnixMilli(), NodeID: "b"} // 60s ahead
	if _, err := c.Update(remote); err == nil {
		t.Fatal("expected drift rejection for a far-future remote timestamp")
	}
}

func TestClockCheckSkew(t *testing.T) {
	mc := &manualClock{t: atMillis(100_000)}
	c := NewClock("a", WithPhysicalClock(mc.now))

	within := Timestamp{Wall: atMillis(105_000).UnixMilli(), NodeID: "b"}
	if err := c.CheckSkew(within, 10*time.Second); err != nil {
		t.Errorf("within-window timestamp rejected: %v", err)
	}
	for _, bad := range []int64{100_000 + 30_000, 100_000 - 30_000} {
		ts := Timestamp{Wall: atMillis(bad).UnixMilli(), NodeID: "b"}
		if err := c.CheckSkew(ts, 10*time.Second); err == nil {
			t.Errorf("out-of-window timestamp (%d) accepted", bad)
		}
	}
}

func TestClockRestartNoRegression(t *testing.T) {
	mc := &manualClock{t: atMillis(9000)}
	c := NewClock("a", WithPhysicalClock(mc.now))
	var last Timestamp
	for i := 0; i < 50; i++ {
		last = c.Now()
	}

	// Restart: physical clock came back at an earlier time; seed from snapshot.
	restarted := NewClock("a", WithPhysicalClock(func() time.Time { return atMillis(1000) }), WithInitial(last))
	if next := restarted.Now(); next.Compare(last) <= 0 {
		t.Fatalf("clock regressed across restart: %v then %v", last, next)
	}
}
