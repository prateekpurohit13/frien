package gossip

import "testing"

func TestFanoutForCapsAtAvailableAndSeedsAtMax(t *testing.T) {
	e := &Engine{cfg: Config{GossipFanout: 6}}
	if got := e.fanoutFor(3); got != 3 {
		t.Fatalf("fanout should be capped at the available peer count, got %d", got)
	}
	// Seeded target is the configured max; with more peers available it is used.
	if got := e.fanoutFor(10); got != 6 {
		t.Fatalf("fanout should seed at the configured max of 6, got %d", got)
	}
}

func TestFanoutBacksOffThenRecovers(t *testing.T) {
	e := &Engine{cfg: Config{GossipFanout: 8}}
	e.fanoutFor(8) // seed target at 8

	// A round where the majority failed halves the target.
	e.adjustFanout(5, 8)
	if got := e.fanoutFor(100); got != 4 {
		t.Fatalf("majority failure should halve fan-out to 4, got %d", got)
	}
	// A second bad round halves again.
	e.adjustFanout(3, 4)
	if got := e.fanoutFor(100); got != 2 {
		t.Fatalf("second failure should halve to 2, got %d", got)
	}
	// Healthy rounds step it back up one at a time toward the max.
	e.adjustFanout(0, 2)
	if got := e.fanoutFor(100); got != 3 {
		t.Fatalf("a clean round should additively increase to 3, got %d", got)
	}
}

func TestFanoutNeverDropsBelowOne(t *testing.T) {
	e := &Engine{cfg: Config{GossipFanout: 2}}
	e.fanoutFor(2)
	for i := 0; i < 5; i++ {
		e.adjustFanout(2, 2) // every round fully fails
	}
	if got := e.fanoutFor(100); got != 1 {
		t.Fatalf("fan-out must never fall below 1, got %d", got)
	}
}

func TestRandIntnWithinBound(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if v := randIntn(5); v < 0 || v >= 5 {
			t.Fatalf("randIntn(5) = %d, out of [0,5)", v)
		}
	}
	if randIntn(1) != 0 || randIntn(0) != 0 {
		t.Fatal("randIntn(<=1) must be 0")
	}
}
