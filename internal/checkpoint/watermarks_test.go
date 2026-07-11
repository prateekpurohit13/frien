package checkpoint

import "testing"

func TestSafeFloorNilUntilEveryLivePeerObserved(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 10})

	if got := w.SafeFloor("fleet", []string{"peerA", "peerB"}, map[string]uint64{"node.a": 10}); got != nil {
		t.Fatalf("floor should be nil until peerB is observed, got %v", got)
	}

	w.Observe("peerB", "fleet", map[string]uint64{"node.a": 5})
	got := w.SafeFloor("fleet", []string{"peerA", "peerB"}, map[string]uint64{"node.a": 10})
	if got == nil || got["node.a"] != 5 {
		t.Fatalf("floor should be min(self=10, peerA=10, peerB=5)=5, got %v", got)
	}
}

func TestSafeFloorTakesMinAcrossSelfAndAllPeers(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 20, "node.b": 3})
	w.Observe("peerB", "fleet", map[string]uint64{"node.a": 8, "node.b": 100})

	got := w.SafeFloor("fleet", []string{"peerA", "peerB"}, map[string]uint64{"node.a": 15, "node.b": 50})
	if got["node.a"] != 8 {
		t.Fatalf("node.a floor = %d, want 8 (min of self=15, peerA=20, peerB=8)", got["node.a"])
	}
	if got["node.b"] != 3 {
		t.Fatalf("node.b floor = %d, want 3 (min of self=50, peerA=3, peerB=100)", got["node.b"])
	}
}

func TestSafeFloorTreatsUnreportedOriginAsZero(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", "fleet", map[string]uint64{}) // observed, but reports nothing

	got := w.SafeFloor("fleet", []string{"peerA"}, map[string]uint64{"node.a": 10})
	if got["node.a"] != 0 {
		t.Fatalf("an observed peer reporting nothing for an origin should floor it at 0, got %d", got["node.a"])
	}
}

func TestSafeFloorEmptyLivePeersUsesSelfOnly(t *testing.T) {
	w := NewPeerWatermarks()
	got := w.SafeFloor("fleet", nil, map[string]uint64{"node.a": 10})
	if got["node.a"] != 10 {
		t.Fatalf("with no peers to confirm against, floor should just be self's watermark, got %d", got["node.a"])
	}
}

func TestObserveKeepsMaximumReported(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 5})
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 3}) // stale/out-of-order report
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 9})

	got := w.SafeFloor("fleet", []string{"peerA"}, map[string]uint64{"node.a": 100})
	if got["node.a"] != 9 {
		t.Fatalf("watermark should be the max ever reported (9), got %d", got["node.a"])
	}
}

func TestObservedReportsWhetherPeerSeen(t *testing.T) {
	w := NewPeerWatermarks()
	if w.Observed("peerA", "fleet") {
		t.Fatal("unobserved peer should report false")
	}
	w.Observe("peerA", "fleet", nil)
	if !w.Observed("peerA", "fleet") {
		t.Fatal("a peer observed with an empty report should still count as observed")
	}
}

// TestScopesDoNotConflate proves the bug a single-map-per-peer version of
// this type would have: a peer's fleet-scope watermark for an origin and its
// zone-scope watermark for the same origin must stay independent, or a floor
// computed for one scope would be silently corrupted by data observed for
// the other.
func TestScopesDoNotConflate(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", "fleet", map[string]uint64{"node.a": 100})
	w.Observe("peerA", "zone:eu", map[string]uint64{"node.a": 3})

	if w.Observed("peerA", "zone:us") {
		t.Fatal("peerA was never observed for zone:us and should not report observed")
	}

	fleetFloor := w.SafeFloor("fleet", []string{"peerA"}, map[string]uint64{"node.a": 100})
	if fleetFloor["node.a"] != 100 {
		t.Fatalf("fleet floor should be unaffected by the much lower zone:eu report, got %d", fleetFloor["node.a"])
	}
	zoneFloor := w.SafeFloor("zone:eu", []string{"peerA"}, map[string]uint64{"node.a": 100})
	if zoneFloor["node.a"] != 3 {
		t.Fatalf("zone:eu floor should be unaffected by the much higher fleet report, got %d", zoneFloor["node.a"])
	}
}
