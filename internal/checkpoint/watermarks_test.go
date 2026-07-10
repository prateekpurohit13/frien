package checkpoint

import "testing"

func TestSafeFloorNilUntilEveryLivePeerObserved(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", map[string]uint64{"node.a": 10})

	if got := w.SafeFloor([]string{"peerA", "peerB"}, map[string]uint64{"node.a": 10}); got != nil {
		t.Fatalf("floor should be nil until peerB is observed, got %v", got)
	}

	w.Observe("peerB", map[string]uint64{"node.a": 5})
	got := w.SafeFloor([]string{"peerA", "peerB"}, map[string]uint64{"node.a": 10})
	if got == nil || got["node.a"] != 5 {
		t.Fatalf("floor should be min(self=10, peerA=10, peerB=5)=5, got %v", got)
	}
}

func TestSafeFloorTakesMinAcrossSelfAndAllPeers(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", map[string]uint64{"node.a": 20, "node.b": 3})
	w.Observe("peerB", map[string]uint64{"node.a": 8, "node.b": 100})

	got := w.SafeFloor([]string{"peerA", "peerB"}, map[string]uint64{"node.a": 15, "node.b": 50})
	if got["node.a"] != 8 {
		t.Fatalf("node.a floor = %d, want 8 (min of self=15, peerA=20, peerB=8)", got["node.a"])
	}
	if got["node.b"] != 3 {
		t.Fatalf("node.b floor = %d, want 3 (min of self=50, peerA=3, peerB=100)", got["node.b"])
	}
}

func TestSafeFloorTreatsUnreportedOriginAsZero(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", map[string]uint64{}) // observed, but reports nothing

	got := w.SafeFloor([]string{"peerA"}, map[string]uint64{"node.a": 10})
	if got["node.a"] != 0 {
		t.Fatalf("an observed peer reporting nothing for an origin should floor it at 0, got %d", got["node.a"])
	}
}

func TestSafeFloorEmptyLivePeersUsesSelfOnly(t *testing.T) {
	w := NewPeerWatermarks()
	got := w.SafeFloor(nil, map[string]uint64{"node.a": 10})
	if got["node.a"] != 10 {
		t.Fatalf("with no peers to confirm against, floor should just be self's watermark, got %d", got["node.a"])
	}
}

func TestObserveKeepsMaximumReported(t *testing.T) {
	w := NewPeerWatermarks()
	w.Observe("peerA", map[string]uint64{"node.a": 5})
	w.Observe("peerA", map[string]uint64{"node.a": 3}) // stale/out-of-order report
	w.Observe("peerA", map[string]uint64{"node.a": 9})

	got := w.SafeFloor([]string{"peerA"}, map[string]uint64{"node.a": 100})
	if got["node.a"] != 9 {
		t.Fatalf("watermark should be the max ever reported (9), got %d", got["node.a"])
	}
}

func TestObservedReportsWhetherPeerSeen(t *testing.T) {
	w := NewPeerWatermarks()
	if w.Observed("peerA") {
		t.Fatal("unobserved peer should report false")
	}
	w.Observe("peerA", nil)
	if !w.Observed("peerA") {
		t.Fatal("a peer observed with an empty report should still count as observed")
	}
}
