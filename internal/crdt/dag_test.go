package crdt

import (
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func envWithParents(t *testing.T, opID, nodeID string, seq uint64, parents ...string) *frienv1.OperationEnvelope {
	t.Helper()
	env := threatEnv(t, opID, nodeID, seq, "")
	env.Parents = parents
	return env
}

func TestAddBuffersUntilParentArrives(t *testing.T) {
	s := NewOpSet()
	child := envWithParents(t, "child", "node.a", 2, "parent")

	res, err := s.Add(child)
	if err != nil {
		t.Fatalf("add child: %v", err)
	}
	if !res.Buffered || res.Added {
		t.Fatalf("expected child buffered awaiting parent, got %+v", res)
	}
	if s.Has("child") {
		t.Fatal("child should not be admitted before its parent")
	}
	if s.PendingCount() != 1 {
		t.Fatalf("pending count = %d, want 1", s.PendingCount())
	}

	parent := threatEnv(t, "parent", "node.a", 1, "")
	res, err = s.Add(parent)
	if err != nil || !res.Added {
		t.Fatalf("add parent: res=%+v err=%v", res, err)
	}
	if !s.Has("child") {
		t.Fatal("child should be admitted once its parent arrives")
	}
	if s.PendingCount() != 0 {
		t.Fatalf("pending count = %d, want 0 after drain", s.PendingCount())
	}
}

func TestDrainRecursivelyUnblocksChain(t *testing.T) {
	s := NewOpSet()
	// Deliver a 3-hop chain in reverse order: c depends on b depends on a.
	c := envWithParents(t, "c", "node.a", 3, "b")
	b := envWithParents(t, "b", "node.a", 2, "a")
	a := threatEnv(t, "a", "node.a", 1, "")

	if res, _ := s.Add(c); !res.Buffered {
		t.Fatalf("c should buffer, got %+v", res)
	}
	if res, _ := s.Add(b); !res.Buffered {
		t.Fatalf("b should buffer, got %+v", res)
	}

	res, drained, err := s.AddWithLimitAndDrain(a, 0)
	if err != nil || !res.Added {
		t.Fatalf("add a: res=%+v err=%v", res, err)
	}
	if len(drained) != 2 {
		t.Fatalf("expected b and c drained together, got %d: %+v", len(drained), drained)
	}
	if !s.Has("b") || !s.Has("c") {
		t.Fatal("both b and c should be admitted once the whole chain resolves")
	}
}

func TestParentsSatisfiedByCompactedTombstone(t *testing.T) {
	s := NewOpSet()
	parent := threatEnv(t, "parent", "node.a", 1, "")
	if _, err := s.Add(parent); err != nil {
		t.Fatalf("add parent: %v", err)
	}
	s.CompactBelow(map[string]uint64{"node.a": 1})
	if s.Has("parent") {
		t.Fatal("parent should have been compacted out")
	}

	child := envWithParents(t, "child", "node.a", 2, "parent")
	res, err := s.Add(child)
	if err != nil || !res.Added {
		t.Fatalf("child with a compacted parent should admit directly, got %+v err=%v", res, err)
	}
}

func TestBufferOverflowFailsOpen(t *testing.T) {
	s := NewOpSet()
	// Fill the buffer with unrelated parent-less-yet envelopes so it saturates.
	for i := 0; i < maxPendingParents; i++ {
		env := envWithParents(t, fmt.Sprintf("op%d", i), "node.a", uint64(i+2), "never-arrives")
		if res, err := s.Add(env); err != nil || !res.Buffered {
			t.Fatalf("op%d: expected buffered, got %+v err=%v", i, res, err)
		}
	}
	if s.PendingCount() != maxPendingParents {
		t.Fatalf("pending count = %d, want %d", s.PendingCount(), maxPendingParents)
	}

	overflow := envWithParents(t, "overflow", "node.a", uint64(maxPendingParents+2), "also-never-arrives")
	res, err := s.Add(overflow)
	if err != nil || !res.Added {
		t.Fatalf("op past the pending cap should fail open and admit directly, got %+v err=%v", res, err)
	}
}

func TestChainRootStableAcrossCompaction(t *testing.T) {
	s := NewOpSet()
	var prev string
	for i := uint64(1); i <= 5; i++ {
		env := threatEnv(t, fmt.Sprintf("op%d", i), "node.a", i, "")
		if prev != "" {
			env.Parents = []string{prev}
		}
		if _, err := s.Add(env); err != nil {
			t.Fatalf("add op%d: %v", i, err)
		}
		prev = env.GetOpId()
	}
	before := s.ChainRoot("node.a")
	if before == "" {
		t.Fatal("expected a non-empty chain root")
	}

	s.CompactBelow(map[string]uint64{"node.a": 3})
	after := s.ChainRoot("node.a")
	if before != after {
		t.Fatalf("chain root changed across compaction: before=%s after=%s", before, after)
	}
}

func TestLastOpIDInScopeDoesNotCrossScopes(t *testing.T) {
	s := NewOpSet()
	tr := &frienv1.ThreatRecord{Id: "z1", Indicator: "203.0.113.1", Scope: "zone:eu"}
	body, err := proto.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	zoneEnv := &frienv1.OperationEnvelope{
		OpId: "z1", OpType: OpThreatRecord, NodeId: "node.a", Seq: 1,
		Payload: body, PayloadHash: payloadHash(body),
	}
	if _, err := s.Add(zoneEnv); err != nil {
		t.Fatalf("add zone env: %v", err)
	}

	if _, ok := s.LastOpIDInScope("node.a", "fleet"); ok {
		t.Fatal("a node's zone-scoped op must not surface as the last op in the fleet scope")
	}
	if last, ok := s.LastOpIDInScope("node.a", "zone:eu"); !ok || last != "z1" {
		t.Fatalf("LastOpIDInScope(zone:eu) = %q, %v; want z1, true", last, ok)
	}
}
