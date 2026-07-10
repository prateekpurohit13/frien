package crdt

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// opList is a randomly-generated batch of ops drawn from a small shared id space
// so that batches overlap — exercising union with genuinely-shared elements.
// Identical op_ids always carry identical content, modelling immutable ops.
type opList []*frienv1.OperationEnvelope

func (opList) Generate(r *rand.Rand, size int) reflect.Value {
	n := r.Intn(size + 1)
	const idSpace = 12
	out := make(opList, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("op%d", r.Intn(idSpace))
		out = append(out, &frienv1.OperationEnvelope{
			OpId:        id,
			OpType:      OpThreatRecord,
			NodeId:      "node.a",
			Seq:         uint64(r.Intn(idSpace)),
			PayloadHash: "h-" + id,
		})
	}
	return reflect.ValueOf(out)
}

func buildSet(lists ...opList) *OpSet {
	s := NewOpSet()
	for _, l := range lists {
		for _, env := range l {
			_, _ = s.Add(env)
		}
	}
	return s
}

func idSet(s *OpSet) map[string]bool {
	out := make(map[string]bool)
	for _, env := range s.Snapshot() {
		out[env.GetOpId()] = true
	}
	return out
}

func quickCfg() *quick.Config { return &quick.Config{MaxCount: 500, Rand: rand.New(rand.NewSource(1))} }

func TestMergeIdempotent(t *testing.T) {
	f := func(a opList) bool {
		s := buildSet(a)
		before := s.CanonicalHash()
		s.Merge(buildSet(a))
		return s.CanonicalHash() == before
	}
	if err := quick.Check(f, quickCfg()); err != nil {
		t.Fatal(err)
	}
}

func TestMergeCommutative(t *testing.T) {
	f := func(a, b opList) bool {
		ab := buildSet(a)
		ab.Merge(buildSet(b))
		ba := buildSet(b)
		ba.Merge(buildSet(a))
		return ab.CanonicalHash() == ba.CanonicalHash()
	}
	if err := quick.Check(f, quickCfg()); err != nil {
		t.Fatal(err)
	}
}

func TestMergeAssociative(t *testing.T) {
	f := func(a, b, c opList) bool {
		// (a ∪ b) ∪ c
		left := buildSet(a)
		left.Merge(buildSet(b))
		left.Merge(buildSet(c))
		// a ∪ (b ∪ c)
		bc := buildSet(b)
		bc.Merge(buildSet(c))
		right := buildSet(a)
		right.Merge(bc)
		return left.CanonicalHash() == right.CanonicalHash()
	}
	if err := quick.Check(f, quickCfg()); err != nil {
		t.Fatal(err)
	}
}

func TestMergeMonotonic(t *testing.T) {
	f := func(a, b opList) bool {
		s := buildSet(a)
		before := idSet(s)
		s.Merge(buildSet(b))
		after := idSet(s)
		for id := range before {
			if !after[id] {
				return false // state shrank — not inflationary
			}
		}
		return true
	}
	if err := quick.Check(f, quickCfg()); err != nil {
		t.Fatal(err)
	}
}

func TestReplicasConvergeRegardlessOfOrder(t *testing.T) {
	f := func(a, b, c opList) bool {
		// Three replicas receive the same ops in different orders, with a
		// duplicate re-delivery standing in for dropped-then-anti-entropy sync.
		r1 := buildSet(a, b, c)
		r2 := buildSet(c, a, b)
		r3 := buildSet(b, c, a, a)
		h := r1.CanonicalHash()
		return r2.CanonicalHash() == h && r3.CanonicalHash() == h
	}
	if err := quick.Check(f, quickCfg()); err != nil {
		t.Fatal(err)
	}
}
