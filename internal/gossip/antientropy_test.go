package gossip

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/scope"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func fleetEnv(id string, seq uint64) *frienv1.OperationEnvelope {
	return &frienv1.OperationEnvelope{
		// ScopeSeq mirrors Seq: every envelope here is unscoped (default
		// fleet) and shares node "n", so the two counters coincide 1:1.
		OpId: id, OpType: crdt.OpCheckpoint, NodeId: "n", Seq: seq, ScopeSeq: seq,
		PayloadHash: "sha256:x", Payload: []byte(id),
	}
}

func newAntiEntropyEngine(t *testing.T, maxOpsPerMsg, total int) *Engine {
	t.Helper()
	set := crdt.NewOpSet()
	for i := 0; i < total; i++ {
		if _, err := set.Add(fleetEnv(fmt.Sprintf("op%03d", i), uint64(i+1))); err != nil {
			t.Fatalf("seed op %d: %v", i, err)
		}
	}
	return &Engine{
		cfg:    Config{ProtoVersion: 1, MaxOpsPerMsg: maxOpsPerMsg},
		set:    set,
		router: scope.NewRouter("z"),
		log:    zerolog.Nop(),
	}
}

func TestOnAntiEntropyCapsResponse(t *testing.T) {
	e := newAntiEntropyEngine(t, 4, 10)
	resp := e.OnAntiEntropy(&frienv1.AntiEntropyRequest{Scope: "fleet", Zone: "z"})
	if got := len(resp.GetMissingOps()); got != 4 {
		t.Fatalf("response should be capped at 4, got %d", got)
	}
}

func TestOnAntiEntropyRangePagesToCompletion(t *testing.T) {
	const total, page = 10, 4
	e := newAntiEntropyEngine(t, page, total)
	requester := crdt.NewOpSet()

	for round := 0; round < total+2; round++ {
		haveSeqs, haveAbove := requester.ScopeState("fleet")
		resp := e.OnAntiEntropy(&frienv1.AntiEntropyRequest{
			Scope: "fleet", Zone: "z", HaveSeqs: haveSeqs, HaveAbove: haveAbove,
		})
		if len(resp.GetMissingOps()) == 0 {
			break
		}
		if len(resp.GetMissingOps()) > page {
			t.Fatalf("round %d exceeded the page cap: %d", round, len(resp.GetMissingOps()))
		}
		for _, env := range resp.GetMissingOps() {
			if _, err := requester.Add(env); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
	}

	if requester.Len() != total {
		t.Fatalf("range sync converged to %d ops, want %d", requester.Len(), total)
	}
	if requester.CanonicalHash() != e.set.CanonicalHash() {
		t.Fatal("requester and responder sets diverged after range sync")
	}
}
