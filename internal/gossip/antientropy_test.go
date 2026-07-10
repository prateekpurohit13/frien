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
		OpId: id, OpType: crdt.OpCheckpoint, NodeId: "n", Seq: seq,
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

func TestOnAntiEntropyPagesToCompletion(t *testing.T) {
	const total, page = 10, 4
	e := newAntiEntropyEngine(t, page, total)

	seen := make(map[string]int)
	have := []string{}
	for round := 0; round < total+2; round++ {
		resp := e.OnAntiEntropy(&frienv1.AntiEntropyRequest{Scope: "fleet", Zone: "z", HaveOpIds: have})
		if len(resp.GetMissingOps()) == 0 {
			break
		}
		if len(resp.GetMissingOps()) > page {
			t.Fatalf("round %d exceeded the page cap: %d", round, len(resp.GetMissingOps()))
		}
		for _, env := range resp.GetMissingOps() {
			seen[env.GetOpId()]++
			have = append(have, env.GetOpId())
		}
	}

	if len(seen) != total {
		t.Fatalf("paging delivered %d distinct ops, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("op %s delivered %d times; paging should not duplicate", id, n)
		}
	}
}
