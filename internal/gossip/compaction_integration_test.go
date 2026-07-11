package gossip

import (
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/checkpoint"
	"github.com/prateekpurohit13/frien/internal/crdt"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// TestClusterCompactsFleetScopeOnceAllPeersConfirm exercises the whole
// checkpoint/compaction path over a real two-node QUIC cluster: publish,
// converge, let anti-entropy teach each side the other's watermark, then
// compact. This is the end-to-end proof that a compaction cycle bounds memory
// without the mesh losing or resurrecting anything.
func TestClusterCompactsFleetScopeOnceAllPeersConfirm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live cluster test in -short")
	}
	ca := newTestCA(t)
	addrA, addrB := freeUDPAddr(t), freeUDPAddr(t)
	a := newNode(t, ca, "node.a", "z", addrA, nil)
	b := newNode(t, ca, "node.b", "z", addrB, []string{addrA})
	defer a.stop()
	defer b.stop()

	now := time.Now().UTC()
	future := now.Add(time.Hour).Format(time.RFC3339)
	var envs []*frienv1.OperationEnvelope
	for i := 0; i < 3; i++ {
		tr := &frienv1.ThreatRecord{Id: string(rune('a' + i)), Indicator: "203.0.113.1", Scope: "fleet", ExpiresAt: future}
		env, err := a.eng.Publish(crdt.OpThreatRecord, tr, "fleet")
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		envs = append(envs, env)
	}

	if !eventually(t, 20*time.Second, func() bool {
		for _, env := range envs {
			if !b.set.Has(env.GetOpId()) {
				return false
			}
		}
		return true
	}) {
		t.Fatal("ops did not converge to node.b")
	}

	compactor := checkpoint.NewCompactor(a.set, a.eng.PeerWatermarks(), a.eng,
		func() []string { return []string{"fleet"} },
		func(string) []string { return a.eng.LiveFleetPeers() },
		a.eng.signer, zerolog.Nop())

	// Wait for node.b to have reported (via anti-entropy) a watermark for
	// node.a that covers all 3 published ops -- the precondition SafeFloor
	// requires before a cut past them is safe. Drive RunOnce each poll so the
	// compaction happens as soon as the floor becomes safe.
	if !eventually(t, 20*time.Second, func() bool {
		compactor.RunOnce()
		for _, env := range envs {
			if a.set.Has(env.GetOpId()) {
				return false
			}
		}
		return true
	}) {
		t.Fatal("compaction never became safe within the timeout")
	}

	// The checkpoint op itself must converge to node.b like any other op.
	if !eventually(t, 20*time.Second, func() bool {
		for _, env := range b.set.Snapshot() {
			if env.GetOpType() == crdt.OpCheckpoint {
				return true
			}
		}
		return false
	}) {
		t.Fatal("the checkpoint op did not propagate to node.b")
	}
}
