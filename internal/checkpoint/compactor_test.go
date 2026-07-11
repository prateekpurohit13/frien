package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type recordingPublisher struct {
	published []*frienv1.OperationEnvelope
	seq       uint64
}

func (p *recordingPublisher) Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error) {
	body, err := proto.Marshal(payload)
	if err != nil {
		return nil, err
	}
	p.seq++
	env := &frienv1.OperationEnvelope{
		OpId: fmt.Sprintf("cp_op_%d", p.seq), OpType: opType, NodeId: "self",
		Seq: p.seq, Payload: body,
	}
	p.published = append(p.published, env)
	return env, nil
}

func fleetOnly() []string { return []string{"fleet"} }

// peersFunc returns a LivePeersFunc that offers the same fixed peer set
// regardless of scope, matching the single-scope ("fleet") tests below.
func peersFunc(peers ...string) LivePeersFunc {
	return func(string) []string { return peers }
}

func fleetOp(t *testing.T, opID, nodeID string, seq uint64) *frienv1.OperationEnvelope {
	t.Helper()
	body, err := proto.Marshal(&frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(body)
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: crdt.OpThreatRecord, NodeId: nodeID, Seq: seq,
		Hlc:         fmt.Sprintf("1700000000000-%d-%s", seq, nodeID),
		PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Payload: body,
	}
}

func TestCompactorNoOpUntilFloorIsSafe(t *testing.T) {
	set := crdt.NewOpSet()
	set.Add(fleetOp(t, "op1", "node.a", 1))
	watermarks := NewPeerWatermarks()
	pub := &recordingPublisher{}
	signer := newTestSigner(t)

	c := NewCompactor(set, watermarks, pub, fleetOnly, peersFunc("peerB"), signer, zerolog.Nop())
	c.RunOnce()

	if set.Len() != 1 {
		t.Fatal("nothing should be compacted before peerB is observed")
	}
	if len(pub.published) != 0 {
		t.Fatal("no checkpoint should be published when nothing was compacted")
	}
}

func TestCompactorCompactsAndPublishesCheckpoint(t *testing.T) {
	set := crdt.NewOpSet()
	set.Add(fleetOp(t, "op1", "node.a", 1))
	set.Add(fleetOp(t, "op2", "node.a", 2))

	watermarks := NewPeerWatermarks()
	watermarks.Observe("peerB", "fleet", map[string]uint64{"node.a": 2})

	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	c := NewCompactor(set, watermarks, pub, fleetOnly, peersFunc("peerB"), signer, zerolog.Nop())

	c.RunOnce()

	if set.Len() != 0 {
		t.Fatalf("both ops should be compacted, set.Len() = %d", set.Len())
	}
	if len(pub.published) != 1 {
		t.Fatalf("exactly one checkpoint should be published, got %d", len(pub.published))
	}
	var cp frienv1.Checkpoint
	if err := proto.Unmarshal(pub.published[0].GetPayload(), &cp); err != nil {
		t.Fatalf("unmarshal checkpoint payload: %v", err)
	}
	if cp.GetTreeHead() == "" || cp.GetCheckpointId() == "" || cp.GetSignature() == nil {
		t.Fatalf("checkpoint should be fully populated and signed: %+v", &cp)
	}
}

func TestCompactorChainsSuccessiveCheckpoints(t *testing.T) {
	set := crdt.NewOpSet()
	watermarks := NewPeerWatermarks()
	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	c := NewCompactor(set, watermarks, pub, fleetOnly, peersFunc(), signer, zerolog.Nop())

	set.Add(fleetOp(t, "op1", "node.a", 1))
	watermarks.Observe("noone", "fleet", nil) // no live peers to confirm against; self-only floor
	c.RunOnce()

	set.Add(fleetOp(t, "op2", "node.a", 2))
	c.RunOnce()

	if len(pub.published) != 2 {
		t.Fatalf("expected 2 checkpoints, got %d", len(pub.published))
	}
	var first, second frienv1.Checkpoint
	proto.Unmarshal(pub.published[0].GetPayload(), &first)
	proto.Unmarshal(pub.published[1].GetPayload(), &second)

	if second.GetPrevCheckpoint() != first.GetCheckpointId() {
		t.Fatalf("second checkpoint should chain from the first: prev=%q want=%q", second.GetPrevCheckpoint(), first.GetCheckpointId())
	}
	if second.GetTreeHead() == first.GetTreeHead() {
		t.Fatal("tree heads across successive checkpoints should differ")
	}
}

func TestCompactorDoesNotCompactEquivocationEvidence(t *testing.T) {
	set := crdt.NewOpSet()
	set.Add(fleetOp(t, "opA", "node.a", 1))
	set.Add(fleetOp(t, "opB", "node.a", 1)) // fork at (node.a, 1)

	watermarks := NewPeerWatermarks()
	watermarks.Observe("peerB", "fleet", map[string]uint64{"node.a": 1})

	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	c := NewCompactor(set, watermarks, pub, fleetOnly, peersFunc("peerB"), signer, zerolog.Nop())
	c.RunOnce()

	if set.Len() != 2 {
		t.Fatalf("equivocation evidence must survive compaction, set.Len() = %d", set.Len())
	}
	if len(pub.published) != 0 {
		t.Fatal("no checkpoint should publish when the floor advanced but nothing was actually removable")
	}
}

func zoneOp(t *testing.T, opID, nodeID string, seq uint64, zoneScope string) *frienv1.OperationEnvelope {
	t.Helper()
	body, err := proto.Marshal(&frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.1", Scope: zoneScope})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(body)
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: crdt.OpThreatRecord, NodeId: nodeID, Seq: seq,
		Hlc:         fmt.Sprintf("1700000000000-%d-%s", seq, nodeID),
		PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Payload: body,
	}
}

// TestCompactorCompactsScopesIndependently is the end-to-end proof that zone
// compaction is safe alongside fleet compaction: a zone peer confirming only
// the zone watermark must not let the fleet scope compact (no fleet peer has
// confirmed it yet), and vice versa. This is the scenario
// TestCompactBelowIsScopedNotGlobal proves at the OpSet layer; this test
// proves the whole Compactor, including its per-scope LivePeersFunc dispatch,
// gets it right too.
//
// node.a and node.b are deliberately different origins, each single-scope:
// this isolates "does per-scope SafeFloor/CompactBelow dispatch work" from a
// separate, harder problem this test does not exercise -- a single origin
// interleaving scopes in its own (global, not per-scope) seq counter can
// stall ScopeState's contiguous-watermark computation for one of those
// scopes indefinitely. That's a real, documented limitation (see
// HARDENING_ROADMAP.md); this test's job is the scope-isolation guarantee,
// not the interleaving one.
func TestCompactorCompactsScopesIndependently(t *testing.T) {
	set := crdt.NewOpSet()
	set.Add(zoneOp(t, "f1", "node.b", 1, "fleet"))
	set.Add(zoneOp(t, "z1", "node.a", 1, "zone:eu"))

	watermarks := NewPeerWatermarks()
	// A zone peer confirms only the zone watermark; no fleet peer has
	// confirmed anything yet.
	watermarks.Observe("zonePeer", "zone:eu", map[string]uint64{"node.a": 1})

	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	livePeers := func(scopeKey string) []string {
		if scopeKey == "zone:eu" {
			return []string{"zonePeer"}
		}
		return []string{"fleetPeer"} // never observed -> fleet floor stays unsafe
	}
	c := NewCompactor(set, watermarks, pub, func() []string { return []string{"fleet", "zone:eu"} }, livePeers, signer, zerolog.Nop())
	c.RunOnce()

	if set.Has("z1") {
		t.Fatal("zone:eu op should have been compacted once its own zone peer confirmed it")
	}
	if !set.Has("f1") {
		t.Fatal("fleet op must survive: no fleet peer has confirmed it, even though the zone floor advanced")
	}
	if len(pub.published) != 1 {
		t.Fatalf("exactly one checkpoint (zone:eu) should have published, got %d", len(pub.published))
	}
	var cp frienv1.Checkpoint
	if err := proto.Unmarshal(pub.published[0].GetPayload(), &cp); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	if cp.GetScope() != "zone:eu" {
		t.Fatalf("published checkpoint scope = %q, want zone:eu", cp.GetScope())
	}

	id, _, ok := c.Latest("zone:eu")
	if !ok || id != cp.GetCheckpointId() {
		t.Fatalf("Latest(zone:eu) = %q, %v; want %q, true", id, ok, cp.GetCheckpointId())
	}
	if _, _, ok := c.Latest("fleet"); ok {
		t.Fatal("Latest(fleet) should report nothing built, since fleet never compacted")
	}
}
