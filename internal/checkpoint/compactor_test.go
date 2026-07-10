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

func fleetOp(t *testing.T, opID, nodeID string, seq uint64) *frienv1.OperationEnvelope {
	t.Helper()
	body, err := proto.Marshal(&frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(body)
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: crdt.OpThreatRecord, NodeId: nodeID, Seq: seq,
		Hlc: fmt.Sprintf("1700000000000-%d-%s", seq, nodeID),
		PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Payload: body,
	}
}

func TestCompactorNoOpUntilFloorIsSafe(t *testing.T) {
	set := crdt.NewOpSet()
	set.Add(fleetOp(t, "op1", "node.a", 1))
	watermarks := NewPeerWatermarks()
	pub := &recordingPublisher{}
	signer := newTestSigner(t)

	c := NewCompactor(set, watermarks, pub, func() []string { return []string{"peerB"} }, signer, zerolog.Nop())
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
	watermarks.Observe("peerB", map[string]uint64{"node.a": 2})

	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	c := NewCompactor(set, watermarks, pub, func() []string { return []string{"peerB"} }, signer, zerolog.Nop())

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
	c := NewCompactor(set, watermarks, pub, func() []string { return nil }, signer, zerolog.Nop())

	set.Add(fleetOp(t, "op1", "node.a", 1))
	watermarks.Observe("noone", nil) // no live peers to confirm against; self-only floor
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
	watermarks.Observe("peerB", map[string]uint64{"node.a": 1})

	pub := &recordingPublisher{}
	signer := newTestSigner(t)
	c := NewCompactor(set, watermarks, pub, func() []string { return []string{"peerB"} }, signer, zerolog.Nop())
	c.RunOnce()

	if set.Len() != 2 {
		t.Fatalf("equivocation evidence must survive compaction, set.Len() = %d", set.Len())
	}
	if len(pub.published) != 0 {
		t.Fatal("no checkpoint should publish when the floor advanced but nothing was actually removable")
	}
}
