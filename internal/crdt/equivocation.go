package crdt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// StampAttribution completes a freshly-detected MisbehaviorProof with the
// detecting node's identity, the detection time, and a fresh proof id.
// detectEquivocation cannot fill these in itself: it runs under the OpSet's
// lock with no notion of which node is asking or what time it is; both belong
// to the caller, which knows its own identity and clock.
func StampAttribution(proof *frienv1.MisbehaviorProof, detectedBy string, at time.Time) {
	if proof == nil {
		return
	}
	proof.Id = "proof_" + randomToken()
	proof.DetectedBy = detectedBy
	proof.DetectedAt = at.UTC().Format(time.RFC3339)
}

func randomToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// detectEquivocation reports whether env reuses a (node_id, seq) already held by
// a different op_id, which is a forked author history. It assumes the caller
// holds the write lock and has already ruled out a duplicate op_id. The returned
// proof carries both conflicting envelopes; the caller stamps attribution via
// StampAttribution once it has admitted the op (see gossip.Engine.ingest).
func (s *OpSet) detectEquivocation(env *frienv1.OperationEnvelope) *frienv1.MisbehaviorProof {
	bySeq, ok := s.seqIndex[env.GetNodeId()]
	if !ok {
		return nil
	}
	prevID, ok := bySeq[env.GetSeq()]
	if !ok || prevID == env.GetOpId() {
		return nil
	}
	return &frienv1.MisbehaviorProof{
		OffenderNodeId: env.GetNodeId(),
		OpA:            s.ops[prevID],
		OpB:            env,
	}
}

// recordSeq indexes the first op_id seen at each (node_id, seq) so later forks
// are detected against the original. It assumes the write lock is held.
func (s *OpSet) recordSeq(env *frienv1.OperationEnvelope) {
	bySeq := s.seqIndex[env.GetNodeId()]
	if bySeq == nil {
		bySeq = make(map[uint64]string)
		s.seqIndex[env.GetNodeId()] = bySeq
	}
	if _, ok := bySeq[env.GetSeq()]; !ok {
		bySeq[env.GetSeq()] = env.GetOpId()
	}
}
