package crdt

import frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"

// detectEquivocation reports whether env reuses a (node_id, seq) already held by
// a different op_id, which is a forked author history. It assumes the caller
// holds the write lock and has already ruled out a duplicate op_id. The returned
// proof carries both conflicting envelopes; detected_by/detected_at are left for
// the verify layer (Phase 4) to stamp.
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
