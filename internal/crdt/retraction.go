package crdt

import (
	"google.golang.org/protobuf/proto"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// retractedSet returns the op_ids withdrawn by a valid author retraction. A
// retraction counts only when it is authored by the same node as its target and
// carries a strictly higher seq — single-writer last-writer-wins, no cross-actor
// race. Envelope authenticity itself is verified upstream (Phase 4); here the
// node_id is taken as the asserted author. Assumes the read lock is held.
func (s *OpSet) retractedSet() map[string]bool {
	out := make(map[string]bool)
	for _, env := range s.ops {
		if env.GetOpType() != OpRetraction {
			continue
		}
		var r frienv1.Retraction
		if err := proto.Unmarshal(env.GetPayload(), &r); err != nil {
			continue
		}
		target, ok := s.ops[r.GetTargetOpId()]
		if !ok {
			continue
		}
		if target.GetNodeId() == env.GetNodeId() && env.GetSeq() > target.GetSeq() {
			out[r.GetTargetOpId()] = true
		}
	}
	return out
}
