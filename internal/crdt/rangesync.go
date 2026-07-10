package crdt

import (
	"sort"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type nodeSeq struct {
	node string
	seq  uint64
}

// ScopeState summarizes what this node holds in a scope for a range-based
// anti-entropy request: the highest contiguous seq per origin node, and the
// op_ids not covered by those watermarks (the out-of-order tail plus any
// equivocation siblings). A peer can then return exactly the ops this node
// lacks without either side shipping its full op-id set for the scope.
//
// The contiguous-watermark scan reads seqIndex (kept forever, including seqs
// whose envelope has since been compacted) rather than the live scopeIndex,
// filtered by the opScope tombstone. Scanning only live ops would make a
// watermark unable to advance past a compacted region: the compacted seqs
// would simply be invisible, looking like a permanent gap.
func (s *OpSet) ScopeState(scopeKey string) (haveSeqs map[string]uint64, haveAbove []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seqsByNode := make(map[string][]uint64)
	for node, bySeq := range s.seqIndex {
		for seq, id := range bySeq {
			if s.opScope[id] == scopeKey {
				seqsByNode[node] = append(seqsByNode[node], seq)
			}
		}
	}

	haveSeqs = make(map[string]uint64, len(seqsByNode))
	for n, seqs := range seqsByNode {
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		var wm uint64
		for _, sq := range seqs {
			if sq == wm+1 {
				wm = sq
			} else if sq > wm {
				break // gap: contiguous run ends here
			}
		}
		haveSeqs[n] = wm
	}

	// haveAbove only ever needs to list still-present ops: it tells a peer
	// what this node already holds beyond the watermark (or as an
	// equivocation sibling), and a compacted op cannot be listed or sent
	// regardless -- every live peer is already guaranteed to hold it.
	ids := s.scopeIndex[scopeKey]
	countByNodeSeq := make(map[nodeSeq]int, len(ids))
	for id := range ids {
		if env := s.ops[id]; env != nil {
			countByNodeSeq[nodeSeq{env.GetNodeId(), env.GetSeq()}]++
		}
	}
	for id := range ids {
		env := s.ops[id]
		if env == nil {
			continue
		}
		ns := nodeSeq{env.GetNodeId(), env.GetSeq()}
		if env.GetSeq() > haveSeqs[env.GetNodeId()] || countByNodeSeq[ns] > 1 {
			haveAbove = append(haveAbove, id)
		}
	}
	sort.Strings(haveAbove)
	return haveSeqs, haveAbove
}

// MissingInRange returns up to limit ops in scope that the requester lacks,
// given its per-node contiguous watermark (haveSeqs) and the op_ids it already
// holds above those watermarks or as equivocation siblings (haveAbove). Ops are
// ordered by (node_id, seq) so the requester fills gaps in order and its
// watermark advances each round; a limit of 0 returns all missing ops. Ops that
// share a (node_id, seq) with a sibling on this side (equivocation) bypass the
// watermark, so the evidence propagates even when it sits below the watermark.
func (s *OpSet) MissingInRange(scopeKey string, haveSeqs map[string]uint64, haveAbove map[string]struct{}, limit int) []*frienv1.OperationEnvelope {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.scopeIndex[scopeKey]
	countByNodeSeq := make(map[nodeSeq]int, len(ids))
	for id := range ids {
		if env := s.ops[id]; env != nil {
			countByNodeSeq[nodeSeq{env.GetNodeId(), env.GetSeq()}]++
		}
	}

	var out []*frienv1.OperationEnvelope
	for id := range ids {
		env := s.ops[id]
		if env == nil {
			continue
		}
		if _, held := haveAbove[id]; held {
			continue
		}
		ns := nodeSeq{env.GetNodeId(), env.GetSeq()}
		if env.GetSeq() <= haveSeqs[env.GetNodeId()] && countByNodeSeq[ns] == 1 {
			continue // requester provably holds this op below its watermark
		}
		out = append(out, env)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].GetNodeId() != out[j].GetNodeId() {
			return out[i].GetNodeId() < out[j].GetNodeId()
		}
		if out[i].GetSeq() != out[j].GetSeq() {
			return out[i].GetSeq() < out[j].GetSeq()
		}
		return out[i].GetOpId() < out[j].GetOpId()
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
