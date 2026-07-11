package crdt

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/scope"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Digest summarizes one scope's portion of the set for anti-entropy: peers
// compare Root cheaply and only exchange op-id lists when roots differ.
type Digest struct {
	Scope string
	Root  string
	Count int
}

// scopeOf returns the replication scope an op belongs to. Threat records carry
// their own scope; a retraction inherits its target's scope when the target is
// known; a checkpoint carries the scope of the cut it covers (see
// internal/checkpoint.Build) so a zone checkpoint doesn't leak fleet-wide;
// everything else is fleet (control-plane ops gossip mesh-wide). It assumes
// the lock is held.
func (s *OpSet) scopeOf(env *frienv1.OperationEnvelope) string {
	switch env.GetOpType() {
	case OpThreatRecord:
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) == nil {
			if _, err := scope.Parse(tr.GetScope()); err == nil {
				return tr.GetScope()
			}
		}
	case OpRetraction:
		var r frienv1.Retraction
		if proto.Unmarshal(env.GetPayload(), &r) == nil {
			if target, ok := s.ops[r.GetTargetOpId()]; ok {
				return s.scopeOf(target)
			}
		}
	case OpCheckpoint:
		var cp frienv1.Checkpoint
		if proto.Unmarshal(env.GetPayload(), &cp) == nil {
			if _, err := scope.Parse(cp.GetScope()); err == nil {
				return cp.GetScope()
			}
		}
	}
	return scope.Scope{Kind: scope.Fleet}.String()
}

// indexScope records env under its scope, and remembers which scope it landed
// in (opScope) so a later removal does not need to recompute scopeOf -- which
// would give the wrong answer for a retraction once its target has itself
// already been removed. It also records env's scope_seq in scopeSeqIndex (see
// that field's doc comment) for the same reason recordSeq maintains seqIndex.
// It assumes the write lock is held.
func (s *OpSet) indexScope(env *frienv1.OperationEnvelope) {
	sc := s.scopeOf(env)
	set := s.scopeIndex[sc]
	if set == nil {
		set = make(map[string]struct{})
		s.scopeIndex[sc] = set
	}
	set[env.GetOpId()] = struct{}{}
	s.opScope[env.GetOpId()] = sc

	byNode := s.scopeSeqIndex[sc]
	if byNode == nil {
		byNode = make(map[string]map[uint64]string)
		s.scopeSeqIndex[sc] = byNode
	}
	byScopeSeq := byNode[env.GetNodeId()]
	if byScopeSeq == nil {
		byScopeSeq = make(map[uint64]string)
		byNode[env.GetNodeId()] = byScopeSeq
	}
	if _, ok := byScopeSeq[env.GetScopeSeq()]; !ok {
		byScopeSeq[env.GetScopeSeq()] = env.GetOpId()
	}
}

// unindexScope removes id from the live per-scope set. opScope itself is kept
// forever as a tombstone alongside seqIndex: LastOpIDInScope needs it to
// resolve which scope a compacted (now-gone) op belonged to when scanning a
// node's global seq history, and parentsSatisfied needs it (via the
// compacted set) to recognize a parent that was legitimately compacted away
// rather than never seen. scopeSeqIndex, not opScope, is what lets
// ScopeState's contiguous watermark see through a compacted region -- it is
// never touched here, by design (see CompactBelow). It assumes the write
// lock is held.
func (s *OpSet) unindexScope(id string) {
	if sc, ok := s.opScope[id]; ok {
		delete(s.scopeIndex[sc], id)
	}
}

// Scopes lists the scope keys currently present in the set.
func (s *OpSet) Scopes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.scopeIndex))
	for sc := range s.scopeIndex {
		out = append(out, sc)
	}
	sort.Strings(out)
	return out
}

// OpIDsInScope returns the sorted op_ids held for a scope.
func (s *OpSet) OpIDsInScope(scopeKey string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sortedIDs(scopeKey)
}

// ScopeDigest returns the per-scope root hash and count.
func (s *OpSet) ScopeDigest(scopeKey string) Digest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.sortedIDs(scopeKey)
	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(s.ops[id].GetPayloadHash()))
		h.Write([]byte{0})
	}
	return Digest{Scope: scopeKey, Root: hex.EncodeToString(h.Sum(nil)), Count: len(ids)}
}

func (s *OpSet) sortedIDs(scopeKey string) []string {
	set := s.scopeIndex[scopeKey]
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
