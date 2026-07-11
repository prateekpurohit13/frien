package crdt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// maxPendingParents bounds the total number of envelopes buffered awaiting an
// unseen parent, across all parents. It exists purely as a resource guard: a
// node that claims a parent this replica will never see (forged, or from a
// peer this replica doesn't gossip with) must not be able to grow unbounded
// local memory. When the buffer is full, addLocked fails open -- the op is
// admitted immediately without waiting for its parent -- rather than dropping
// it silently. Equivocation detection via the (node_id, seq) index is the
// primary safety net regardless; DAG parent verification is supplementary
// tamper-evidence for causal history, not the sole admission gate.
const maxPendingParents = 4096

// parentsSatisfied reports whether every parent env declares is either
// currently held or was compacted out of ops (and therefore tombstoned in
// compacted -- kept forever alongside seqIndex for exactly this check). A
// parent that is neither is not yet known to this replica. It assumes the
// caller holds the lock.
func (s *OpSet) parentsSatisfied(env *frienv1.OperationEnvelope) bool {
	for _, p := range env.GetParents() {
		if p == "" {
			continue
		}
		if _, ok := s.ops[p]; ok {
			continue
		}
		if _, ok := s.compacted[p]; ok {
			continue
		}
		return false
	}
	return true
}

// bufferPending parks env under each of its still-missing parents so it is
// retried once that parent arrives (see drainPending). It assumes the caller
// holds the lock.
func (s *OpSet) bufferPending(env *frienv1.OperationEnvelope) {
	if s.pendingCount >= maxPendingParents {
		return // caller falls back to admitting env directly; see maxPendingParents
	}
	for _, p := range env.GetParents() {
		if p == "" {
			continue
		}
		if _, ok := s.ops[p]; ok {
			continue
		}
		if _, ok := s.compacted[p]; ok {
			continue
		}
		if s.pendingByParent == nil {
			s.pendingByParent = make(map[string][]*frienv1.OperationEnvelope)
		}
		s.pendingByParent[p] = append(s.pendingByParent[p], env)
		s.pendingCount++
	}
}

// DrainResult reports one envelope admitted as a side effect of unblocking a
// parent it was waiting on, and any equivocation proof that admission
// surfaced. See AddWithLimitAndDrain.
type DrainResult struct {
	Env          *frienv1.OperationEnvelope
	Equivocation *frienv1.MisbehaviorProof
}

// drainPending retries every envelope waiting on newlyAvailable now that it is
// admitted (or tombstoned), recursively following the chain of anything those
// retries themselves unblock, and returns every envelope actually admitted
// along the way. It assumes the caller holds the lock.
func (s *OpSet) drainPending(newlyAvailable string, maxPerScope int) []DrainResult {
	var drained []DrainResult
	queue := []string{newlyAvailable}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		waiting := s.pendingByParent[id]
		if len(waiting) == 0 {
			continue
		}
		delete(s.pendingByParent, id)
		s.pendingCount -= len(waiting)
		for _, env := range waiting {
			if _, ok := s.ops[env.GetOpId()]; ok {
				continue // already admitted via another path (e.g. a duplicate delivery)
			}
			res, err := s.addLocked(env, maxPerScope)
			if err == nil && res.Added {
				drained = append(drained, DrainResult{Env: env, Equivocation: res.Equivocation})
				queue = append(queue, env.GetOpId())
			}
		}
	}
	return drained
}

// PendingCount reports how many envelopes are currently buffered awaiting a
// parent, for observability and tests.
func (s *OpSet) PendingCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingCount
}

// ChainRoot digests the node's known (seq -> op_id) chain, read from seqIndex
// so it stays stable across compaction (seqIndex tombstones are kept forever,
// see OpSet.CompactBelow). Two replicas with the same ChainRoot for nodeID
// have identical causal history for it regardless of how much either has
// locally compacted; a differing root is a cheap, op-list-free divergence
// signal, used to anchor anti-entropy's root-hash exchange above a shared
// checkpoint instead of re-hashing live envelope payloads every round.
func (s *OpSet) ChainRoot(nodeID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.chainRootLocked(nodeID)
}

func (s *OpSet) chainRootLocked(nodeID string) string {
	bySeq := s.seqIndex[nodeID]
	if len(bySeq) == 0 {
		return ""
	}
	seqs := make([]uint64, 0, len(bySeq))
	for sq := range bySeq {
		seqs = append(seqs, sq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	h := sha256.New()
	for _, sq := range seqs {
		fmt.Fprintf(h, "%d:", sq)
		h.Write([]byte(bySeq[sq]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// KnownOrigins lists the node_ids this replica has ever recorded an op for,
// sorted for determinism.
func (s *OpSet) KnownOrigins() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.seqIndex))
	for node := range s.seqIndex {
		out = append(out, node)
	}
	sort.Strings(out)
	return out
}

// LastOpIDInScope returns the op_id of nodeID's most recent op within
// scopeKey (by seq, descending), used by gossip.Engine.Publish to set a
// freshly published op's parent to the publishing node's own prior op in the
// *same* scope -- a self-chain giving every node's per-scope history
// tamper-evidence via ChainRoot, without requiring app-level causal
// dependency tracking between different nodes' ops.
//
// Chaining must stay within one scope: a node's seq counter is global across
// all scopes it publishes into, but scope membership determines who a peer
// legitimately receives an op from at all (see internal/scope.Router). If a
// fleet op's parent pointed at that node's immediately preceding op
// regardless of scope, an out-of-zone peer that (correctly) never receives a
// zone-scoped op would permanently be unable to satisfy a later fleet op
// chained through it -- parentsSatisfied would never see that parent, and the
// fleet op would sit buffered forever despite fleet ops being required to
// reach every node. Reads seqIndex/opScope, both kept forever (see
// OpSet.CompactBelow), so this still works once older ops in the chain have
// been compacted away.
func (s *OpSet) LastOpIDInScope(nodeID, scopeKey string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bySeq := s.seqIndex[nodeID]
	if len(bySeq) == 0 {
		return "", false
	}
	seqs := make([]uint64, 0, len(bySeq))
	for sq := range bySeq {
		seqs = append(seqs, sq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] > seqs[j] })
	for _, sq := range seqs {
		id := bySeq[sq]
		if s.opScope[id] == scopeKey {
			return id, true
		}
	}
	return "", false
}
