package crdt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// ErrScopeFull is returned by AddWithLimit when admitting a new op would push its
// scope past the configured cap. It is a memory bound against a peer flooding a
// scope, not a correctness signal; duplicates and replays are never rejected.
var ErrScopeFull = errors.New("crdt: scope at capacity")

const (
	OpThreatRecord        = "threat_record"
	OpEnforcementDecision = "enforcement_decision"
	OpRetraction          = "retraction"
	OpCheckpoint          = "checkpoint"
	OpRevocation          = "revocation"
	OpPolicy              = "policy"
)

// AddResult reports the outcome of admitting an op into the set.
type AddResult struct {
	Added        bool
	Duplicate    bool                      // op_id already present; idempotent no-op
	Buffered     bool                      // parked awaiting an unseen parent; see dag.go
	Equivocation *frienv1.MisbehaviorProof // set when this op forks an existing (node_id, seq)
}

// OpSet is the replicated state: a grow-only set of immutable signed operation
// envelopes keyed by op_id. Merge is set-union, which is commutative,
// associative, and idempotent, so the set is a join-semilattice and converges
// without coordination. Expiry, retraction, and quorum are projections over the
// set (see project.go), not part of the merge.
type OpSet struct {
	mu          sync.RWMutex
	ops         map[string]*frienv1.OperationEnvelope
	seqIndex    map[string]map[uint64]string   // node_id -> seq -> first op_id ever seen (kept forever, see CompactBelow)
	scopeIndex  map[string]map[string]struct{} // scope key -> set of op_id
	opScope     map[string]string              // op_id -> the scope key it was indexed under
	equivocated map[string]struct{}            // op_id -> present if it is part of a detected fork; never compacted
	compacted   map[string]struct{}            // op_id -> present if removed by CompactBelow (kept forever, see dag.go)

	pendingByParent map[string][]*frienv1.OperationEnvelope // parent op_id -> envelopes waiting on it (see dag.go)
	pendingCount    int
}

func NewOpSet() *OpSet {
	return &OpSet{
		ops:         make(map[string]*frienv1.OperationEnvelope),
		seqIndex:    make(map[string]map[uint64]string),
		scopeIndex:  make(map[string]map[string]struct{}),
		opScope:     make(map[string]string),
		equivocated: make(map[string]struct{}),
		compacted:   make(map[string]struct{}),
	}
}

// Add admits one envelope with no scope cap. See AddWithLimit.
func (s *OpSet) Add(env *frienv1.OperationEnvelope) (AddResult, error) {
	return s.AddWithLimit(env, 0)
}

// AddWithLimit admits one envelope, refusing a brand-new op that would push its
// scope past maxPerScope (0 = unlimited). The duplicate check, cap check, and
// insert are one atomic step under the set lock, so concurrent adds cannot race
// past the cap. Re-adding a known op_id is an idempotent no-op; an op that reuses
// an existing (node_id, seq) with a different op_id is equivocation, still stored
// so the evidence is preserved and a proof returned.
func (s *OpSet) AddWithLimit(env *frienv1.OperationEnvelope, maxPerScope int) (AddResult, error) {
	res, _, err := s.addWithLimitAndDrain(env, maxPerScope)
	return res, err
}

// AddWithLimitAndDrain behaves like AddWithLimit but also returns any
// envelopes that were themselves unblocked and admitted as a side effect of
// this call (buffered earlier awaiting env as a parent, see dag.go). Callers
// that must run per-admission side effects for every op that actually enters
// the set -- gossip.Engine.ingest applying a revocation or recording a
// watermark -- need these: a drain-admitted op is inserted deep inside this
// call, not the one that originally buffered it, so it never surfaces
// otherwise.
func (s *OpSet) AddWithLimitAndDrain(env *frienv1.OperationEnvelope, maxPerScope int) (AddResult, []DrainResult, error) {
	return s.addWithLimitAndDrain(env, maxPerScope)
}

func (s *OpSet) addWithLimitAndDrain(env *frienv1.OperationEnvelope, maxPerScope int) (AddResult, []DrainResult, error) {
	if env == nil {
		return AddResult{}, nil, fmt.Errorf("crdt: nil envelope")
	}
	if env.GetOpId() == "" {
		return AddResult{}, nil, fmt.Errorf("crdt: envelope missing op_id")
	}
	if env.GetNodeId() == "" {
		return AddResult{}, nil, fmt.Errorf("crdt: envelope %s missing node_id", env.GetOpId())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.addLocked(env, maxPerScope)
	var drained []DrainResult
	if err == nil && res.Added {
		drained = s.drainPending(env.GetOpId(), maxPerScope)
	}
	return res, drained, err
}

// addLocked performs one admission attempt. It assumes the caller holds the
// write lock. Callers are addLocked itself (via drainPending, recursively
// unblocking a chain of parent-waiting envelopes) and AddWithLimit.
func (s *OpSet) addLocked(env *frienv1.OperationEnvelope, maxPerScope int) (AddResult, error) {
	if _, ok := s.ops[env.GetOpId()]; ok {
		return AddResult{Duplicate: true}, nil
	}
	// A replay of an op_id already recorded at this (node_id, seq) -- even one
	// since compacted out of ops -- is an idempotent no-op. seqIndex is kept
	// forever precisely so this case is distinguishable from equivocation:
	// without it, a compacted op replayed by a slow peer would look like a
	// brand-new admission and grow the set right back (a resurrection bug).
	if bySeq := s.seqIndex[env.GetNodeId()]; bySeq != nil {
		if prevID, ok := bySeq[env.GetSeq()]; ok && prevID == env.GetOpId() {
			return AddResult{Duplicate: true}, nil
		}
	}
	if maxPerScope > 0 && len(s.scopeIndex[s.scopeOf(env)]) >= maxPerScope {
		return AddResult{}, ErrScopeFull
	}
	// A causal parent this replica has never seen and never compacted means
	// the op's history can't yet be verified; park it rather than admitting
	// it blind. See maxPendingParents for the fail-open bound.
	if !s.parentsSatisfied(env) {
		if s.pendingCount < maxPendingParents {
			s.bufferPending(env)
			return AddResult{Buffered: true}, nil
		}
	}

	proof := s.detectEquivocation(env)
	s.ops[env.GetOpId()] = env
	s.recordSeq(env)
	s.indexScope(env)
	if proof != nil {
		// OpA is nil when the original half of the fork was already compacted
		// before this later conflicting op arrived; there is nothing left to
		// protect on that side, but the new op itself is protected.
		if proof.GetOpA() != nil {
			s.equivocated[proof.GetOpA().GetOpId()] = struct{}{}
		}
		s.equivocated[env.GetOpId()] = struct{}{}
	}
	return AddResult{Added: true, Equivocation: proof}, nil
}

// CompactBelow removes the bulky envelope and scope-index entry for any op in
// scopeKey whose (node_id, seq) is at or below cuts[node_id], freeing the
// memory a long-lived or high-churn mesh would otherwise hold forever. An
// origin absent from cuts is left entirely untouched -- no safe cut is known
// for it yet, which is the conservative default. It returns exactly the
// envelopes removed (sorted by op_id), so the caller can build a checkpoint's
// tree_head from precisely the ops a given cut retired, computed in the same
// locked pass rather than via a separate read that could race with a
// concurrent add.
//
// Filtering by scopeKey is load-bearing, not cosmetic: a node's seq counter
// is global across every scope it publishes into (see LastOpIDInScope), so
// two different scopes' cuts for the same origin are computed from disjoint
// evidence -- a zone's SafeFloor is only ever confirmed by that zone's own
// peers, never by the wider fleet. Without the scope filter, compacting past
// a zone-confirmed cut would also delete that same origin's *fleet*-scoped
// ops sharing the low end of its seq range, even though no fleet peer ever
// confirmed holding them -- a real resurrection/data-loss vector once more
// than one scope is ever compacted for the same origin (see
// internal/checkpoint's Compactor, which now compacts a zone alongside
// fleet).
//
// Two things are deliberately never removed:
//   - seqIndex entries (node_id -> seq -> op_id), which stay forever as a tiny
//     tombstone. Without them, a later op forging the same (node_id, seq)
//     after its original was compacted would look like a first sighting
//     instead of equivocation, silently losing the ability to detect it.
//   - ops flagged in equivocated, so misbehavior evidence survives compaction
//     for audit and revocation even once its seq is below the safe cut.
//
// The caller (internal/checkpoint) is responsible for only ever advancing
// cuts to a value every currently-live peer that replicates scopeKey has
// itself acknowledged holding; CompactBelow performs no such check itself,
// trusting its input.
func (s *OpSet) CompactBelow(scopeKey string, cuts map[string]uint64) []*frienv1.OperationEnvelope {
	s.mu.Lock()
	defer s.mu.Unlock()

	var removed []*frienv1.OperationEnvelope
	for id := range s.scopeIndex[scopeKey] {
		env := s.ops[id]
		if env == nil {
			continue
		}
		cut, ok := cuts[env.GetNodeId()]
		if !ok || env.GetSeq() > cut {
			continue
		}
		if _, protected := s.equivocated[id]; protected {
			continue
		}
		delete(s.ops, id)
		s.unindexScope(id)
		s.compacted[id] = struct{}{}
		removed = append(removed, env)
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].GetOpId() < removed[j].GetOpId() })
	return removed
}

// Merge unions other into s and returns any equivocation proofs surfaced during
// the merge. Union of immutable ops makes merge idempotent, so a dropped or
// duplicated delta is harmless.
func (s *OpSet) Merge(other *OpSet) []*frienv1.MisbehaviorProof {
	var proofs []*frienv1.MisbehaviorProof
	for _, env := range other.Snapshot() {
		res, err := s.Add(env)
		if err == nil && res.Equivocation != nil {
			proofs = append(proofs, res.Equivocation)
		}
	}
	return proofs
}

// Snapshot returns the envelopes in the set, sorted by op_id for determinism.
func (s *OpSet) Snapshot() []*frienv1.OperationEnvelope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*frienv1.OperationEnvelope, 0, len(s.ops))
	for _, env := range s.ops {
		out = append(out, env)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetOpId() < out[j].GetOpId() })
	return out
}

func (s *OpSet) Get(opID string) (*frienv1.OperationEnvelope, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	env, ok := s.ops[opID]
	return env, ok
}

func (s *OpSet) Has(opID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ops[opID]
	return ok
}

func (s *OpSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ops)
}

// CanonicalHash is an order-independent, content-sensitive digest of the set,
// used to compare convergence between replicas and as the per-set Merkle input.
func (s *OpSet) CanonicalHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.ops))
	for id := range s.ops {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	h := sha256.New()
	for _, id := range ids {
		h.Write([]byte(id))
		h.Write([]byte{0})
		h.Write([]byte(s.ops[id].GetPayloadHash()))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
