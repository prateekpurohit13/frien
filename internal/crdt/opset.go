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
	Equivocation *frienv1.MisbehaviorProof // set when this op forks an existing (node_id, seq)
}

// OpSet is the replicated state: a grow-only set of immutable signed operation
// envelopes keyed by op_id. Merge is set-union, which is commutative,
// associative, and idempotent, so the set is a join-semilattice and converges
// without coordination. Expiry, retraction, and quorum are projections over the
// set (see project.go), not part of the merge.
type OpSet struct {
	mu         sync.RWMutex
	ops        map[string]*frienv1.OperationEnvelope
	seqIndex   map[string]map[uint64]string   // node_id -> seq -> first op_id seen
	scopeIndex map[string]map[string]struct{} // scope key -> set of op_id
}

func NewOpSet() *OpSet {
	return &OpSet{
		ops:        make(map[string]*frienv1.OperationEnvelope),
		seqIndex:   make(map[string]map[uint64]string),
		scopeIndex: make(map[string]map[string]struct{}),
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
	if env == nil {
		return AddResult{}, fmt.Errorf("crdt: nil envelope")
	}
	if env.GetOpId() == "" {
		return AddResult{}, fmt.Errorf("crdt: envelope missing op_id")
	}
	if env.GetNodeId() == "" {
		return AddResult{}, fmt.Errorf("crdt: envelope %s missing node_id", env.GetOpId())
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.ops[env.GetOpId()]; ok {
		return AddResult{Duplicate: true}, nil
	}
	if maxPerScope > 0 && len(s.scopeIndex[s.scopeOf(env)]) >= maxPerScope {
		return AddResult{}, ErrScopeFull
	}

	proof := s.detectEquivocation(env)
	s.ops[env.GetOpId()] = env
	s.recordSeq(env)
	s.indexScope(env)
	return AddResult{Added: true, Equivocation: proof}, nil
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
