// Package revocation implements two-phase identity revocation: a fast
// "tainted" signal that a node is suspected compromised, followed by a
// formal "revoked" state once the mesh has propagated it. Tainting alone does
// not disconnect existing sessions -- it only stops the node from counting as
// a fresh quorum contributor -- but a revocation both blocks new mTLS
// handshakes (via the transport RevocationChecker seam) and actively drops
// any session already open with that peer.
//
// Both states are monotonic and revocation always implies taint: a node
// cannot be un-tainted or un-revoked by this package. Reinstating a node is
// an operator action outside this package's scope (a fresh identity/cert, not
// a state flip here).
package revocation

import (
	"fmt"
	"sync"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

const (
	StatusTainted = "tainted"
	StatusRevoked = "revoked"
)

// Set tracks the mesh's revocation state, derived from ingested
// RevocationRecord ops. It implements transport.RevocationChecker.
type Set struct {
	mu           sync.RWMutex
	tainted      map[string]struct{} // cert_fingerprint -> present
	revoked      map[string]struct{} // cert_fingerprint -> present
	nodeByFinger map[string]string   // cert_fingerprint -> node_id, for session teardown
}

func NewSet() *Set {
	return &Set{
		tainted:      make(map[string]struct{}),
		revoked:      make(map[string]struct{}),
		nodeByFinger: make(map[string]string),
	}
}

// ApplyResult reports what changed when a record was applied.
type ApplyResult struct {
	NewlyTainted bool
	NewlyRevoked bool // set only when this record is the one that first revoked the node
	NodeID       string
}

// Apply admits one RevocationRecord. The caller is responsible for having
// already cryptographically verified the record (both the envelope-level
// signature via internal/verify against the pinned operator key, and
// optionally the record's own embedded signature via Verify) before calling
// Apply: this method trusts its input completely and only enforces the
// monotonic state machine.
func (s *Set) Apply(rec *frienv1.RevocationRecord) (ApplyResult, error) {
	if rec == nil {
		return ApplyResult{}, fmt.Errorf("revocation: nil record")
	}
	if rec.GetSignedBy() != "operator" {
		return ApplyResult{}, fmt.Errorf("revocation: record must be signed_by operator, got %q", rec.GetSignedBy())
	}
	fp := rec.GetCertFingerprint()
	if fp == "" {
		return ApplyResult{}, fmt.Errorf("revocation: record missing cert_fingerprint")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res := ApplyResult{NodeID: rec.GetNodeId()}
	if rec.GetNodeId() != "" {
		s.nodeByFinger[fp] = rec.GetNodeId()
	}

	if _, ok := s.tainted[fp]; !ok {
		s.tainted[fp] = struct{}{}
		res.NewlyTainted = true
	}

	switch rec.GetStatus() {
	case StatusRevoked:
		if _, ok := s.revoked[fp]; !ok {
			s.revoked[fp] = struct{}{}
			res.NewlyRevoked = true
		}
	case StatusTainted, "":
		// Tainting is the default/lesser state; an empty status is treated as
		// taint-only rather than rejected, since a record that reaches Apply
		// has already passed its cryptographic checks and a stricter status
		// value is not itself a trust decision.
	default:
		return ApplyResult{}, fmt.Errorf("revocation: unknown status %q", rec.GetStatus())
	}
	return res, nil
}

// IsRevoked reports whether fingerprint has been formally revoked. This is
// the transport.RevocationChecker contract: a revoked fingerprint is
// rejected at the mTLS handshake before it can carry any traffic.
func (s *Set) IsRevoked(fingerprint string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[fingerprint]
	return ok
}

// IsTainted reports whether fingerprint has been flagged as suspected
// compromised, whether or not it has since been formally revoked.
func (s *Set) IsTainted(fingerprint string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tainted[fingerprint]
	return ok
}

// IsNodeExcluded reports whether any fingerprint associated with nodeID has
// been tainted (or revoked, which implies taint). This is the quorum-eligibility
// query: a tainted/revoked node does not count as a fresh quorum contributor
// (docs/FRIEN_ARCHITECTURE.md §8.1). It is keyed by node id rather than
// fingerprint because the policy layer counts contributions by origin identity.
func (s *Set) IsNodeExcluded(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for fp, n := range s.nodeByFinger {
		if n != nodeID {
			continue
		}
		if _, ok := s.tainted[fp]; ok {
			return true
		}
	}
	return false
}

// NodeIDFor returns the node id last associated with fingerprint, if any, so
// a caller can also drop an already-open session for a newly revoked peer.
func (s *Set) NodeIDFor(fingerprint string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.nodeByFinger[fingerprint]
	return id, ok
}
