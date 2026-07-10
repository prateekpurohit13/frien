// Package verify checks the classical signature on an operation envelope
// against the public key bound to its claimed signer before the envelope is
// trusted into local state. A node-signed envelope is checked against the
// node's key (learned opportunistically from its already CA-verified mTLS
// session, since the architecture binds the envelope-signing key to the same
// key in the node's leaf certificate); an operator-signed envelope is checked
// against the single pinned operator key.
//
// PQC (ML-DSA-65) verification is intentionally not performed here: PQC public
// keys are not yet distributed mesh-wide (see docs/task-checklist.md's Phase 2
// and Phase 7 PQC notes), so only the always-present classical signature is
// checked. A present pqc_signature field does not itself cause rejection or
// acceptance; this mirrors identity.Verify's own behavior when no PQC key is
// supplied.
package verify

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// ErrUnknownSigner means the envelope's claimed signer has no registered
// public key yet. This is an expected transient state, not necessarily
// malicious: an op relayed via anti-entropy may arrive before this node has
// directly connected to its origin. The caller should skip the op rather than
// treat it as fatal; anti-entropy naturally retries it once the key is known.
var ErrUnknownSigner = errors.New("verify: signer public key not yet known")

// KeyStore holds the classical public keys used to verify envelopes.
type KeyStore struct {
	mu       sync.RWMutex
	nodes    map[string]ed25519.PublicKey
	operator ed25519.PublicKey
}

func NewKeyStore() *KeyStore {
	return &KeyStore{nodes: make(map[string]ed25519.PublicKey)}
}

// RegisterNode records nodeID's classical public key, overwriting any prior
// key so a rotated certificate's new key takes over. A nil or empty key is
// ignored so a non-conforming peer certificate cannot poison the store.
func (k *KeyStore) RegisterNode(nodeID string, pub ed25519.PublicKey) {
	if len(pub) == 0 {
		return
	}
	k.mu.Lock()
	k.nodes[nodeID] = pub
	k.mu.Unlock()
}

// NodeKey returns nodeID's registered public key, if any.
func (k *KeyStore) NodeKey(nodeID string) (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	pub, ok := k.nodes[nodeID]
	return pub, ok
}

// SetOperatorKey pins the operator's public key, used to verify operator-signed
// control ops (revocations, policies).
func (k *KeyStore) SetOperatorKey(pub ed25519.PublicKey) {
	k.mu.Lock()
	k.operator = pub
	k.mu.Unlock()
}

// OperatorKey returns the pinned operator public key, if configured.
func (k *KeyStore) OperatorKey() (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.operator, len(k.operator) > 0
}

// Verifier checks operation envelopes against a KeyStore.
type Verifier struct {
	keys *KeyStore
}

func NewVerifier(keys *KeyStore) *Verifier {
	return &Verifier{keys: keys}
}

// Verify checks env's classical signature over its canonical content against
// the public key bound to its claimed signer.
func (v *Verifier) Verify(env *frienv1.OperationEnvelope) error {
	if env == nil {
		return fmt.Errorf("verify: nil envelope")
	}

	var pub ed25519.PublicKey
	if env.GetSignedBy() == "operator" {
		p, ok := v.keys.OperatorKey()
		if !ok {
			return ErrUnknownSigner
		}
		pub = p
	} else {
		p, ok := v.keys.NodeKey(env.GetNodeId())
		if !ok {
			return ErrUnknownSigner
		}
		pub = p
	}

	msg := identity.CanonicalSignedContent(
		env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(),
		env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy(),
	)
	if _, err := identity.Verify(msg, env.GetKeyId(), env.GetSignature(), pub, "", nil, nil); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
