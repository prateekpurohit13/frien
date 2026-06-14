package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// VerifyResult is returned by Verify and explains which algorithm was accepted.
type VerifyResult struct {
	Algorithm string
	Trusted   bool
}

// Verify checks a hybrid-signed OperationEnvelope against available algorithms.
//
// Policy (applied in order):
//  1. If PQC signature is present and we have the PQC public key → verify ML-DSA-65.
//     If it passes, return immediately (strongest available).
//     If it fails, reject — do NOT fall through to classical, because a valid
//     classical signature cannot make a broken PQC signature acceptable.
//  2. If no PQC signature is present → verify ed25519 only.
//
// This means:
//   - A node that cannot do PQC simply never sees pqc_signature fields it understands,
//     so it verifies ed25519 and accepts normally.
//   - A node that can do PQC verifies the PQC signature. A corrupted PQC sig is a
//     hard reject regardless of the classical sig, preventing downgrade attacks.
func Verify(
	canonicalMsg []byte,
	classicalKeyID string, classicalSig []byte, classicalPubKey ed25519.PublicKey,
	pqcAlgorithm string, pqcSig []byte, pqcPubKeyBytes []byte,
) (*VerifyResult, error) {
	if pqcAlgorithm == AlgorithmMLDSA65 && len(pqcSig) > 0 && len(pqcPubKeyBytes) > 0 {
		var pub mldsa65.PublicKey
		if err := pub.UnmarshalBinary(pqcPubKeyBytes); err != nil {
			return nil, fmt.Errorf("parsing ml-dsa-65 public key [%s]: %w", pqcAlgorithm, err)
		}
		if !mldsa65.Verify(&pub, canonicalMsg, nil, pqcSig) {
			return nil, fmt.Errorf("ml-dsa-65 signature invalid (key_id=%s)", pqcAlgorithm)
		}
		return &VerifyResult{Algorithm: AlgorithmMLDSA65, Trusted: true}, nil
	}

	if pqcAlgorithm != "" && pqcAlgorithm != AlgorithmMLDSA65 {
		return nil, fmt.Errorf("unsupported pqc_algorithm %q: update frien to support it", pqcAlgorithm)
	}
	if len(classicalPubKey) == 0 {
		return nil, fmt.Errorf("no public key available for verification (key_id=%s)", classicalKeyID)
	}
	if !ed25519.Verify(classicalPubKey, canonicalMsg, classicalSig) {
		return nil, fmt.Errorf("ed25519 signature invalid (key_id=%s)", classicalKeyID)
	}
	return &VerifyResult{Algorithm: AlgorithmEd25519, Trusted: true}, nil
}

// ─── Key registry ─────────────────────────────────────────────────────────────
// PeerPublicKeys holds the public keys for a single peer node.
// Classical key comes from the node's mTLS certificate.
// PQC key is distributed out-of-band (gossip, config, or key exchange message).
type PeerPublicKeys struct {
	Ed25519    ed25519.PublicKey
	MLDSAPub   []byte
}

// keyFingerprint returns a hex-encoded SHA-256 fingerprint of raw public key bytes.
func keyFingerprint(pubBytes []byte) string {
	h := sha256.Sum256(pubBytes)
	return hex.EncodeToString(h[:8])
}
