package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	AlgorithmEd25519 = "ed25519"
	AlgorithmMLDSA65 = "ml-dsa-65"
)

// Signer produces signatures over canonical envelope content.
// Each implementation signs the bytes produced by CanonicalSignedContent.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Algorithm() string
	PublicKeyID() string
}

// ─── ed25519 ──────────────────────────────────────────────────────────────────

// Ed25519Signer signs using ed25519. This is the classical baseline that is
// always present in every signed envelope.
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// NewEd25519SignerFromFile loads an ed25519 private key from a PEM file.
// The PEM type must be "PRIVATE KEY" or "ED25519 PRIVATE KEY".
func NewEd25519SignerFromFile(path string) (*Ed25519Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ed25519 key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if len(block.Bytes) < ed25519.PrivateKeySize {
		return nil, fmt.Errorf("PEM block too short for ed25519 private key in %s", path)
	}
	// Raw 64-byte ed25519 private key (seed || public key)
	priv := ed25519.PrivateKey(block.Bytes[len(block.Bytes)-ed25519.PrivateKeySize:])
	return NewEd25519Signer(priv), nil
}

// NewEd25519Signer wraps an existing ed25519.PrivateKey.
func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{
		privateKey: priv,
		keyID:      "ed25519:" + keyFingerprint(pub),
	}
}

// GenerateEd25519Signer generates a fresh ed25519 key pair (for testing / bootstrap).
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewEd25519Signer(priv), nil
}

func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, msg), nil
}

func (s *Ed25519Signer) Algorithm() string   { return AlgorithmEd25519 }
func (s *Ed25519Signer) PublicKeyID() string { return s.keyID }

// PublicKey returns the ed25519 public key for use in cert verification.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.privateKey.Public().(ed25519.PublicKey)
}

// ─── ML-DSA-65 (FIPS 204, via cloudflare/circl) ──────────────────────────────

// MLDSASigner signs using ML-DSA-65 (CRYSTALS-Dilithium security level 3).
// Signature size: 3309 bytes. Public key size: 1952 bytes.
//
// This implementation uses cloudflare/circl. When Go stdlib ships ML-DSA
// (expected ~Go 1.27/1.28), replace the circl calls with stdlib equivalents.
// The interface, HybridSigner, and all callers are unchanged.
type MLDSASigner struct {
	privateKey *mldsa65.PrivateKey
	publicKey  *mldsa65.PublicKey
	keyID      string
}

// NewMLDSASignerFromFile loads an ML-DSA-65 private key from a PEM file.
// PEM type must be "ML-DSA-65 PRIVATE KEY".
func NewMLDSASignerFromFile(path string) (*MLDSASigner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ml-dsa-65 key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	var priv mldsa65.PrivateKey
	if err := priv.UnmarshalBinary(block.Bytes); err != nil {
		return nil, fmt.Errorf("parsing ml-dsa-65 private key: %w", err)
	}
	pub := priv.Public().(*mldsa65.PublicKey)
	pubBytes, _ := pub.MarshalBinary()
	return &MLDSASigner{
		privateKey: &priv,
		publicKey:  pub,
		keyID:      "ml-dsa-65:" + keyFingerprint(pubBytes),
	}, nil
}

func GenerateMLDSASigner() (*MLDSASigner, error) {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ml-dsa-65 key: %w", err)
	}
	pubBytes, _ := pub.MarshalBinary()
	return &MLDSASigner{
		privateKey: priv,
		publicKey:  pub,
		keyID:      "ml-dsa-65:" + keyFingerprint(pubBytes),
	}, nil
}

func (s *MLDSASigner) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(s.privateKey, msg, nil, false, sig)
	return sig, nil
}

func (s *MLDSASigner) Algorithm() string   { return AlgorithmMLDSA65 }
func (s *MLDSASigner) PublicKeyID() string { return s.keyID }

// PublicKey returns the ML-DSA-65 public key bytes for distribution.
func (s *MLDSASigner) PublicKeyBytes() []byte {
	b, _ := s.publicKey.MarshalBinary()
	return b
}

// ─── HybridSigner ─────────────────────────────────────────────────────────────
// HybridResult holds both signatures from a hybrid sign operation.
type HybridResult struct {
	KeyID        string
	Signature    []byte
	PQCAlgorithm string
	PQCKeyID     string
	PQCSignature []byte
}

// HybridSigner signs with both ed25519 and ML-DSA-65 simultaneously.
type HybridSigner struct {
	classical *Ed25519Signer
	pqc       *MLDSASigner
}

// NewHybridSigner creates a HybridSigner. pqc may be nil for classical-only operation.
func NewHybridSigner(classical *Ed25519Signer, pqc *MLDSASigner) *HybridSigner {
	return &HybridSigner{classical: classical, pqc: pqc}
}

func (h *HybridSigner) Sign(msg []byte) (*HybridResult, error) {
	clSig, err := h.classical.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("ed25519 sign: %w", err)
	}
	result := &HybridResult{
		KeyID:     h.classical.PublicKeyID(),
		Signature: clSig,
	}
	if h.pqc != nil {
		pqcSig, err := h.pqc.Sign(msg)
		if err != nil {
			return nil, fmt.Errorf("ml-dsa-65 sign: %w", err)
		}
		result.PQCAlgorithm = h.pqc.Algorithm()
		result.PQCKeyID = h.pqc.PublicKeyID()
		result.PQCSignature = pqcSig
	}
	return result, nil
}

func (h *HybridSigner) HasPQC() bool { return h.pqc != nil }
