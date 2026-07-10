package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"time"
)

// Identity is the node's loaded cryptographic identity: its short-lived mTLS
// certificate plus the ed25519 key used to sign operation envelopes. Per the
// architecture, the envelope-signing key is the same key bound in the node's
// mTLS leaf certificate, so the cert fingerprint and the signer's key id refer
// to one identity.
//
// Certificates are deliberately short-lived (hours; see docs/security.md), so the
// daemon must watch NotAfter and renew before expiry. NeedsRenewal supports that
// loop; the renewal transport itself (CA call / SPIFFE) lands with the CA modes.
type Identity struct {
	NodeID      string
	Certificate *x509.Certificate // parsed leaf certificate
	TLSCert     tls.Certificate   // full chain + private key, for the TLS stack
	Fingerprint string            // "sha256:<hex>" over the leaf DER
	signer      *Ed25519Signer    // envelope signer derived from the leaf key
}

// LoadOptions configures certificate loading. It is a small struct rather than
// the full config.Config so the identity package stays decoupled from the
// daemon's configuration schema and is easy to construct in tests.
type LoadOptions struct {
	CertPath string // PEM node certificate (short-lived)
	KeyPath  string // PEM ed25519 private key matching the certificate
	// ExpectedNodeID, when non-empty, is required to equal the certificate CN.
	// This catches a config/cert mismatch at startup (docs/configuration.md
	// startup-validation rule #2) rather than letting a node assume a wrong identity.
	ExpectedNodeID string
}

// Load reads and validates the node certificate and key, derives the ed25519
// envelope signer from the leaf key, and computes the certificate fingerprint.
// It fails fast on any mismatch: a node must not run with an ambiguous identity.
func Load(opts LoadOptions) (*Identity, error) {
	if opts.CertPath == "" {
		return nil, fmt.Errorf("identity: cert_path is required")
	}
	if opts.KeyPath == "" {
		return nil, fmt.Errorf("identity: key_path is required")
	}

	tlsCert, err := tls.LoadX509KeyPair(opts.CertPath, opts.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("identity: loading cert/key pair: %w", err)
	}
	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("identity: no certificate found in %s", opts.CertPath)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("identity: parsing leaf certificate: %w", err)
	}
	tlsCert.Leaf = leaf

	// The node key that signs operation envelopes must be ed25519 (the classical
	// baseline of the hybrid scheme). Other key types can serve mTLS but cannot
	// drive envelope signing, so we reject them explicitly rather than silently.
	priv, ok := tlsCert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: node key must be ed25519, got %T", tlsCert.PrivateKey)
	}

	cn := leaf.Subject.CommonName
	if opts.ExpectedNodeID != "" && cn != opts.ExpectedNodeID {
		return nil, fmt.Errorf("identity: certificate CN %q does not match node.id %q", cn, opts.ExpectedNodeID)
	}
	nodeID := opts.ExpectedNodeID
	if nodeID == "" {
		nodeID = cn
	}

	id := &Identity{
		NodeID:      nodeID,
		Certificate: leaf,
		TLSCert:     tlsCert,
		Fingerprint: CertFingerprint(leaf),
		signer:      NewEd25519Signer(priv),
	}
	return id, nil
}

// Signer returns the ed25519 envelope signer for this identity.
func (i *Identity) Signer() *Ed25519Signer { return i.signer }

// NotAfter is the certificate expiry time.
func (i *Identity) NotAfter() time.Time { return i.Certificate.NotAfter }

// NeedsRenewal reports whether the certificate should be renewed now. It
// fires on whichever condition is met first:
//
//   - the configured threshold: a fixed safety-margin floor the certificate
//     must never be renewed later than (disabled by a non-positive threshold);
//   - roughly half the certificate's total lifetime remaining, jittered by a
//     small per-certificate offset (see jitterHalfLife) so a fleet of
//     certificates issued in lockstep with the same lifetime does not also
//     renew in lockstep against the CA. This trigger is always active
//     regardless of threshold.
func (i *Identity) NeedsRenewal(threshold time.Duration) bool {
	now := time.Now()
	if threshold > 0 && !now.Before(i.Certificate.NotAfter.Add(-threshold)) {
		return true
	}
	return !now.Before(i.jitteredHalfLifeRenewAt())
}

// jitterHalfLifeSpread bounds the jitter applied to the half-life renewal
// trigger to +/-10% of the half-life duration.
const jitterHalfLifeSpread = 0.1

func (i *Identity) jitteredHalfLifeRenewAt() time.Time {
	lifetime := i.Certificate.NotAfter.Sub(i.Certificate.NotBefore)
	if lifetime <= 0 {
		return i.Certificate.NotAfter
	}
	return i.Certificate.NotAfter.Add(-jitterHalfLife(lifetime/2, i.Fingerprint))
}

// jitterHalfLife scales halfLife by a factor in [1-jitterHalfLifeSpread,
// 1+jitterHalfLifeSpread), derived deterministically from a hash of
// fingerprint. Deriving the jitter from the certificate itself, rather than a
// fresh random draw, makes NeedsRenewal repeatable for a given certificate
// (no test flakiness, no re-triggering on every call with a new random value)
// while still varying across different certificates -- exactly the property
// needed to desynchronize a fleet whose certificates were all issued at once.
func jitterHalfLife(halfLife time.Duration, fingerprint string) time.Duration {
	sum := sha256.Sum256([]byte(fingerprint))
	frac := float64(binary.BigEndian.Uint32(sum[:4])) / float64(math.MaxUint32) // [0, 1)
	factor := (1 - jitterHalfLifeSpread) + 2*jitterHalfLifeSpread*frac          // [0.9, 1.1)
	return time.Duration(float64(halfLife) * factor)
}

// IsExpired reports whether the certificate is outside its validity window now.
func (i *Identity) IsExpired() bool {
	now := time.Now()
	return now.Before(i.Certificate.NotBefore) || now.After(i.Certificate.NotAfter)
}

// CertFingerprint returns the SHA-256 fingerprint of a certificate's DER bytes,
// formatted as "sha256:<hex>" to match the cert_fingerprint fields used across
// the data model (PeerState, RevocationRecord).
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LoadCACertPool loads a PEM bundle into an x509 pool for verifying peer or
// operator certificates. It fails if no certificate could be parsed, so a
// misconfigured or empty CA file is caught at startup rather than at first use.
func LoadCACertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: reading CA bundle %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("identity: no valid certificates in CA bundle %s", path)
	}
	return pool, nil
}

// LoadOperatorPublicKey reads the operator root certificate at path and returns
// its ed25519 public key, used to verify operator-signed control ops
// (revocations, policies) against a pinned key rather than a per-node one.
func LoadOperatorPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: reading operator root cert %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("identity: no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parsing operator root cert %s: %w", path, err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("identity: operator root cert %s key must be ed25519, got %T", path, cert.PublicKey)
	}
	return pub, nil
}
