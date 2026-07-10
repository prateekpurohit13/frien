package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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

// NeedsRenewal reports whether the certificate expires within threshold from now
// (or is already expired). The renewal loop uses this to refresh short-lived certs
// before they lapse. A non-positive threshold disables renewal checks.
func (i *Identity) NeedsRenewal(threshold time.Duration) bool {
	if threshold <= 0 {
		return false
	}
	return time.Until(i.Certificate.NotAfter) <= threshold
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
