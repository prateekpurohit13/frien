package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/prateekpurohit13/frien/internal/identity"
)

// ALPNProto is the QUIC application-layer protocol token for the frien peer mesh.
// A peer that does not advertise it is not a frien node and the handshake fails.
const ALPNProto = "frien-mesh/1"

// KEMMode selects the TLS 1.3 key-exchange curve preference.
type KEMMode string

const (
	KEMHybridPQC KEMMode = "x25519mlkem768" // hybrid X25519 + ML-KEM-768 (FIPS 203); default
	KEMClassical KEMMode = "classical"      // X25519 only
)

// RevocationChecker reports whether a peer certificate fingerprint has been
// revoked. Transport consults it during the TLS handshake so a session from a
// revoked identity is dropped before it can carry any traffic (architecture
// Layer 1 + Layer 10). The revocation set itself is a Phase 4 control-plane
// object; until then the daemon passes a nil checker (nothing revoked).
type RevocationChecker interface {
	IsRevoked(fingerprint string) bool
}

// tlsConfig builds the mutual-TLS configuration used by both the QUIC listener
// and dialer. Every peer presents the node certificate and must present one
// chaining to the mesh CA. Peers are identified by certificate CN (node id), not
// by DNS name — nodes dial each other by address — so hostname verification is
// replaced with explicit chain-plus-revocation verification in verifyPeer.
func tlsConfig(id *identity.Identity, caPool *x509.CertPool, kem KEMMode, rc RevocationChecker) (*tls.Config, error) {
	if id == nil {
		return nil, fmt.Errorf("transport: identity is required")
	}
	if caPool == nil {
		return nil, fmt.Errorf("transport: CA pool is required for peer verification")
	}
	curves, err := curvePreferences(kem)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{id.TLSCert},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caPool,
		RootCAs:          caPool,
		CurvePreferences: curves,
		NextProtos:       []string{ALPNProto},
		// Hostname verification is meaningless for a CN-identified mesh peer, so
		// disable the default check and verify the chain ourselves in verifyPeer.
		// This applies to the dialer role; the listener role verifies via ClientCAs.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeer(caPool, rc),
	}, nil
}

// verifyPeer verifies a peer certificate chain against the mesh CA without a
// DNS-name check and rejects revoked fingerprints. It runs on both roles: for
// the dialer it is the sole verification (InsecureSkipVerify bypasses the
// default), and for the listener it runs in addition to ClientCAs verification.
func verifyPeer(caPool *x509.CertPool, rc RevocationChecker) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("transport: peer presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("transport: parsing peer leaf certificate: %w", err)
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			ic, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("transport: parsing peer intermediate certificate: %w", err)
			}
			intermediates.AddCert(ic)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool, Intermediates: intermediates}); err != nil {
			return fmt.Errorf("transport: peer certificate not trusted: %w", err)
		}
		if rc != nil && rc.IsRevoked(identity.CertFingerprint(leaf)) {
			return fmt.Errorf("transport: peer certificate is revoked")
		}
		return nil
	}
}

func curvePreferences(kem KEMMode) ([]tls.CurveID, error) {
	switch kem {
	case KEMHybridPQC, "":
		return []tls.CurveID{tls.X25519MLKEM768, tls.X25519}, nil
	case KEMClassical:
		return []tls.CurveID{tls.X25519}, nil
	default:
		return nil, fmt.Errorf("transport: unknown pqc_kem %q", kem)
	}
}
