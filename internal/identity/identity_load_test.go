package identity_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prateekpurohit13/frien/internal/identity"
)

// writeTestCert generates a self-signed certificate with the given CN and
// validity window, using the supplied key, and writes cert+key PEM files into
// dir. It returns their paths. signerKey may be ed25519 or another type, letting
// tests exercise the "node key must be ed25519" rejection path.
func writeTestCert(t *testing.T, dir, cn string, notBefore, notAfter time.Time, key any) (certPath, keyPath string) {
	t.Helper()

	var pub any
	switch k := key.(type) {
	case ed25519.PrivateKey:
		pub = k.Public()
	case *ecdsa.PrivateKey:
		pub = k.Public()
	default:
		t.Fatalf("unsupported test key type %T", key)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "node.crt")
	keyPath = filepath.Join(dir, "node.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestIdentity_Load_Valid(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	certPath, keyPath := writeTestCert(t, dir, "node.edge.eu-west.01",
		time.Now().Add(-time.Hour), time.Now().Add(8*time.Hour), priv)

	id, err := identity.Load(identity.LoadOptions{
		CertPath:       certPath,
		KeyPath:        keyPath,
		ExpectedNodeID: "node.edge.eu-west.01",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if id.NodeID != "node.edge.eu-west.01" {
		t.Errorf("node id = %q", id.NodeID)
	}
	if id.Signer() == nil {
		t.Error("signer must be derived from the leaf key")
	}
	if len(id.Fingerprint) <= len("sha256:") || id.Fingerprint[:7] != "sha256:" {
		t.Errorf("fingerprint format unexpected: %q", id.Fingerprint)
	}

	// The derived signer must actually sign with the certificate's key.
	msg := identity.CanonicalSignedContent(1, "op", "t", id.NodeID, "hlc", 1, nil, "ph", "node")
	sig, err := id.Signer().Sign(msg)
	if err != nil || len(sig) != 64 {
		t.Fatalf("signer.Sign: sig len %d err %v", len(sig), err)
	}
}

func TestIdentity_Load_CNMismatch_Rejected(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	certPath, keyPath := writeTestCert(t, dir, "node.actual",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), priv)

	_, err := identity.Load(identity.LoadOptions{
		CertPath:       certPath,
		KeyPath:        keyPath,
		ExpectedNodeID: "node.expected",
	})
	if err == nil {
		t.Fatal("CN/node.id mismatch must be rejected")
	}
}

func TestIdentity_Load_NonEd25519Key_Rejected(t *testing.T) {
	dir := t.TempDir()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPath, keyPath := writeTestCert(t, dir, "node.ec",
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), ecKey)

	_, err := identity.Load(identity.LoadOptions{CertPath: certPath, KeyPath: keyPath})
	if err == nil {
		t.Fatal("a non-ed25519 node key must be rejected for envelope signing")
	}
}

func TestIdentity_NeedsRenewal(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Cert expires in 30 minutes.
	certPath, keyPath := writeTestCert(t, dir, "node.soon",
		time.Now().Add(-time.Hour), time.Now().Add(30*time.Minute), priv)

	id, err := identity.Load(identity.LoadOptions{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if !id.NeedsRenewal(time.Hour) {
		t.Error("cert expiring in 30m should need renewal at a 1h threshold")
	}
	if id.NeedsRenewal(10 * time.Minute) {
		t.Error("cert expiring in 30m should NOT need renewal at a 10m threshold")
	}
	if id.NeedsRenewal(0) {
		t.Error("a non-positive threshold disables renewal")
	}
}

func TestIdentity_IsExpired(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Already expired.
	certPath, keyPath := writeTestCert(t, dir, "node.expired",
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), priv)

	id, err := identity.Load(identity.LoadOptions{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !id.IsExpired() {
		t.Error("expired certificate should report IsExpired() == true")
	}
}

func TestIdentity_Load_MissingFile(t *testing.T) {
	_, err := identity.Load(identity.LoadOptions{
		CertPath: "/nonexistent/node.crt",
		KeyPath:  "/nonexistent/node.key",
	})
	if err == nil {
		t.Fatal("loading a missing certificate must fail")
	}
}
