package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testCACertPEM(t *testing.T, cn string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func poolHasSubject(pool *x509.CertPool, cn string, certPEM []byte) bool {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool})
	return err == nil
}

func TestTrustBundlePoolIsCurrentOnlyBeforePrepare(t *testing.T) {
	oldCA := testCACertPEM(t, "old-ca")
	b, err := NewTrustBundle(oldCA, time.Hour)
	if err != nil {
		t.Fatalf("new bundle: %v", err)
	}
	pool, err := b.Pool()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if !poolHasSubject(pool, "old-ca", oldCA) {
		t.Fatal("pool should trust the initial CA")
	}
	if b.InOverlap() {
		t.Fatal("should not be in overlap before PrepareNext")
	}
}

func TestTrustBundleUnionsDuringOverlap(t *testing.T) {
	oldCA := testCACertPEM(t, "old-ca")
	newCA := testCACertPEM(t, "new-ca")
	b, err := NewTrustBundle(oldCA, time.Hour)
	if err != nil {
		t.Fatalf("new bundle: %v", err)
	}
	if err := b.PrepareNext(newCA); err != nil {
		t.Fatalf("prepare next: %v", err)
	}
	if !b.InOverlap() {
		t.Fatal("should be in overlap immediately after PrepareNext")
	}
	pool, err := b.Pool()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if !poolHasSubject(pool, "old-ca", oldCA) {
		t.Fatal("overlap pool should still trust the old CA")
	}
	if !poolHasSubject(pool, "new-ca", newCA) {
		t.Fatal("overlap pool should trust the new CA")
	}
}

func TestTrustBundleCutsOverAfterWindow(t *testing.T) {
	oldCA := testCACertPEM(t, "old-ca")
	newCA := testCACertPEM(t, "new-ca")
	b, err := NewTrustBundle(oldCA, time.Minute)
	if err != nil {
		t.Fatalf("new bundle: %v", err)
	}
	now := time.Now()
	b.SetClock(func() time.Time { return now })

	if err := b.PrepareNext(newCA); err != nil {
		t.Fatalf("prepare next: %v", err)
	}
	now = now.Add(2 * time.Minute) // past the 1-minute window

	pool, err := b.Pool()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if poolHasSubject(pool, "old-ca", oldCA) {
		t.Fatal("old CA should have been retired once the overlap window elapsed")
	}
	if !poolHasSubject(pool, "new-ca", newCA) {
		t.Fatal("new CA should be trusted after cutover")
	}
	if b.InOverlap() {
		t.Fatal("should no longer report being in overlap after cutover")
	}
}

func TestTrustBundlePrepareNextRejectsMalformedPEM(t *testing.T) {
	oldCA := testCACertPEM(t, "old-ca")
	b, err := NewTrustBundle(oldCA, time.Hour)
	if err != nil {
		t.Fatalf("new bundle: %v", err)
	}
	if err := b.PrepareNext([]byte("not a cert")); err == nil {
		t.Fatal("malformed PEM should be rejected before staging")
	}
	if b.InOverlap() {
		t.Fatal("a rejected PrepareNext must not enter overlap")
	}
}
