package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/prateekpurohit13/frien/internal/identity"
)

func newOperatorSigner(t *testing.T) *identity.Ed25519Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return identity.NewEd25519Signer(priv)
}

func TestBuildProducesVerifiableRecord(t *testing.T) {
	signer := newOperatorSigner(t)
	r, err := Build("node.evil", "sha256:abc", "key compromise", StatusRevoked, signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if r.GetId() == "" || r.GetSignedBy() != "operator" {
		t.Fatalf("record not fully populated: %+v", r)
	}
	if err := Verify(r, signer.PublicKey()); err != nil {
		t.Fatalf("a freshly built record should verify, got %v", err)
	}
}

func TestBuildRejectsInvalidStatus(t *testing.T) {
	signer := newOperatorSigner(t)
	if _, err := Build("node.evil", "sha256:abc", "reason", "bogus", signer, time.Now()); err == nil {
		t.Fatal("an invalid status should be rejected at build time")
	}
}

func TestVerifyRejectsTamperedRecord(t *testing.T) {
	signer := newOperatorSigner(t)
	r, err := Build("node.evil", "sha256:abc", "reason", StatusTainted, signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	r.CertFingerprint = "sha256:different"
	if err := Verify(r, signer.PublicKey()); err == nil {
		t.Fatal("a tampered record should fail verification")
	}
}

func TestVerifyRejectsWrongOperatorKey(t *testing.T) {
	signer := newOperatorSigner(t)
	other := newOperatorSigner(t)
	r, err := Build("node.evil", "sha256:abc", "reason", StatusTainted, signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := Verify(r, other.PublicKey()); err == nil {
		t.Fatal("verifying against the wrong operator key should fail")
	}
}
