package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func newTestSigner(t *testing.T) *identity.Ed25519Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return identity.NewEd25519Signer(priv)
}

func TestBuildProducesVerifiableCheckpoint(t *testing.T) {
	signer := newTestSigner(t)
	cp, err := Build("", "tree-hash", "2026-01-01T00:00:00Z", "state-hash", "fleet", signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cp.GetCheckpointId() == "" {
		t.Fatal("checkpoint should have a non-empty id")
	}
	if err := Verify(cp, signer.PublicKey()); err != nil {
		t.Fatalf("a freshly built checkpoint should verify, got %v", err)
	}
}

func TestVerifyRejectsTamperedField(t *testing.T) {
	signer := newTestSigner(t)
	cp, err := Build("", "tree-hash", "2026-01-01T00:00:00Z", "state-hash", "fleet", signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	cp.TreeHead = "tampered"
	if err := Verify(cp, signer.PublicKey()); err == nil {
		t.Fatal("a tampered checkpoint field should fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signer := newTestSigner(t)
	other := newTestSigner(t)
	cp, err := Build("", "tree-hash", "2026-01-01T00:00:00Z", "state-hash", "fleet", signer, time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := Verify(cp, other.PublicKey()); err == nil {
		t.Fatal("verifying against the wrong key should fail")
	}
}

func TestBuildChainsToPrevCheckpoint(t *testing.T) {
	signer := newTestSigner(t)
	first, _ := Build("", "t1", "hlc1", "s1", "fleet", signer, time.Now())
	second, err := Build(first.GetCheckpointId(), "t2", "hlc2", "s2", "fleet", signer, time.Now())
	if err != nil {
		t.Fatalf("build second: %v", err)
	}
	if second.GetPrevCheckpoint() != first.GetCheckpointId() {
		t.Fatalf("second checkpoint should chain to the first, got prev=%q", second.GetPrevCheckpoint())
	}
}

func TestTreeHeadForIsOrderSensitiveButDeterministic(t *testing.T) {
	envs := []*frienv1.OperationEnvelope{
		{OpId: "a", PayloadHash: "h1"},
		{OpId: "b", PayloadHash: "h2"},
	}
	h1 := treeHeadFor(envs)
	h2 := treeHeadFor(envs)
	if h1 != h2 {
		t.Fatal("treeHeadFor should be deterministic for the same input")
	}

	other := []*frienv1.OperationEnvelope{
		{OpId: "a", PayloadHash: "h1"},
		{OpId: "b", PayloadHash: "different"},
	}
	if treeHeadFor(other) == h1 {
		t.Fatal("a different payload hash should change the tree head")
	}
}
