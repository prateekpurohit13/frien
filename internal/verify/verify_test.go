package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func signedEnv(t *testing.T, signer *identity.Ed25519Signer, nodeID, signedBy string) *frienv1.OperationEnvelope {
	t.Helper()
	env := &frienv1.OperationEnvelope{
		ProtoVersion: 1, OpId: "op1", OpType: "threat_record", NodeId: nodeID,
		Hlc: "1-0-" + nodeID, Seq: 1, PayloadHash: "sha256:x", SignedBy: signedBy,
		KeyId: signer.PublicKeyID(),
	}
	msg := identity.CanonicalSignedContent(env.ProtoVersion, env.OpId, env.OpType, env.NodeId, env.Hlc, env.Seq, env.ScopeSeq, env.Parents, env.PayloadHash, env.SignedBy)
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	return env
}

func TestVerifyAcceptsCorrectlySignedNodeEnvelope(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := identity.NewEd25519Signer(priv)

	keys := NewKeyStore()
	keys.RegisterNode("node.a", signer.PublicKey())

	env := signedEnv(t, signer, "node.a", "node")
	if err := NewVerifier(keys).Verify(env); err != nil {
		t.Fatalf("correctly signed envelope should verify, got %v", err)
	}
}

func TestVerifyRejectsUnknownSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := identity.NewEd25519Signer(priv)

	env := signedEnv(t, signer, "node.a", "node")
	if err := NewVerifier(NewKeyStore()).Verify(env); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("unknown signer should be ErrUnknownSigner, got %v", err)
	}
}

func TestVerifyRejectsTamperedPayloadHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := identity.NewEd25519Signer(priv)
	keys := NewKeyStore()
	keys.RegisterNode("node.a", signer.PublicKey())

	env := signedEnv(t, signer, "node.a", "node")
	env.PayloadHash = "sha256:tampered" // changed after signing
	if err := NewVerifier(keys).Verify(env); err == nil {
		t.Fatal("tampered payload hash should fail verification")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := identity.NewEd25519Signer(priv)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub := identity.NewEd25519Signer(otherPriv).PublicKey()

	keys := NewKeyStore()
	keys.RegisterNode("node.a", otherPub) // wrong key registered for node.a

	env := signedEnv(t, signer, "node.a", "node")
	if err := NewVerifier(keys).Verify(env); err == nil {
		t.Fatal("signature from an unregistered key should fail verification")
	}
}

func TestVerifyOperatorSignedUsesOperatorKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	opSigner := identity.NewEd25519Signer(priv)

	keys := NewKeyStore()
	keys.SetOperatorKey(opSigner.PublicKey())

	env := signedEnv(t, opSigner, "node.a", "operator")
	if err := NewVerifier(keys).Verify(env); err != nil {
		t.Fatalf("operator-signed envelope should verify against the operator key, got %v", err)
	}
}

func TestVerifyOperatorSignedWithoutPinnedKeyIsUnknownSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	opSigner := identity.NewEd25519Signer(priv)

	env := signedEnv(t, opSigner, "node.a", "operator")
	if err := NewVerifier(NewKeyStore()).Verify(env); !errors.Is(err, ErrUnknownSigner) {
		t.Fatalf("no pinned operator key should be ErrUnknownSigner, got %v", err)
	}
}

func TestRegisterAndReadTier(t *testing.T) {
	keys := NewKeyStore()
	// Unknown node defaults to the conservative tier.
	if got := keys.TierFor("node.x"); got != "standard" {
		t.Fatalf("unknown node tier = %q, want standard", got)
	}
	keys.RegisterTier("node.x", "high")
	if got := keys.TierFor("node.x"); got != "high" {
		t.Fatalf("registered tier = %q, want high", got)
	}
	// Empty tier is ignored (does not overwrite).
	keys.RegisterTier("node.x", "")
	if got := keys.TierFor("node.x"); got != "high" {
		t.Fatalf("empty tier overwrote existing: %q", got)
	}
}

func TestRegisterNodeIgnoresEmptyKey(t *testing.T) {
	keys := NewKeyStore()
	keys.RegisterNode("node.a", nil)
	if _, ok := keys.NodeKey("node.a"); ok {
		t.Fatal("registering a nil key should not create an entry")
	}
}

func TestRegisterNodeOverwritesOnRotation(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	pub1 := identity.NewEd25519Signer(priv1).PublicKey()
	pub2 := identity.NewEd25519Signer(priv2).PublicKey()

	keys := NewKeyStore()
	keys.RegisterNode("node.a", pub1)
	keys.RegisterNode("node.a", pub2)

	got, _ := keys.NodeKey("node.a")
	if !got.Equal(pub2) {
		t.Fatal("a later registration should overwrite the prior key (rotation)")
	}
}
