package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/revocation"
	"github.com/prateekpurohit13/frien/internal/verify"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// TestSignedRevocationVerifiesEndToEnd is the real-world proof this whole
// offline-signing path exists for: a revocation signed with only the
// operator private key (never a node key) must (a) verify at the envelope
// level against internal/verify.Verifier exactly like a peer-gossiped op
// would, and (b) verify at the payload level against
// internal/revocation.Verify, independent of the envelope check. Both are
// checked in production (gossip.Engine.ingest then applyRevocation).
func TestSignedRevocationVerifiesEndToEnd(t *testing.T) {
	signer, err := identity.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}

	now := time.Now()
	rec, err := revocation.Build("node.compromised", "aa:bb:cc", "key leaked", revocation.StatusTainted, signer, now)
	if err != nil {
		t.Fatalf("build revocation record: %v", err)
	}
	payload, err := proto.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	env, err := signOperatorEnvelope("revocation", payload, signer, now)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	if env.GetSignedBy() != "operator" {
		t.Fatalf("signed_by = %q, want operator", env.GetSignedBy())
	}

	// Envelope-level verification, as gossip.Engine.ingest performs it.
	keys := verify.NewKeyStore()
	keys.SetOperatorKey(signer.PublicKey())
	if err := verify.NewVerifier(keys).Verify(env); err != nil {
		t.Fatalf("envelope should verify against the operator key, got %v", err)
	}

	// Payload-level verification, as applyRevocation performs on the inner record.
	var gotRec frienv1.RevocationRecord
	if err := proto.Unmarshal(env.GetPayload(), &gotRec); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := revocation.Verify(&gotRec, signer.PublicKey()); err != nil {
		t.Fatalf("revocation record should verify, got %v", err)
	}
	if gotRec.GetNodeId() != "node.compromised" {
		t.Fatalf("node_id = %q, want node.compromised", gotRec.GetNodeId())
	}
}

// TestSignedEnvelopeRejectsTamperedPayload proves the envelope signature
// actually covers the payload -- a bit-flipped payload must fail
// verification, not just fail a downstream semantic check.
func TestSignedEnvelopeRejectsTamperedPayload(t *testing.T) {
	signer, err := identity.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	env, err := signOperatorEnvelope("revocation", []byte("original"), signer, time.Now())
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	env.Payload = []byte("tampered")
	env.PayloadHash = "sha256:deadbeef"

	keys := verify.NewKeyStore()
	keys.SetOperatorKey(signer.PublicKey())
	if err := verify.NewVerifier(keys).Verify(env); err == nil {
		t.Fatal("a tampered payload should fail envelope verification")
	}
}

// TestRevokeSignThenDecodeRoundTrips exercises the actual file path
// `revoke sign` writes and `revoke submit` reads: base64-encoded serialized
// bytes on disk.
func TestRevokeSignThenDecodeRoundTrips(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "operator.key")
	outPath := filepath.Join(dir, "revocation.env")

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	signer := identity.NewEd25519Signer(priv)

	err = cmdRevokeSign([]string{
		"--node-id", "node.bad",
		"--fingerprint", "11:22:33",
		"--reason", "test",
		"--key", keyPath,
		"--out", outPath,
	})
	if err != nil {
		t.Fatalf("revoke sign: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	env, err := decodeEnvelope(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.GetOpType() != "revocation" || env.GetSignedBy() != "operator" {
		t.Fatalf("envelope = %+v", env)
	}

	keys := verify.NewKeyStore()
	keys.SetOperatorKey(signer.PublicKey())
	if err := verify.NewVerifier(keys).Verify(env); err != nil {
		t.Fatalf("round-tripped envelope should verify, got %v", err)
	}
}
