package identity_test

import (
	"testing"

	"github.com/prateekpurohit13/frien/internal/identity"
)

// canonical returns a deterministic test message representing envelope content.
func canonical() []byte {
	return identity.CanonicalSignedContent(
		1, "op_01TEST", "threat_record", "node-sf",
		"2026-06-14T03:14:22.000Z-1-node-sf", 42,
		[]string{"sha256:abc", "sha256:def"},
		"sha256:payloadhash",
		"node",
	)
}

// ─── canonical encoding ───────────────────────────────────────────────────────

func TestCanonical_Deterministic(t *testing.T) {
	a := canonical()
	b := canonical()
	if string(a) != string(b) {
		t.Error("CanonicalSignedContent is not deterministic")
	}
}

func TestCanonical_DifferentFields_DifferentOutput(t *testing.T) {
	base := canonical()
	changed := identity.CanonicalSignedContent(
		1, "op_01OTHER", "threat_record", "node-sf",
		"2026-06-14T03:14:22.000Z-1-node-sf", 42,
		[]string{"sha256:abc", "sha256:def"},
		"sha256:payloadhash",
		"node",
	)
	if string(base) == string(changed) {
		t.Error("different op_id produced same canonical bytes")
	}
}

func TestCanonical_ParentOrderMatters(t *testing.T) {
	// Causal order must be preserved — reordering parents changes the canonical bytes.
	a := identity.CanonicalSignedContent(1, "op", "t", "n", "hlc", 1,
		[]string{"sha256:aaa", "sha256:bbb"}, "ph", "node")
	b := identity.CanonicalSignedContent(1, "op", "t", "n", "hlc", 1,
		[]string{"sha256:bbb", "sha256:aaa"}, "ph", "node")
	if string(a) == string(b) {
		t.Error("parent order should affect canonical bytes")
	}
}

// ─── ed25519 ──────────────────────────────────────────────────────────────────

func TestEd25519_SignVerify(t *testing.T) {
	signer, err := identity.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := canonical()
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("expected ed25519 sig length 64, got %d", len(sig))
	}
	result, err := identity.Verify(msg,
		signer.PublicKeyID(), sig, signer.PublicKey(),
		"", nil, nil,
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Algorithm != identity.AlgorithmEd25519 {
		t.Errorf("expected algorithm ed25519, got %s", result.Algorithm)
	}
}

func TestEd25519_TamperedMessage_Rejected(t *testing.T) {
	signer, _ := identity.GenerateEd25519Signer()
	msg := canonical()
	sig, _ := signer.Sign(msg)

	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[0] ^= 0xFF // flip bits in first byte

	_, err := identity.Verify(tampered, signer.PublicKeyID(), sig, signer.PublicKey(), "", nil, nil)
	if err == nil {
		t.Error("tampered message should not verify")
	}
}

func TestEd25519_TamperedSignature_Rejected(t *testing.T) {
	signer, _ := identity.GenerateEd25519Signer()
	msg := canonical()
	sig, _ := signer.Sign(msg)

	sig[0] ^= 0xFF // corrupt first byte of signature

	_, err := identity.Verify(msg, signer.PublicKeyID(), sig, signer.PublicKey(), "", nil, nil)
	if err == nil {
		t.Error("tampered signature should not verify")
	}
}

func TestEd25519_WrongKey_Rejected(t *testing.T) {
	signer1, _ := identity.GenerateEd25519Signer()
	signer2, _ := identity.GenerateEd25519Signer()
	msg := canonical()
	sig, _ := signer1.Sign(msg)

	// Verify with signer2's key — should fail
	_, err := identity.Verify(msg, signer2.PublicKeyID(), sig, signer2.PublicKey(), "", nil, nil)
	if err == nil {
		t.Error("signature from different key should not verify")
	}
}

// ─── ML-DSA-65 ───────────────────────────────────────────────────────────────

func TestMLDSA_SignVerify(t *testing.T) {
	signer, err := identity.GenerateMLDSASigner()
	if err != nil {
		t.Fatalf("generate ml-dsa-65: %v", err)
	}
	msg := canonical()
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// ML-DSA-65 signature is 3309 bytes
	if len(sig) == 0 {
		t.Error("empty ML-DSA-65 signature")
	}

	result, err := identity.Verify(msg,
		"classical-key-id", make([]byte, 64), nil, // classical fields unused when PQC present
		signer.Algorithm(), sig, signer.PublicKeyBytes(),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Algorithm != identity.AlgorithmMLDSA65 {
		t.Errorf("expected algorithm ml-dsa-65, got %s", result.Algorithm)
	}
}

func TestMLDSA_TamperedMessage_Rejected(t *testing.T) {
	signer, _ := identity.GenerateMLDSASigner()
	msg := canonical()
	sig, _ := signer.Sign(msg)

	tampered := make([]byte, len(msg))
	copy(tampered, msg)
	tampered[0] ^= 0xFF

	_, err := identity.Verify(tampered, "", nil, nil,
		signer.Algorithm(), sig, signer.PublicKeyBytes())
	if err == nil {
		t.Error("tampered message should not verify with ML-DSA-65")
	}
}

func TestMLDSA_TamperedSignature_Rejected(t *testing.T) {
	signer, _ := identity.GenerateMLDSASigner()
	msg := canonical()
	sig, _ := signer.Sign(msg)

	sig[0] ^= 0xFF

	_, err := identity.Verify(msg, "", nil, nil,
		signer.Algorithm(), sig, signer.PublicKeyBytes())
	if err == nil {
		t.Error("tampered ML-DSA-65 signature should not verify")
	}
}

// ─── Hybrid ──────────────────────────────────────────────────────────────────

func TestHybrid_BothSignaturesValid(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	pqc, _ := identity.GenerateMLDSASigner()
	hybrid := identity.NewHybridSigner(cl, pqc)

	msg := canonical()
	result, err := hybrid.Sign(msg)
	if err != nil {
		t.Fatalf("hybrid sign: %v", err)
	}
	if len(result.Signature) != 64 {
		t.Error("classical signature missing")
	}
	if result.PQCAlgorithm != identity.AlgorithmMLDSA65 {
		t.Error("PQC algorithm field not set")
	}
	if len(result.PQCSignature) == 0 {
		t.Error("PQC signature missing")
	}
}

func TestHybrid_ReceiverPrefersMLDSA(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	pqc, _ := identity.GenerateMLDSASigner()
	hybrid := identity.NewHybridSigner(cl, pqc)

	msg := canonical()
	hr, _ := hybrid.Sign(msg)

	// PQC-capable receiver: should verify ML-DSA-65
	vr, err := identity.Verify(msg,
		hr.KeyID, hr.Signature, cl.PublicKey(),
		hr.PQCAlgorithm, hr.PQCSignature, pqc.PublicKeyBytes(),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.Algorithm != identity.AlgorithmMLDSA65 {
		t.Errorf("PQC-capable receiver should prefer ML-DSA-65, got %s", vr.Algorithm)
	}
}

func TestHybrid_ClassicalOnlyReceiver_AcceptsEd25519(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	pqc, _ := identity.GenerateMLDSASigner()
	hybrid := identity.NewHybridSigner(cl, pqc)

	msg := canonical()
	hr, _ := hybrid.Sign(msg)

	// Classical-only receiver: passes empty PQC fields
	vr, err := identity.Verify(msg,
		hr.KeyID, hr.Signature, cl.PublicKey(),
		"", nil, nil, // no PQC support
	)
	if err != nil {
		t.Fatalf("classical-only verify: %v", err)
	}
	if vr.Algorithm != identity.AlgorithmEd25519 {
		t.Errorf("classical-only receiver should use ed25519, got %s", vr.Algorithm)
	}
}

func TestHybrid_CorruptedPQCSig_HardReject(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	pqc, _ := identity.GenerateMLDSASigner()
	hybrid := identity.NewHybridSigner(cl, pqc)

	msg := canonical()
	hr, _ := hybrid.Sign(msg)

	// Corrupt the PQC signature — classical sig is valid but PQC-capable
	// receiver must NOT fall back and must reject.
	hr.PQCSignature[0] ^= 0xFF

	_, err := identity.Verify(msg,
		hr.KeyID, hr.Signature, cl.PublicKey(),
		hr.PQCAlgorithm, hr.PQCSignature, pqc.PublicKeyBytes(),
	)
	if err == nil {
		t.Error("corrupted PQC signature must be a hard reject — no classical fallback")
	}
}

func TestHybrid_ClassicalOnly_NoPQC(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	hybrid := identity.NewHybridSigner(cl, nil) // no PQC signer

	if hybrid.HasPQC() {
		t.Error("HasPQC should be false when no PQC signer")
	}
	msg := canonical()
	hr, err := hybrid.Sign(msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if hr.PQCSignature != nil {
		t.Error("PQC signature should be nil when no PQC signer")
	}
}

func TestVerify_UnknownPQCAlgorithm_Rejected(t *testing.T) {
	cl, _ := identity.GenerateEd25519Signer()
	msg := canonical()
	sig, _ := cl.Sign(msg)

	// Sender claims a PQC algorithm we don't know about — must reject,
	// not silently fall back to classical.
	_, err := identity.Verify(msg,
		cl.PublicKeyID(), sig, cl.PublicKey(),
		"some-future-pqc-algo-v9", []byte("fakesig"), []byte("fakepub"),
	)
	if err == nil {
		t.Error("unknown PQC algorithm must be rejected, not silently ignored")
	}
}
