package policy

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// samplePolicy returns a realistic enforce-capable policy for tests.
func samplePolicy() *Policy {
	return &Policy{
		ID:                    "edge_block_v1",
		Version:               7,
		Action:                "block",
		DefaultMode:           ModeObserve,
		MinConfidence:         0.85,
		RequireWeight:         3.0,
		QuorumWindow:          "5m",
		MaxTTL:                "1h",
		KernelTimeoutRequired: true,
		ProtectSelfPlanes:     true,
	}
}

func TestParseWrappedAndValidate(t *testing.T) {
	yaml := []byte(`
policy:
  id: edge_block_v1
  version: 7
  action: block
  default_mode: observe
  min_confidence: 0.85
  require_weight: 3.0
  quorum_window: 5m
  max_ttl: 1h
  kernel_timeout_required: true
  protect_self_planes: true
`)
	p, err := Parse(yaml)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.ID != "edge_block_v1" || p.Version != 7 || p.RequireWeight != 3.0 {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.QuorumWindowDuration() != 5*time.Minute {
		t.Fatalf("window: %v", p.QuorumWindowDuration())
	}
	if p.MaxTTLDuration() != time.Hour {
		t.Fatalf("max ttl: %v", p.MaxTTLDuration())
	}
	if p.AdapterName() != DefaultAdapter {
		t.Fatalf("adapter default: %v", p.AdapterName())
	}
}

func TestValidateRejectsBadPolicy(t *testing.T) {
	cases := map[string][]byte{
		"missing id":     []byte("policy:\n  version: 1\n  action: block\n"),
		"bad action":     []byte("policy:\n  id: x\n  version: 1\n  action: nope\n"),
		"bad mode":       []byte("policy:\n  id: x\n  version: 1\n  action: block\n  default_mode: maybe\n"),
		"bad confidence": []byte("policy:\n  id: x\n  version: 1\n  action: block\n  min_confidence: 2.0\n"),
		"bad window":     []byte("policy:\n  id: x\n  version: 1\n  action: block\n  quorum_window: 5\n"),
		"zero version":   []byte("policy:\n  id: x\n  version: 0\n  action: block\n"),
	}
	for name, y := range cases {
		if _, err := Parse(y); err == nil {
			t.Errorf("%s: expected parse error, got none", name)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	p := samplePolicy()
	p.Sign(priv, "operator-key-1")

	if p.SignedBy != "operator" || p.Signature == "" {
		t.Fatal("Sign did not fill signature fields")
	}
	if err := p.Verify(pub); err != nil {
		t.Fatalf("Verify after Sign: %v", err)
	}

	// A different key must not verify.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := p.Verify(otherPub); err == nil {
		t.Fatal("Verify accepted wrong operator key")
	}

	// No pinned key is a hard error.
	if err := p.Verify(nil); err == nil {
		t.Fatal("Verify accepted nil operator key")
	}
}

func TestVerifyRejectsTamperedPolicy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	p := samplePolicy()
	p.Sign(priv, "k")
	// Tamper with a signed field after signing.
	p.RequireWeight = 1.0
	if err := p.Verify(pub); err == nil {
		t.Fatal("Verify accepted a policy whose signed content was changed")
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	p := samplePolicy() // never signed
	if err := p.Verify(pub); err == nil {
		t.Fatal("Verify accepted an unsigned policy")
	}
}

func TestCanonicalBytesStableAcrossNumberForms(t *testing.T) {
	// 3.0 vs 3 must hash identically so YAML int/float parsing cannot break a
	// signature.
	a := &Policy{ID: "x", Version: 1, Action: "block", RequireWeight: 3.0}
	b := &Policy{ID: "x", Version: 1, Action: "block", RequireWeight: 3}
	if string(a.CanonicalBytes()) != string(b.CanonicalBytes()) {
		t.Fatal("3.0 and 3 produced different canonical bytes")
	}
}
