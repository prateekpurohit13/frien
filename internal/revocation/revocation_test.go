package revocation

import (
	"testing"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func rec(fp, status string) *frienv1.RevocationRecord {
	return &frienv1.RevocationRecord{
		Id: "r1", CertFingerprint: fp, NodeId: "node.evil",
		SignedBy: "operator", Status: status,
	}
}

func TestApplyRejectsNonOperatorSigner(t *testing.T) {
	s := NewSet()
	bad := rec("fp1", StatusTainted)
	bad.SignedBy = "node"
	if _, err := s.Apply(bad); err == nil {
		t.Fatal("a record not signed_by operator should be rejected")
	}
}

func TestApplyRejectsMissingFingerprint(t *testing.T) {
	s := NewSet()
	bad := rec("", StatusTainted)
	if _, err := s.Apply(bad); err == nil {
		t.Fatal("a record with no cert_fingerprint should be rejected")
	}
}

func TestApplyRejectsUnknownStatus(t *testing.T) {
	s := NewSet()
	bad := rec("fp1", "bogus")
	if _, err := s.Apply(bad); err == nil {
		t.Fatal("an unrecognized status should be rejected")
	}
}

func TestTaintDoesNotRevoke(t *testing.T) {
	s := NewSet()
	res, err := s.Apply(rec("fp1", StatusTainted))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.NewlyTainted || res.NewlyRevoked {
		t.Fatalf("taint-only record should set NewlyTainted, not NewlyRevoked: %+v", res)
	}
	if !s.IsTainted("fp1") {
		t.Fatal("fp1 should be tainted")
	}
	if s.IsRevoked("fp1") {
		t.Fatal("tainting alone must not revoke")
	}
}

func TestRevokeImpliesTaint(t *testing.T) {
	s := NewSet()
	res, err := s.Apply(rec("fp1", StatusRevoked))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !res.NewlyTainted || !res.NewlyRevoked {
		t.Fatalf("a fresh revocation should set both flags: %+v", res)
	}
	if !s.IsTainted("fp1") || !s.IsRevoked("fp1") {
		t.Fatal("revoked implies tainted")
	}
}

func TestApplyIsMonotonicAndIdempotent(t *testing.T) {
	s := NewSet()
	s.Apply(rec("fp1", StatusTainted))
	res, err := s.Apply(rec("fp1", StatusRevoked))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.NewlyTainted {
		t.Fatal("already-tainted fingerprint should not report NewlyTainted again")
	}
	if !res.NewlyRevoked {
		t.Fatal("the taint->revoke transition should still report NewlyRevoked")
	}

	// Re-applying revoked again is a no-op, not an error, and reports no change.
	res2, err := s.Apply(rec("fp1", StatusRevoked))
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if res2.NewlyTainted || res2.NewlyRevoked {
		t.Fatalf("re-applying an already-revoked record should report no new change: %+v", res2)
	}
	if !s.IsRevoked("fp1") {
		t.Fatal("fp1 should remain revoked")
	}
}

func TestIsRevokedIsPerFingerprint(t *testing.T) {
	s := NewSet()
	s.Apply(rec("fp1", StatusRevoked))
	if s.IsRevoked("fp2") {
		t.Fatal("a different fingerprint must not be affected")
	}
}

func TestNodeIDForTracksAssociation(t *testing.T) {
	s := NewSet()
	s.Apply(rec("fp1", StatusRevoked))
	nodeID, ok := s.NodeIDFor("fp1")
	if !ok || nodeID != "node.evil" {
		t.Fatalf("NodeIDFor(fp1) = (%q, %v), want (node.evil, true)", nodeID, ok)
	}
	if _, ok := s.NodeIDFor("unknown"); ok {
		t.Fatal("an unknown fingerprint should report not-found")
	}
}
