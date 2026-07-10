package revocation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Build assembles and signs a RevocationRecord with the operator's key. The
// record is meant to be created out-of-band by an operator tool holding the
// operator private key (never on a node, per docs/security.md) and then
// carried into the mesh inside an operator-signed OperationEnvelope; nodes
// never mint these themselves.
func Build(nodeID, certFingerprint, reason, status string, operatorSigner *identity.Ed25519Signer, now time.Time) (*frienv1.RevocationRecord, error) {
	if status != StatusTainted && status != StatusRevoked {
		return nil, fmt.Errorf("revocation: invalid status %q", status)
	}
	rec := &frienv1.RevocationRecord{
		Id:              "rev_" + randomToken(),
		CertFingerprint: certFingerprint,
		NodeId:          nodeID,
		Reason:          reason,
		RevokedAt:       now.UTC().Format(time.RFC3339),
		SignedBy:        "operator",
		OperatorKeyId:   operatorSigner.PublicKeyID(),
		Status:          status,
	}
	sig, err := operatorSigner.Sign(canonicalRecord(rec))
	if err != nil {
		return nil, fmt.Errorf("revocation: signing %s: %w", rec.GetId(), err)
	}
	rec.Signature = sig
	return rec, nil
}

// Verify checks a RevocationRecord's own embedded signature against the
// operator's public key, independent of any envelope-level verification.
func Verify(rec *frienv1.RevocationRecord, operatorPub ed25519.PublicKey) error {
	if rec == nil {
		return fmt.Errorf("revocation: nil record")
	}
	if !ed25519.Verify(operatorPub, canonicalRecord(rec), rec.GetSignature()) {
		return fmt.Errorf("revocation: signature verification failed (id=%s)", rec.GetId())
	}
	return nil
}

func canonicalRecord(rec *frienv1.RevocationRecord) []byte {
	clone := proto.Clone(rec).(*frienv1.RevocationRecord)
	clone.Signature = nil
	b, _ := proto.Marshal(clone)
	sum := sha256.Sum256(b)
	return sum[:]
}

func randomToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
