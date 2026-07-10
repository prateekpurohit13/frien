package checkpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Build assembles and signs a Checkpoint recording a compaction cut: treeHead
// (a digest of the op set at the cut), coversThroughHLC (the highest HLC the
// cut is valid up to), the materialized state hash, and the id of the
// checkpoint it chains from (empty for the first). The signature covers every
// other field, so a tampered checkpoint fails Verify.
func Build(prevID, treeHead, coversThroughHLC, materializedStateHash string, signer *identity.Ed25519Signer, now time.Time) (*frienv1.Checkpoint, error) {
	cp := &frienv1.Checkpoint{
		CheckpointId:          "cp_" + randomToken(),
		TreeHead:              treeHead,
		CoversThroughHlc:      coversThroughHLC,
		PrevCheckpoint:        prevID,
		MaterializedStateHash: materializedStateHash,
		CreatedAt:             now.UTC().Format(time.RFC3339),
		SignedBy:              "node",
	}
	sig, err := signer.Sign(canonicalCheckpoint(cp))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: signing %s: %w", cp.GetCheckpointId(), err)
	}
	cp.Signature = sig
	return cp, nil
}

// Verify checks a Checkpoint's signature against pub.
func Verify(cp *frienv1.Checkpoint, pub ed25519.PublicKey) error {
	if cp == nil {
		return fmt.Errorf("checkpoint: nil checkpoint")
	}
	if !ed25519.Verify(pub, canonicalCheckpoint(cp), cp.GetSignature()) {
		return fmt.Errorf("checkpoint: signature verification failed (checkpoint_id=%s)", cp.GetCheckpointId())
	}
	return nil
}

// canonicalCheckpoint returns the bytes a Checkpoint's signature covers: every
// field except the signature itself.
func canonicalCheckpoint(cp *frienv1.Checkpoint) []byte {
	clone := proto.Clone(cp).(*frienv1.Checkpoint)
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

// treeHeadFor summarizes a set of op envelopes into a single digest, used as a
// Checkpoint's tree_head. Envelopes are hashed by (op_id, payload_hash);
// envs is expected already sorted by op_id (as CompactBelow returns), so the
// digest is deterministic regardless of map iteration order upstream.
func treeHeadFor(envs []*frienv1.OperationEnvelope) string {
	h := sha256.New()
	var lenBuf [4]byte
	for _, env := range envs {
		id := env.GetOpId()
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(id)))
		h.Write(lenBuf[:])
		h.Write([]byte(id))
		h.Write([]byte(env.GetPayloadHash()))
	}
	return hex.EncodeToString(h.Sum(nil))
}
