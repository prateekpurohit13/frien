package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// CanonicalSignedContent produces the deterministic byte sequence that is signed
// by every algorithm (ed25519 and ML-DSA-65). Both signatures always cover
// exactly this content so a hybrid-signed envelope cannot be split into two
// independently-valid envelopes with different content.
//
// Fields included (in order):
//   proto_version | op_id | op_type | node_id | hlc | seq | parents_hash | payload_hash | signed_by
//
// Fields excluded: signature, pqc_signature, pqc_algorithm, pqc_key_id, key_id, payload.
// payload is excluded because it is already committed to via payload_hash.
//
// The result is the SHA-256 of the concatenated fields. Signing the hash rather
// than the raw fields keeps the input size constant regardless of op size, which
// matters for ML-DSA-65 whose performance degrades with large messages.
func CanonicalSignedContent(
	protoVersion uint32,
	opID, opType, nodeID, hlc string,
	seq uint64,
	parents []string,
	payloadHash string,
	signedBy string,
) []byte {
	h := sha256.New()

	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], protoVersion)
	h.Write(u32[:])

	for _, s := range []string{opID, opType, nodeID, hlc} {
		writeField(h, s)
	}

	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], seq)
	h.Write(u64[:])

	// Parents: sort is not required here because callers must pass parents in
	// insertion order (DAG causal order). Sorting would change the causal semantics.
	// We hash the joined string so the count and content are both committed to.
	writeField(h, strings.Join(parents, "|"))

	writeField(h, payloadHash)
	writeField(h, signedBy)

	return h.Sum(nil)
}

// writeField writes a length-prefixed string into h to prevent field boundary
// ambiguity (e.g. "ab"+"c" vs "a"+"bc" would otherwise collide).
func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(s)))
	h.Write(length[:])
	h.Write([]byte(s))
}
