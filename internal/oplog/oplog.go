// Package oplog is a thin, signed operation log layered over the hash-linked WAL.
//
// In Phase 1 it records node-lifecycle operations (start/stop) as signed
// OperationEnvelopes and verifies them on replay. This is the smallest honest use
// of the WAL that exercises the full path the architecture depends on:
// canonical-content signing → protobuf marshaling → durable hash-linked append →
// verifying replay across restarts. The Merkle-DAG parent linking, CRDT payloads,
// and PQC envelope signatures layer onto this same envelope in Phases 3–4; the
// wire format (proto/v1 OperationEnvelope) does not change.
package oplog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/storage"
	"github.com/prateekpurohit13/frien/internal/version"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// OpTypeNodeLifecycle marks node start/stop operations.
const OpTypeNodeLifecycle = "node_lifecycle"

// LifecyclePayload is the JSON body of a lifecycle operation.
type LifecyclePayload struct {
	Event string    `json:"event"` // "start" | "stop"
	At    time.Time `json:"at"`
}

// Log appends signed operations to the WAL and tracks the per-node sequence number
// so it continues monotonically across restarts. It is safe for concurrent use.
type Log struct {
	wal    *storage.WAL
	signer *identity.Ed25519Signer
	pubKey ed25519.PublicKey
	nodeID string

	mu  sync.Mutex
	seq uint64 // last assigned sequence; the next op uses seq+1
}

// New constructs a Log bound to a WAL and the node's identity. The caller is
// expected to invoke Recover once at startup before the first Append so that seq
// continues from the highest sequence already on disk.
func New(wal *storage.WAL, id *identity.Identity) *Log {
	return &Log{
		wal:    wal,
		signer: id.Signer(),
		pubKey: id.Certificate.PublicKey.(ed25519.PublicKey),
		nodeID: id.NodeID,
	}
}

// RecoverResult summarizes a replay of the existing WAL.
type RecoverResult struct {
	Records int    // total operations replayed and verified
	LastSeq uint64 // highest sequence observed for this node
}

// Recover replays the WAL, verifies every record's signature and payload hash, and
// advances the sequence counter past the highest sequence seen. A signature or
// hash mismatch is returned as an error: replay must not silently accept a record
// it cannot verify. Records authored by other nodes are counted but not rejected
// for unknown keys here (cross-node key verification belongs to the Phase 4 verify
// layer); in Phase 1 every WAL record is self-authored.
func (l *Log) Recover() (RecoverResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var res RecoverResult
	err := l.wal.Replay(func(payload []byte) error {
		var env frienv1.OperationEnvelope
		if err := proto.Unmarshal(payload, &env); err != nil {
			return fmt.Errorf("oplog: unmarshaling WAL record %d: %w", res.Records, err)
		}
		if err := l.verifyEnvelope(&env); err != nil {
			return fmt.Errorf("oplog: verifying WAL record %d: %w", res.Records, err)
		}
		if env.NodeId == l.nodeID && env.Seq > res.LastSeq {
			res.LastSeq = env.Seq
		}
		res.Records++
		return nil
	})
	if err != nil {
		return RecoverResult{}, err
	}
	l.seq = res.LastSeq
	return res, nil
}

// AppendLifecycle records a node-lifecycle event (e.g. "start") as a signed
// operation and durably appends it to the WAL. It returns the assigned op_id.
func (l *Log) AppendLifecycle(event string) (string, error) {
	payload := LifecyclePayload{Event: event, At: time.Now().UTC()}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("oplog: marshaling lifecycle payload: %w", err)
	}
	return l.append(OpTypeNodeLifecycle, body)
}

func (l *Log) append(opType string, body []byte) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	seq := l.seq

	opID := newOpID()
	payloadHash := sha256Hex(body)
	// True hybrid logical clocks arrive in Phase 3; until then the timestamp gives a
	// monotonic-enough ordering hint for a single node's own lifecycle records.
	hlc := fmt.Sprintf("%s-%d-%s", time.Now().UTC().Format(time.RFC3339Nano), seq, l.nodeID)

	canonical := identity.CanonicalSignedContent(
		version.ProtoVersion, opID, opType, l.nodeID, hlc, seq, 0, nil, payloadHash, "node",
	)
	sig, err := l.signer.Sign(canonical)
	if err != nil {
		l.seq-- // roll back the sequence; nothing was written
		return "", fmt.Errorf("oplog: signing op %s: %w", opID, err)
	}

	env := &frienv1.OperationEnvelope{
		ProtoVersion: version.ProtoVersion,
		OpId:         opID,
		OpType:       opType,
		NodeId:       l.nodeID,
		Hlc:          hlc,
		Seq:          seq,
		PayloadHash:  payloadHash,
		Payload:      body,
		SignedBy:     "node",
		KeyId:        l.signer.PublicKeyID(),
		Signature:    sig,
	}
	wireBytes, err := proto.Marshal(env)
	if err != nil {
		l.seq--
		return "", fmt.Errorf("oplog: marshaling envelope %s: %w", opID, err)
	}
	if err := l.wal.Append(wireBytes); err != nil {
		l.seq--
		return "", fmt.Errorf("oplog: appending op %s: %w", opID, err)
	}
	return opID, nil
}

// verifyEnvelope checks the payload hash and the classical signature over the
// canonical content. Self-authored records (the only kind in Phase 1) verify
// against our own public key; records from other nodes are accepted structurally
// here and fully verified by the Phase 4 verify layer once peer keys exist.
func (l *Log) verifyEnvelope(env *frienv1.OperationEnvelope) error {
	if got := sha256Hex(env.Payload); got != env.PayloadHash {
		return fmt.Errorf("payload hash mismatch (op_id=%s)", env.OpId)
	}
	canonical := identity.CanonicalSignedContent(
		env.ProtoVersion, env.OpId, env.OpType, env.NodeId, env.Hlc, env.Seq, env.ScopeSeq, env.Parents, env.PayloadHash, env.SignedBy,
	)
	if env.NodeId != l.nodeID {
		return nil // cross-node verification deferred to the verify layer (Phase 4)
	}
	if !ed25519.Verify(l.pubKey, canonical, env.Signature) {
		return fmt.Errorf("signature verification failed (op_id=%s)", env.OpId)
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// newOpID returns a unique operation identifier. Phase 3 replaces this with a ULID
// (lexically sortable by time) once the CRDT layer needs ordered IDs; for Phase 1
// lifecycle records a random token is sufficient and dependency-free.
func newOpID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "op_" + hex.EncodeToString(b[:])
}
