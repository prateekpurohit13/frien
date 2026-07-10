package gossip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/transport"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// newIngestEngine builds a real Engine (signer, keystore, verifier all wired)
// bound to a transport that is never started, so these tests exercise the full
// sign/verify path without any network I/O.
func newIngestEngine(t *testing.T, ca *testCA, nodeID string) *Engine {
	t.Helper()
	id := ca.identity(t, nodeID)
	tr, err := transport.New(id, ca.pool, transport.Config{
		BindAddr:        "127.0.0.1:0",
		MaxMessageBytes: 1 << 20,
		DialTimeout:     time.Second,
		IdleTimeout:     time.Second,
		KEM:             transport.KEMClassical,
	}, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	cfg := Config{NodeID: nodeID}
	return New(cfg, id, crdt.NewClock(nodeID, crdt.WithMaxDrift(10*time.Second)), crdt.NewOpSet(), scope.NewRouter("z"), tr, nil, zerolog.Nop())
}

func TestIngestHoldsBackUnknownSigner(t *testing.T) {
	ca := newTestCA(t)
	a := newIngestEngine(t, ca, "node.a")
	b := newIngestEngine(t, ca, "node.b")

	env, err := b.Publish(crdt.OpThreatRecord, &frienv1.ThreatRecord{Id: "t1", Indicator: "203.0.113.1"}, "fleet")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	a.ingest(env)
	if a.set.Has(env.GetOpId()) {
		t.Fatal("an op from an unregistered signer must not be admitted")
	}
}

func TestIngestAdmitsOnceSignerKeyIsKnown(t *testing.T) {
	ca := newTestCA(t)
	a := newIngestEngine(t, ca, "node.a")
	b := newIngestEngine(t, ca, "node.b")

	env, err := b.Publish(crdt.OpThreatRecord, &frienv1.ThreatRecord{Id: "t1", Indicator: "203.0.113.1"}, "fleet")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	a.keys.RegisterNode("node.b", b.signer.PublicKey())
	a.ingest(env)
	if !a.set.Has(env.GetOpId()) {
		t.Fatal("a correctly signed op should be admitted once the signer's key is known")
	}
}

func TestIngestRejectsTamperedPayload(t *testing.T) {
	ca := newTestCA(t)
	a := newIngestEngine(t, ca, "node.a")
	b := newIngestEngine(t, ca, "node.b")
	a.keys.RegisterNode("node.b", b.signer.PublicKey())

	env, err := b.Publish(crdt.OpThreatRecord, &frienv1.ThreatRecord{Id: "t1", Indicator: "203.0.113.1"}, "fleet")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	tampered := proto.Clone(env).(*frienv1.OperationEnvelope)
	tampered.OpId = "tampered"
	tampered.PayloadHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	a.ingest(tampered)
	if a.set.Has("tampered") {
		t.Fatal("a tampered envelope must not be admitted")
	}
}

// signEnvelope signs env with eng's identity key over its canonical content,
// simulating a malicious node that signs two different ops at the same
// (node_id, seq) -- something Engine.Publish's own atomic counter never does,
// but which another node's compromised or buggy client legitimately could.
func signEnvelope(eng *Engine, env *frienv1.OperationEnvelope) *frienv1.OperationEnvelope {
	msg := identity.CanonicalSignedContent(env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(), env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy())
	sig, _ := eng.signer.Sign(msg)
	env.KeyId = eng.signer.PublicKeyID()
	env.Signature = sig
	return env
}

func TestIngestStampsEquivocationAttribution(t *testing.T) {
	ca := newTestCA(t)
	a := newIngestEngine(t, ca, "node.a")
	b := newIngestEngine(t, ca, "node.b")
	a.keys.RegisterNode("node.b", b.signer.PublicKey())

	var logBuf bytes.Buffer
	a.log = zerolog.New(&logBuf)

	mkEnv := func(opID string) *frienv1.OperationEnvelope {
		body, _ := proto.Marshal(&frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.1"})
		sum := sha256.Sum256(body)
		env := &frienv1.OperationEnvelope{
			ProtoVersion: 1, OpId: opID, OpType: crdt.OpThreatRecord, NodeId: "node.b",
			Hlc: b.clock.Now().String(), Seq: 1, PayloadHash: "sha256:" + hex.EncodeToString(sum[:]),
			Payload: body, SignedBy: "node",
		}
		return signEnvelope(b, env)
	}

	env1 := mkEnv("t1")
	env2 := mkEnv("t2") // same (node.b, seq=1), different op_id: genuine equivocation

	a.ingest(env1)
	a.ingest(env2)

	if !a.set.Has("t1") || !a.set.Has("t2") {
		t.Fatal("both conflicting ops must be admitted (evidence preserved)")
	}

	var entry struct {
		ProofID string `json:"proof_id"`
	}
	if err := json.Unmarshal(logBuf.Bytes(), &entry); err != nil {
		t.Fatalf("parsing log entry: %v (log: %s)", err, logBuf.String())
	}
	if entry.ProofID == "" {
		t.Fatal("equivocation log should carry a non-empty stamped proof_id")
	}
}

func TestIngestRejectsForgedSignerClaim(t *testing.T) {
	ca := newTestCA(t)
	a := newIngestEngine(t, ca, "node.a")
	b := newIngestEngine(t, ca, "node.b")
	c := newIngestEngine(t, ca, "node.c")
	a.keys.RegisterNode("node.b", b.signer.PublicKey())
	a.keys.RegisterNode("node.c", c.signer.PublicKey())

	env, err := b.Publish(crdt.OpThreatRecord, &frienv1.ThreatRecord{Id: "t1", Indicator: "203.0.113.1"}, "fleet")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Relabel B's genuinely-signed op as if it came from C: the signature no
	// longer matches the canonical content (node_id is a signed field).
	forged := proto.Clone(env).(*frienv1.OperationEnvelope)
	forged.NodeId = "node.c"

	a.ingest(forged)
	if a.set.Has(forged.GetOpId()) {
		t.Fatal("an op relabeled to a different signer must not be admitted")
	}
}
