package gossip

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
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
	return New(cfg, id, crdt.NewClock(nodeID, crdt.WithMaxDrift(10*time.Second)), crdt.NewOpSet(), scope.NewRouter("z"), tr, zerolog.Nop())
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
