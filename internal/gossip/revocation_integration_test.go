package gossip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/revocation"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/transport"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// newRevocationTestNode mirrors newNode but also configures an operator
// public key, needed for a node to verify operator-signed control ops.
func newRevocationTestNode(t *testing.T, ca *testCA, nodeID, zone, addr string, seeds []string, operatorPub ed25519.PublicKey) (*testNode, *identity.Identity) {
	t.Helper()
	id := ca.identity(t, nodeID)
	tr, err := transport.New(id, ca.pool, transport.Config{
		BindAddr: addr, MaxMessageBytes: 1 << 20, DialTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second, KEM: transport.KEMClassical,
	}, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	set := crdt.NewOpSet()
	cfg := Config{
		NodeID: nodeID, Zone: zone, LocalAddr: addr, Seeds: seeds,
		SubscribedScopes:  []string{"fleet", "zone:" + zone},
		GossipInterval:    150 * time.Millisecond,
		ProbeInterval:     150 * time.Millisecond,
		ProbeTimeout:      300 * time.Millisecond,
		SuspectMultiplier: 3,
		IndirectProbes:    2,
		OperatorPublicKey: operatorPub,
	}
	eng := New(cfg, id, crdt.NewClock(nodeID, crdt.WithMaxDrift(10*time.Second)), set, scope.NewRouter(zone), tr, nil, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start %s: %v", nodeID, err)
	}
	return &testNode{eng: eng, set: set, stop: cancel}, id
}

// revocationEnvelope builds an operator-signed OperationEnvelope carrying rec,
// as an operator tool would construct it before injecting it into a node.
func revocationEnvelope(t *testing.T, rec *frienv1.RevocationRecord, opSigner *identity.Ed25519Signer, seq uint64) *frienv1.OperationEnvelope {
	t.Helper()
	body, err := proto.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	sum := sha256.Sum256(body)
	ts := crdt.Timestamp{Wall: time.Now().UnixMilli(), NodeID: "operator"}
	env := &frienv1.OperationEnvelope{
		ProtoVersion: 1, OpId: "rev_op_" + rec.GetId(), OpType: crdt.OpRevocation,
		NodeId: "operator", Hlc: ts.String(), Seq: seq,
		PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Payload: body,
		SignedBy: "operator",
	}
	msg := identity.CanonicalSignedContent(env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(), env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy())
	sig, err := opSigner.Sign(msg)
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	env.KeyId = opSigner.PublicKeyID()
	env.Signature = sig
	return env
}

func TestRevocationInjectPropagatesAndAppliesLocally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live cluster test in -short")
	}
	ca := newTestCA(t)
	_, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	opSigner := identity.NewEd25519Signer(opPriv)

	addrA, addrB := freeUDPAddr(t), freeUDPAddr(t)
	a, _ := newRevocationTestNode(t, ca, "node.a", "z", addrA, nil, opSigner.PublicKey())
	b, idB := newRevocationTestNode(t, ca, "node.b", "z", addrB, []string{addrA}, opSigner.PublicKey())
	defer a.stop()
	defer b.stop()

	// Give the mesh a moment to discover each other before injecting.
	if !eventually(t, 10*time.Second, func() bool {
		return len(a.eng.LiveFleetPeers()) > 0 && len(b.eng.LiveFleetPeers()) > 0
	}) {
		t.Fatal("nodes never discovered each other")
	}

	rec, err := revocation.Build("node.b", idB.Fingerprint, "compromised key", revocation.StatusRevoked, opSigner, time.Now())
	if err != nil {
		t.Fatalf("build record: %v", err)
	}
	env := revocationEnvelope(t, rec, opSigner, 1)

	if err := a.eng.Ingest(env); err != nil {
		t.Fatalf("injecting the revocation into node.a should succeed: %v", err)
	}
	if !a.eng.revocations.IsRevoked(idB.Fingerprint) {
		t.Fatal("node.a should have applied the revocation locally right away")
	}

	// The revocation op itself must propagate to node.b like any other op.
	if !eventually(t, 20*time.Second, func() bool { return b.set.Has(env.GetOpId()) }) {
		t.Fatal("revocation op did not converge to node.b")
	}
	if !eventually(t, 5*time.Second, func() bool { return b.eng.revocations.IsRevoked(idB.Fingerprint) }) {
		t.Fatal("node.b should have applied the revocation to its own local state once it converged")
	}
}

func TestRevocationTaintDoesNotRevoke(t *testing.T) {
	ca := newTestCA(t)
	_, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	opSigner := identity.NewEd25519Signer(opPriv)

	a, _ := newRevocationTestNode(t, ca, "node.a", "z", freeUDPAddr(t), nil, opSigner.PublicKey())
	defer a.stop()
	idC := ca.identity(t, "node.c")

	rec, err := revocation.Build("node.c", idC.Fingerprint, "suspicious activity", revocation.StatusTainted, opSigner, time.Now())
	if err != nil {
		t.Fatalf("build record: %v", err)
	}
	env := revocationEnvelope(t, rec, opSigner, 1)
	if err := a.eng.Ingest(env); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	if !a.eng.revocations.IsTainted(idC.Fingerprint) {
		t.Fatal("node.a should record the taint")
	}
	if a.eng.revocations.IsRevoked(idC.Fingerprint) {
		t.Fatal("a taint-only record must not revoke")
	}
}

func TestRevocationRejectsNonOperatorEnvelope(t *testing.T) {
	ca := newTestCA(t)
	_, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	opSigner := identity.NewEd25519Signer(opPriv)
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	nodeSigner := identity.NewEd25519Signer(nodePriv)

	a, _ := newRevocationTestNode(t, ca, "node.a", "z", freeUDPAddr(t), nil, opSigner.PublicKey())
	defer a.stop()
	a.eng.keys.RegisterNode("attacker", nodeSigner.PublicKey())

	rec, err := revocation.Build("node.c", "sha256:fake", "forged", revocation.StatusRevoked, opSigner, time.Now())
	if err != nil {
		t.Fatalf("build record: %v", err)
	}
	body, _ := proto.Marshal(rec)
	sum := sha256.Sum256(body)
	ts := crdt.Timestamp{Wall: time.Now().UnixMilli(), NodeID: "attacker"}
	env := &frienv1.OperationEnvelope{
		ProtoVersion: 1, OpId: "forged_rev", OpType: crdt.OpRevocation,
		NodeId: "attacker", Hlc: ts.String(), Seq: 1,
		PayloadHash: "sha256:" + hex.EncodeToString(sum[:]), Payload: body,
		SignedBy: "node", // NOT "operator" -- forged attempt to smuggle a revocation as a node op
	}
	msg := identity.CanonicalSignedContent(env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(), env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy())
	sig, _ := nodeSigner.Sign(msg)
	env.KeyId = nodeSigner.PublicKeyID()
	env.Signature = sig

	if err := a.eng.Ingest(env); err != nil {
		t.Fatalf("the envelope itself verifies fine (node-signed, legitimate node key): %v", err)
	}
	if a.eng.revocations.IsRevoked("sha256:fake") {
		t.Fatal("a revocation op not signed_by operator must be rejected by Set.Apply even if the envelope verifies")
	}
}
