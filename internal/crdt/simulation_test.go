package crdt

import (
	"math/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/scope"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type simNode struct {
	id     string
	zone   string
	set    *OpSet
	router *scope.Router
}

func (n *simNode) accept(env *frienv1.OperationEnvelope) bool {
	return n.router.Accept(EnvelopeScope(env))
}

func scopedThreat(t *testing.T, opID, nodeID string, seq uint64, scopeStr, expires string) *frienv1.OperationEnvelope {
	t.Helper()
	tr := &frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.44", Scope: scopeStr, ExpiresAt: expires}
	payload, err := proto.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: OpThreatRecord, NodeId: nodeID, Seq: seq,
		PayloadHash: payloadHash(payload), Payload: payload,
	}
}

// pull runs one direction of anti-entropy from src into dst, enforcing scope on
// both the egress (ShouldSend) and ingress (Accept) sides.
func pull(dst, src *simNode) {
	for _, scopeKey := range src.set.Scopes() {
		sc, err := scope.Parse(scopeKey)
		if err != nil {
			continue
		}
		if !src.router.ShouldSend(sc, dst.zone) || !dst.router.Accept(sc) {
			continue
		}
		SyncScope(dst.set, src.set, scopeKey, dst.accept)
	}
}

func TestGossipSimulationConvergesPerScope(t *testing.T) {
	const euZone, usZone = "edge-eu-west", "edge-us-east"
	mk := func(id, zone string) *simNode {
		return &simNode{id: id, zone: zone, set: NewOpSet(), router: scope.NewRouter(zone)}
	}
	eu0, eu1 := mk("eu0", euZone), mk("eu1", euZone)
	us0, us1 := mk("us0", usZone), mk("us1", usZone)
	nodes := []*simNode{eu0, eu1, us0, us1}

	now := time.Unix(1_700_000_000, 0).UTC()
	future := rfc3339(now.Add(time.Hour))
	past := rfc3339(now.Add(-time.Hour))

	// eu0 originates four ops with different scopes and lifetimes.
	mustAdd(t, eu0.set, scopedThreat(t, "zoneOp", "eu0", 1, "zone:"+euZone, future))
	mustAdd(t, eu0.set, scopedThreat(t, "fleetOp", "eu0", 2, "fleet", future))
	mustAdd(t, eu0.set, scopedThreat(t, "localOp", "eu0", 3, "local", future))
	mustAdd(t, eu0.set, scopedThreat(t, "expiredOp", "eu0", 4, "zone:"+euZone, past))

	rng := rand.New(rand.NewSource(42))
	for round := 0; round < 300; round++ {
		// Partition eu1 away from the cluster for the first 60 rounds, then heal.
		partitioned := round < 60
		i, j := rng.Intn(len(nodes)), rng.Intn(len(nodes))
		if i == j {
			continue
		}
		a, b := nodes[i], nodes[j]
		if partitioned && (a == eu1 || b == eu1) {
			continue
		}
		if rng.Float64() < 0.3 { // drop this exchange
			continue
		}
		pull(a, b)
		pull(b, a)
	}

	// Zone op converges on both eu nodes, never reaches the us zone.
	for _, n := range []*simNode{eu0, eu1} {
		if !n.set.Has("zoneOp") {
			t.Errorf("%s missing zone op", n.id)
		}
	}
	for _, n := range []*simNode{us0, us1} {
		if n.set.Has("zoneOp") {
			t.Errorf("%s received an out-of-zone op (scope leak)", n.id)
		}
	}
	// Fleet op reaches everyone.
	for _, n := range nodes {
		if !n.set.Has("fleetOp") {
			t.Errorf("%s missing fleet op", n.id)
		}
	}
	// Local op never leaves its origin.
	for _, n := range []*simNode{eu1, us0, us1} {
		if n.set.Has("localOp") {
			t.Errorf("%s received a local-scoped op", n.id)
		}
	}
	// No resurrection: the expired op is never present anywhere, even if held.
	for _, n := range nodes {
		if n.set.IsPresent("expiredOp", now) {
			t.Errorf("%s reports an expired op as present", n.id)
		}
	}
	// Convergence: same per-scope root on all in-scope replicas.
	euRoot := eu0.set.ScopeDigest("zone:" + euZone).Root
	if eu1.set.ScopeDigest("zone:"+euZone).Root != euRoot {
		t.Error("eu nodes did not converge on the zone scope")
	}
	fleetRoot := eu0.set.ScopeDigest("fleet").Root
	for _, n := range nodes {
		if n.set.ScopeDigest("fleet").Root != fleetRoot {
			t.Errorf("%s did not converge on the fleet scope", n.id)
		}
	}
}

func TestGossipPropagatesEquivocation(t *testing.T) {
	a := NewOpSet()
	b := NewOpSet()
	// Same author forks seq 9 with two different ops, each learned by one node.
	mustAdd(t, a, scopedThreat(t, "forkA", "evil", 9, "fleet", ""))
	mustAdd(t, b, scopedThreat(t, "forkB", "evil", 9, "fleet", ""))

	// b reconciles from a, learning the conflicting op -> proof.
	_, proofs := Reconcile(b, a, "fleet", nil)
	if len(proofs) == 0 {
		t.Fatal("reconciling a forked history should surface an equivocation proof")
	}
	if !b.Has("forkA") || !b.Has("forkB") {
		t.Fatal("both conflicting ops must be retained after reconcile")
	}
}

func mustAdd(t *testing.T, s *OpSet, env *frienv1.OperationEnvelope) {
	t.Helper()
	if _, err := s.Add(env); err != nil {
		t.Fatalf("add %s: %v", env.GetOpId(), err)
	}
}
