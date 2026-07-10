package gossip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/membership"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/transport"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "frien-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) identity(t *testing.T, nodeID string) *identity.Identity {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("node cert: %v", err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	writePEM(t, certPath, "CERTIFICATE", der)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER)
	id, err := identity.Load(identity.LoadOptions{CertPath: certPath, KeyPath: keyPath, ExpectedNodeID: nodeID})
	if err != nil {
		t.Fatalf("identity.Load: %v", err)
	}
	return id
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pem: %v", err)
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	return addr
}

type testNode struct {
	eng  *Engine
	set  *crdt.OpSet
	stop context.CancelFunc
}

func newNode(t *testing.T, ca *testCA, nodeID, zone, addr string, seeds []string) *testNode {
	t.Helper()
	id := ca.identity(t, nodeID)
	tr, err := transport.New(id, ca.pool, transport.Config{
		BindAddr:        addr,
		MaxMessageBytes: 1 << 20,
		DialTimeout:     5 * time.Second,
		IdleTimeout:     30 * time.Second,
		KEM:             transport.KEMClassical, // fast handshake for tests
	}, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	set := crdt.NewOpSet()
	cfg := Config{
		NodeID:            nodeID,
		Zone:              zone,
		LocalAddr:         addr,
		Seeds:             seeds,
		SubscribedScopes:  []string{"fleet", "zone:" + zone},
		GossipInterval:    150 * time.Millisecond,
		ProbeInterval:     150 * time.Millisecond,
		ProbeTimeout:      300 * time.Millisecond,
		SuspectMultiplier: 3,
		IndirectProbes:    2,
	}
	eng := New(cfg, id, crdt.NewClock(nodeID, crdt.WithMaxDrift(10*time.Second)), set, scope.NewRouter(zone), tr, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start %s: %v", nodeID, err)
	}
	return &testNode{eng: eng, set: set, stop: cancel}
}

func eventually(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

func TestClusterConvergesByScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live cluster test in -short")
	}
	const euZone, usZone = "edge-eu-west", "edge-us-east"
	ca := newTestCA(t)

	addrA, addrB, addrC := freeUDPAddr(t), freeUDPAddr(t), freeUDPAddr(t)
	a := newNode(t, ca, "node.a", euZone, addrA, nil)
	b := newNode(t, ca, "node.b", euZone, addrB, []string{addrA})
	c := newNode(t, ca, "node.c", usZone, addrC, []string{addrA})
	defer a.stop()
	defer b.stop()
	defer c.stop()

	// node.a publishes one zone-scoped and one fleet-scoped threat.
	now := time.Now().UTC()
	future := now.Add(time.Hour).Format(time.RFC3339)
	zoneTR := &frienv1.ThreatRecord{Id: "z", Indicator: "203.0.113.10", Scope: "zone:" + euZone, ExpiresAt: future}
	fleetTR := &frienv1.ThreatRecord{Id: "f", Indicator: "203.0.113.20", Scope: "fleet", ExpiresAt: future}

	zoneEnv, err := a.eng.Publish(crdt.OpThreatRecord, zoneTR, "zone:"+euZone)
	if err != nil {
		t.Fatalf("publish zone: %v", err)
	}
	fleetEnv, err := a.eng.Publish(crdt.OpThreatRecord, fleetTR, "fleet")
	if err != nil {
		t.Fatalf("publish fleet: %v", err)
	}

	// The fleet op must reach every node.
	if !eventually(t, 20*time.Second, func() bool {
		return b.set.Has(fleetEnv.GetOpId()) && c.set.Has(fleetEnv.GetOpId())
	}) {
		t.Fatalf("fleet op did not converge: b=%v c=%v", b.set.Has(fleetEnv.GetOpId()), c.set.Has(fleetEnv.GetOpId()))
	}

	// The zone op reaches the same-zone peer (b) but never the other zone (c).
	if !eventually(t, 20*time.Second, func() bool { return b.set.Has(zoneEnv.GetOpId()) }) {
		t.Fatal("zone op did not converge on the same-zone peer")
	}
	if c.set.Has(zoneEnv.GetOpId()) {
		t.Fatal("zone op leaked to an out-of-zone node")
	}
}

func TestClusterDetectsFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live cluster test in -short")
	}
	const zone = "edge-eu-west"
	ca := newTestCA(t)
	addrA, addrB := freeUDPAddr(t), freeUDPAddr(t)
	a := newNode(t, ca, "node.a", zone, addrA, nil)
	b := newNode(t, ca, "node.b", zone, addrB, []string{addrA})
	defer b.stop()

	// b learns a is alive.
	if !eventually(t, 15*time.Second, func() bool {
		m, ok := memberState(b, "node.a")
		return ok && m == membership.StateAlive
	}) {
		t.Fatal("b never saw a as alive")
	}

	// a goes down; b must detect and converge on dead.
	a.stop()
	if !eventually(t, 15*time.Second, func() bool {
		m, ok := memberState(b, "node.a")
		return ok && m == membership.StateDead
	}) {
		t.Fatal("b did not detect a's failure")
	}
}

func memberState(n *testNode, nodeID string) (membership.State, bool) {
	for _, m := range n.eng.Peers() {
		if m.NodeID == nodeID {
			return m.State, true
		}
	}
	return 0, false
}
