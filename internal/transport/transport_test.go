package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca keygen: %v", err)
	}
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func (ca *testCA) nodeIdentity(t *testing.T, nodeID string) *identity.Identity {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("node keygen: %v", err)
	}
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
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

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

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testConfig(kem KEMMode) Config {
	return Config{
		BindAddr:        "127.0.0.1:0",
		MaxMessageBytes: 1 << 20,
		DialTimeout:     5 * time.Second,
		IdleTimeout:     10 * time.Second,
		KEM:             kem,
	}
}

type revokeSet map[string]bool

func (r revokeSet) IsRevoked(fp string) bool { return r[fp] }

func dialAndAccept(t *testing.T, server, client *Transport) (srvSess, cliSess *Session, err error) {
	t.Helper()
	ln, lerr := server.Listen()
	if lerr != nil {
		t.Fatalf("listen: %v", lerr)
	}
	defer ln.Close()

	type result struct {
		sess *Session
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, e := ln.Accept(ctx)
		accepted <- result{s, e}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cliSess, err = client.Dial(ctx, ln.Addr().String())

	r := <-accepted
	return r.sess, cliSess, errFirst(err, r.err)
}

func errFirst(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func TestSessionEstablishAndNegotiate(t *testing.T) {
	ca := newTestCA(t)
	log := zerolog.Nop()

	serverID := ca.nodeIdentity(t, "node.a")
	clientID := ca.nodeIdentity(t, "node.b")

	server, err := New(serverID, ca.pool, testConfig(KEMHybridPQC), nil, log)
	if err != nil {
		t.Fatalf("server transport: %v", err)
	}
	client, err := New(clientID, ca.pool, testConfig(KEMHybridPQC), nil, log)
	if err != nil {
		t.Fatalf("client transport: %v", err)
	}

	srv, cli, err := dialAndAccept(t, server, client)
	if err != nil {
		t.Fatalf("establish: %v", err)
	}
	defer srv.Close()
	defer cli.Close()

	if cli.NodeID != "node.a" {
		t.Errorf("client sees peer %q, want node.a", cli.NodeID)
	}
	if srv.NodeID != "node.b" {
		t.Errorf("server sees peer %q, want node.b", srv.NodeID)
	}
	if cli.Version != 1 || srv.Version != 1 {
		t.Errorf("negotiated versions: client=%d server=%d, want 1/1", cli.Version, srv.Version)
	}
}

func TestClassicalKEMEstablishes(t *testing.T) {
	ca := newTestCA(t)
	log := zerolog.Nop()
	server, _ := New(ca.nodeIdentity(t, "node.a"), ca.pool, testConfig(KEMClassical), nil, log)
	client, _ := New(ca.nodeIdentity(t, "node.b"), ca.pool, testConfig(KEMClassical), nil, log)

	srv, cli, err := dialAndAccept(t, server, client)
	if err != nil {
		t.Fatalf("establish (classical): %v", err)
	}
	srv.Close()
	cli.Close()
}

func TestRevokedPeerRejected(t *testing.T) {
	ca := newTestCA(t)
	log := zerolog.Nop()

	serverID := ca.nodeIdentity(t, "node.a")
	clientID := ca.nodeIdentity(t, "node.b")

	// Server revokes the client's fingerprint: the handshake must fail.
	revoked := revokeSet{clientID.Fingerprint: true}
	server, _ := New(serverID, ca.pool, testConfig(KEMHybridPQC), revoked, log)
	client, _ := New(clientID, ca.pool, testConfig(KEMHybridPQC), nil, log)

	_, _, err := dialAndAccept(t, server, client)
	if err == nil {
		t.Fatal("expected handshake failure for revoked peer, got nil")
	}
}

func TestUntrustedCARejected(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	log := zerolog.Nop()

	// Server trusts only caA; client is issued by caB.
	server, _ := New(caA.nodeIdentity(t, "node.a"), caA.pool, testConfig(KEMHybridPQC), nil, log)
	client, _ := New(caB.nodeIdentity(t, "node.b"), caB.pool, testConfig(KEMHybridPQC), nil, log)

	if _, _, err := dialAndAccept(t, server, client); err == nil {
		t.Fatal("expected handshake failure for untrusted CA, got nil")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := &frienv1.NegotiateRequest{SupportedVersions: []uint32{1, 2, 3}}
	if err := writeFrame(&buf, in, 1<<20); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	var out frienv1.NegotiateRequest
	if err := readFrame(&buf, &out, 1<<20); err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if len(out.GetSupportedVersions()) != 3 {
		t.Errorf("round-trip lost data: %v", out.GetSupportedVersions())
	}
}

func TestFrameTooLargeOnWrite(t *testing.T) {
	var buf bytes.Buffer
	msg := &frienv1.NegotiateRequest{SupportedVersions: make([]uint32, 100)}
	if err := writeFrame(&buf, msg, 4); err != ErrMessageTooLarge {
		t.Fatalf("writeFrame err = %v, want ErrMessageTooLarge", err)
	}
}

func TestFrameTooLargeOnRead(t *testing.T) {
	var buf bytes.Buffer
	// Hand-craft a header claiming 1000 bytes against a 10-byte ceiling.
	buf.Write([]byte{0x00, 0x00, 0x03, 0xE8})
	var out frienv1.NegotiateRequest
	if err := readFrame(&buf, &out, 10); err != ErrMessageTooLarge {
		t.Fatalf("readFrame err = %v, want ErrMessageTooLarge", err)
	}
}

func TestCurvePreferences(t *testing.T) {
	if c, _ := curvePreferences(KEMHybridPQC); len(c) == 0 {
		t.Error("hybrid PQC must offer at least one curve")
	}
	if _, err := curvePreferences("bogus"); err == nil {
		t.Error("unknown KEM should error")
	}
}
