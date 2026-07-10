package oplog_test

import (
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
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/oplog"
	"github.com/prateekpurohit13/frien/internal/storage"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// testIdentity creates a self-signed ed25519 identity in a temp dir.
func testIdentity(t *testing.T, nodeID string) *identity.Identity {
	t.Helper()
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(8 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	certPath := filepath.Join(dir, "node.crt")
	keyPath := filepath.Join(dir, "node.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)

	id, err := identity.Load(identity.LoadOptions{CertPath: certPath, KeyPath: keyPath, ExpectedNodeID: nodeID})
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	return id
}

func openStore(t *testing.T, base string) *storage.Store {
	t.Helper()
	s, err := storage.Open(storage.Options{
		WALDir:      filepath.Join(base, "wal"),
		DBPath:      filepath.Join(base, "state.db"),
		SnapshotDir: filepath.Join(base, "snap"),
		WALSync:     true,
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func TestOplog_AppendAndRecoverAcrossRestart(t *testing.T) {
	base := t.TempDir()
	id := testIdentity(t, "node.test.01")

	// First boot: empty WAL, append two lifecycle records.
	s1 := openStore(t, base)
	l1 := oplog.New(s1.WAL, id)
	if res, err := l1.Recover(); err != nil || res.Records != 0 {
		t.Fatalf("fresh recover: records=%d err=%v", res.Records, err)
	}
	if _, err := l1.AppendLifecycle("start"); err != nil {
		t.Fatalf("append start: %v", err)
	}
	if _, err := l1.AppendLifecycle("stop"); err != nil {
		t.Fatalf("append stop: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second boot: recovery must replay and verify both records and continue seq.
	s2 := openStore(t, base)
	defer s2.Close()
	l2 := oplog.New(s2.WAL, id)
	res, err := l2.Recover()
	if err != nil {
		t.Fatalf("recover after restart: %v", err)
	}
	if res.Records != 2 {
		t.Fatalf("recovered %d records, want 2", res.Records)
	}
	if res.LastSeq != 2 {
		t.Fatalf("last seq = %d, want 2", res.LastSeq)
	}

	// The next append must continue the sequence at 3, proving seq survived restart.
	if _, err := l2.AppendLifecycle("start"); err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	res2, _ := l2.Recover()
	if res2.LastSeq != 3 {
		t.Fatalf("seq after restart append = %d, want 3", res2.LastSeq)
	}
}

func TestOplog_TamperedSignature_RejectedOnRecover(t *testing.T) {
	base := t.TempDir()
	id := testIdentity(t, "node.test.02")

	s1 := openStore(t, base)
	l1 := oplog.New(s1.WAL, id)
	if _, err := l1.AppendLifecycle("start"); err != nil {
		t.Fatalf("append: %v", err)
	}
	s1.Close()

	// Forge a record with a valid hash chain (so the WAL accepts it) but a payload
	// that no longer matches its signature/hash, and append it directly.
	forged := &frienv1.OperationEnvelope{
		ProtoVersion: 1,
		OpId:         "op_forged",
		OpType:       oplog.OpTypeNodeLifecycle,
		NodeId:       "node.test.02",
		Hlc:          "forged",
		Seq:          99,
		PayloadHash:  "deadbeef", // deliberately wrong hash for the payload
		Payload:      []byte(`{"event":"start"}`),
		SignedBy:     "node",
		Signature:    make([]byte, 64),
	}
	wire, _ := proto.Marshal(forged)
	s2 := openStore(t, base)
	if err := s2.WAL.Append(wire); err != nil {
		t.Fatalf("append forged: %v", err)
	}
	s2.Close()

	// Recovery must reject the forged record.
	s3 := openStore(t, base)
	defer s3.Close()
	l3 := oplog.New(s3.WAL, id)
	if _, err := l3.Recover(); err == nil {
		t.Fatal("recover must reject a record whose payload hash/signature do not verify")
	}
}
