package grpc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// dialSocket returns a client connected to the admin Unix socket.
func dialSocket(t *testing.T, path string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		"unix:"+path,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func startTestServer(t *testing.T, src StatusSource) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})
	return socket
}

func TestGetStatus_OverSocket(t *testing.T) {
	expiry := time.Now().Add(8 * time.Hour)
	started := time.Now().Add(-90 * time.Second)
	src := StatusFunc(func() StatusInfo {
		return StatusInfo{
			NodeID:       "node.test.01",
			EnforceMode:  "observe",
			PeerCount:    0,
			CertExpiry:   expiry,
			WALSizeBytes: 4096,
			StartedAt:    started,
		}
	})

	socket := startTestServer(t, src)
	conn := dialSocket(t, socket)
	defer conn.Close()

	client := frienv1.NewAdminServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := client.GetStatus(ctx, &frienv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}

	if resp.NodeId != "node.test.01" {
		t.Errorf("node_id = %q", resp.NodeId)
	}
	if resp.Status != "healthy" {
		t.Errorf("status = %q, want healthy (cert valid)", resp.Status)
	}
	if resp.EnforceMode != "observe" {
		t.Errorf("enforce_mode = %q, want observe", resp.EnforceMode)
	}
	if resp.ProtoVersion != "1" {
		t.Errorf("proto_version = %q, want 1", resp.ProtoVersion)
	}
	if resp.WalSizeBytes != 4096 {
		t.Errorf("wal_size_bytes = %d, want 4096", resp.WalSizeBytes)
	}
	if resp.CertExpires == "" {
		t.Error("cert_expires should be populated")
	}
	if resp.Uptime == "" {
		t.Error("uptime should be populated")
	}
}

func TestGetStatus_DegradedWhenCertExpired(t *testing.T) {
	src := StatusFunc(func() StatusInfo {
		return StatusInfo{
			NodeID:      "node.expired",
			EnforceMode: "observe",
			CertExpiry:  time.Now().Add(-time.Minute), // already expired
			StartedAt:   time.Now(),
		}
	})
	socket := startTestServer(t, src)
	conn := dialSocket(t, socket)
	defer conn.Close()

	resp, err := frienv1.NewAdminServiceClient(conn).GetStatus(
		context.Background(), &frienv1.GetStatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp.Status != "degraded" {
		t.Errorf("expired cert should yield degraded, got %q", resp.Status)
	}
}

func TestUnimplementedRPC_ReturnsClearError(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := startTestServer(t, src)
	conn := dialSocket(t, socket)
	defer conn.Close()

	_, err := frienv1.NewAdminServiceClient(conn).ReportThreat(
		context.Background(), &frienv1.ReportThreatRequest{Indicator: "1.2.3.4"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented for a not-yet-built RPC, got %v", status.Code(err))
	}
}

type fakePeers []PeerInfo

func (f fakePeers) Peers() []PeerInfo { return f }

func TestListPeers_ReturnsRoster(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	admin.SetPeerSource(fakePeers{
		{NodeID: "node.a", Status: "alive", Addresses: []string{"10.0.0.1:7443"}, LastSeen: time.Now()},
		{NodeID: "node.b", Status: "dead", Addresses: []string{"10.0.0.2:7443"}},
	})
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	resp, err := frienv1.NewAdminServiceClient(conn).ListPeers(context.Background(), &frienv1.ListPeersRequest{})
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(resp.GetPeers()) != 2 {
		t.Fatalf("peers = %d, want 2", len(resp.GetPeers()))
	}
	if resp.GetPeers()[0].GetNodeId() != "node.a" || resp.GetPeers()[0].GetStatus() != "alive" {
		t.Errorf("peer[0] = %+v", resp.GetPeers()[0])
	}
	if resp.GetPeers()[0].GetLastSeen() == "" {
		t.Error("alive peer should have a last_seen timestamp")
	}
}

func TestListPeers_UnimplementedWithoutSource(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := startTestServer(t, src)
	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err := frienv1.NewAdminServiceClient(conn).ListPeers(context.Background(), &frienv1.ListPeersRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ListPeers without a peer source should be Unimplemented, got %v", status.Code(err))
	}
}

type fakeInjector struct {
	lastEnv *frienv1.OperationEnvelope
	err     error
}

func (f *fakeInjector) Ingest(env *frienv1.OperationEnvelope) error {
	f.lastEnv = env
	return f.err
}

type fakeCompactor struct {
	lastScope string
	compacted []string
}

func (f *fakeCompactor) TriggerCompaction(scopeKey string) []string {
	f.lastScope = scopeKey
	return f.compacted
}

func TestInjectOperatorOp_RoutesToInjector(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	injector := &fakeInjector{}
	admin.SetOperatorOpInjector(injector)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	env := &frienv1.OperationEnvelope{OpId: "op_revoke_1", OpType: "revocation"}
	resp, err := frienv1.NewAdminServiceClient(conn).InjectOperatorOp(
		context.Background(), &frienv1.InjectOperatorOpRequest{Envelope: env})
	if err != nil {
		t.Fatalf("InjectOperatorOp: %v", err)
	}
	if resp.GetOpId() != "op_revoke_1" {
		t.Fatalf("op_id = %q, want op_revoke_1", resp.GetOpId())
	}
	if injector.lastEnv.GetOpId() != "op_revoke_1" {
		t.Fatal("the envelope should have been forwarded to the injector unchanged")
	}
}

func TestInjectOperatorOp_RejectsInvalidEnvelope(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	admin.SetOperatorOpInjector(&fakeInjector{err: status.Error(codes.InvalidArgument, "bad signature")})
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).InjectOperatorOp(
		context.Background(), &frienv1.InjectOperatorOpRequest{Envelope: &frienv1.OperationEnvelope{OpId: "op1"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument when the injector rejects, got %v", status.Code(err))
	}
}

func TestInjectOperatorOp_MissingOpID(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	admin.SetOperatorOpInjector(&fakeInjector{})
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).InjectOperatorOp(
		context.Background(), &frienv1.InjectOperatorOpRequest{Envelope: &frienv1.OperationEnvelope{}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a missing op_id, got %v", status.Code(err))
	}
}

func TestInjectOperatorOp_ReadOnly(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, true, zerolog.Nop()) // read-only
	injector := &fakeInjector{}
	admin.SetOperatorOpInjector(injector)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).InjectOperatorOp(
		context.Background(), &frienv1.InjectOperatorOpRequest{Envelope: &frienv1.OperationEnvelope{OpId: "op1"}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on a read-only admin API, got %v", status.Code(err))
	}
	if injector.lastEnv != nil {
		t.Fatal("the injector must never be called when the admin API is read-only")
	}
}

func TestTriggerCompaction_Routes(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	compactor := &fakeCompactor{compacted: []string{"zone:eu"}}
	admin.SetCompactionTrigger(compactor)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	resp, err := frienv1.NewAdminServiceClient(conn).TriggerCompaction(
		context.Background(), &frienv1.TriggerCompactionRequest{Scope: "zone:eu"})
	if err != nil {
		t.Fatalf("TriggerCompaction: %v", err)
	}
	if compactor.lastScope != "zone:eu" {
		t.Fatalf("scope forwarded = %q, want zone:eu", compactor.lastScope)
	}
	if len(resp.GetCompactedScopes()) != 1 || resp.GetCompactedScopes()[0] != "zone:eu" {
		t.Fatalf("compacted_scopes = %v, want [zone:eu]", resp.GetCompactedScopes())
	}
}

func TestTriggerCompaction_ReadOnlyRejects(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, true, zerolog.Nop())
	compactor := &fakeCompactor{}
	admin.SetCompactionTrigger(compactor)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).TriggerCompaction(context.Background(), &frienv1.TriggerCompactionRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on a read-only admin API, got %v", status.Code(err))
	}
}

type fakeRotator struct {
	lastPEM []byte
	err     error
}

func (f *fakeRotator) PrepareNext(pem []byte) error {
	f.lastPEM = pem
	return f.err
}

func TestRotateCA_RoutesToRotator(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	rotator := &fakeRotator{}
	admin.SetCARotator(rotator)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	resp, err := frienv1.NewAdminServiceClient(conn).RotateCA(
		context.Background(), &frienv1.RotateCARequest{NextCaPem: []byte("pem-bytes")})
	if err != nil {
		t.Fatalf("RotateCA: %v", err)
	}
	if !resp.GetInOverlap() {
		t.Fatal("expected in_overlap=true on success")
	}
	if string(rotator.lastPEM) != "pem-bytes" {
		t.Fatalf("rotator received %q, want pem-bytes", rotator.lastPEM)
	}
}

func TestRotateCA_RejectsEmptyPEM(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, false, zerolog.Nop())
	admin.SetCARotator(&fakeRotator{})
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).RotateCA(context.Background(), &frienv1.RotateCARequest{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty PEM, got %v", status.Code(err))
	}
}

func TestRotateCA_ReadOnlyRejects(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{NodeID: "n"} })
	socket := filepath.Join(t.TempDir(), "admin.sock")
	admin := NewAdminService(src, true, zerolog.Nop())
	rotator := &fakeRotator{}
	admin.SetCARotator(rotator)
	srv, err := NewServer(Options{SocketPath: socket, MaxRecvBytes: 512 * 1024}, admin, zerolog.Nop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	conn := dialSocket(t, socket)
	defer conn.Close()
	_, err = frienv1.NewAdminServiceClient(conn).RotateCA(
		context.Background(), &frienv1.RotateCARequest{NextCaPem: []byte("pem")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on a read-only admin API, got %v", status.Code(err))
	}
	if rotator.lastPEM != nil {
		t.Fatal("the rotator must never be called when the admin API is read-only")
	}
}

func TestNewServer_NoListenerConfigured(t *testing.T) {
	src := StatusFunc(func() StatusInfo { return StatusInfo{} })
	admin := NewAdminService(src, false, zerolog.Nop())
	if _, err := NewServer(Options{}, admin, zerolog.Nop()); err == nil {
		t.Fatal("a server with no socket and no TCP listener must fail to construct")
	}
}

func TestListenUnix_RejectsNonSocketFile(t *testing.T) {
	// A regular file at the socket path must not be clobbered.
	dir := t.TempDir()
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("real data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(regular, 0o660); err == nil {
		t.Fatal("listenUnix must refuse to clobber a non-socket file")
	}
	// And the file must still be intact (never destroyed).
	if data, err := os.ReadFile(regular); err != nil || string(data) != "real data" {
		t.Fatalf("non-socket file was damaged: data=%q err=%v", data, err)
	}
}
