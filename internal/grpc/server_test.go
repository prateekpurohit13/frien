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
