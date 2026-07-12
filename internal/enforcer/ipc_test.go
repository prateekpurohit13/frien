package enforcer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// startTestServer brings up an enforcer IPC server on a temp socket and returns
// a socket client plus the underlying enforcer for assertions.
func startTestServer(t *testing.T, clk *fakeClock, dm *Deadman) (*SocketClient, *Enforcer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "enf.sock")
	rb, _ := NewRollbackStore(testDB(t))
	e := New(rb, clk.now, zerolog.Nop())
	e.Register(NewMemAdapter("nftables", clk.now), ModeEnforce)

	srv := NewServer(e, dm, sock, zerolog.Nop())
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx)

	return NewSocketClient(sock), e
}

func TestIPCApplyListRollbackFlush(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	client, _ := startTestServer(t, clk, nil)

	applied, err := client.Apply(blockDecision("d1", "203.0.113.9", "30m"))
	if err != nil || !applied {
		t.Fatalf("apply over socket: applied=%v err=%v", applied, err)
	}
	rules, err := client.List()
	if err != nil || len(rules) != 1 {
		t.Fatalf("list over socket: rules=%+v err=%v", rules, err)
	}
	status, err := client.Rollback("tok-d1", "test")
	if err != nil || status != RollbackRemoved {
		t.Fatalf("rollback over socket: status=%s err=%v", status, err)
	}

	// Re-apply two and flush.
	_, _ = client.Apply(blockDecision("d2", "203.0.113.10", "30m"))
	_, _ = client.Apply(blockDecision("d3", "203.0.113.11", "30m"))
	n, err := client.Flush("breakglass")
	if err != nil || n != 2 {
		t.Fatalf("flush over socket: n=%d err=%v", n, err)
	}
}

func TestIPCSetGetMode(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	client, _ := startTestServer(t, clk, nil)

	if m, err := client.GetMode("nftables"); err != nil || m != ModeEnforce {
		t.Fatalf("get mode: %s err=%v", m, err)
	}
	prev, err := client.SetMode("nftables", ModeObserve)
	if err != nil || prev != ModeEnforce {
		t.Fatalf("set mode: prev=%s err=%v", prev, err)
	}
	if m, _ := client.GetMode("nftables"); m != ModeObserve {
		t.Fatalf("mode not changed, got %s", m)
	}
}

// TestIPCHeartbeatArmsDeadman proves the request-is-a-heartbeat behavior: a
// steady stream of IPC calls keeps the dead-man's switch from firing.
func TestIPCHeartbeatArmsDeadman(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	fired := 0
	dm := NewDeadman(60*time.Millisecond, func() { fired++ }, zerolog.Nop())
	client, _ := startTestServer(t, clk, dm)

	ctx, cancel := context.WithCancel(context.Background())
	go dm.Run(ctx)
	for i := 0; i < 8; i++ {
		if err := client.Heartbeat(); err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	if fired != 0 {
		t.Fatalf("deadman fired despite steady heartbeats: %d", fired)
	}
}
