package tui

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Snapshot is one poll of the daemon's live state. Individual fields may be nil
// if their RPC failed (e.g. an older daemon without a given RPC); Err carries
// the first hard dial/transport error so the UI can show a disconnected state
// without losing the last good data.
type Snapshot struct {
	Status       *frienv1.GetStatusResponse
	Peers        []*frienv1.PeerState
	Threats      []*frienv1.ThreatRecord
	Enforcements []*frienv1.EnforcementDecision
	Stats        *frienv1.GetStatsResponse
	Audit        []*frienv1.AuditEntrySummary
	At           time.Time
	Err          error
}

// Client wraps the admin gRPC client for the dashboard.
type Client struct {
	conn  *grpc.ClientConn
	admin frienv1.AdminServiceClient
}

// Dial connects to the admin Unix socket.
func Dial(socketPath string) (*Client, error) {
	conn, err := grpc.NewClient("unix:"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, admin: frienv1.NewAdminServiceClient(conn)}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Fetch polls every dashboard RPC in one pass. It is tolerant: a per-RPC error
// leaves that field nil rather than failing the whole snapshot, so a daemon
// missing one RPC still renders everything else. GetStatus is the liveness
// probe — its error becomes Snapshot.Err (disconnected).
func (c *Client) Fetch(parent context.Context) Snapshot {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	snap := Snapshot{At: time.Now()}

	if st, err := c.admin.GetStatus(ctx, &frienv1.GetStatusRequest{}); err != nil {
		snap.Err = err
		return snap
	} else {
		snap.Status = st
	}
	if r, err := c.admin.ListPeers(ctx, &frienv1.ListPeersRequest{}); err == nil {
		snap.Peers = r.GetPeers()
	}
	if r, err := c.admin.ListThreats(ctx, &frienv1.ListThreatsRequest{}); err == nil {
		snap.Threats = r.GetThreats()
	}
	if r, err := c.admin.ListEnforcements(ctx, &frienv1.ListEnforcementsRequest{}); err == nil {
		snap.Enforcements = r.GetEnforcements()
	}
	if r, err := c.admin.GetStats(ctx, &frienv1.GetStatsRequest{}); err == nil {
		snap.Stats = r
	}
	if r, err := c.admin.ListAudit(ctx, &frienv1.ListAuditRequest{Limit: 40}); err == nil {
		snap.Audit = r.GetEntries()
	}
	return snap
}
