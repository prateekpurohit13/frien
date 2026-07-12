package enforcer

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Client is the daemon-facing enforcement contract. The friend daemon computes
// decisions and calls a Client; whether that Client drives the firewall in this
// process or forwards to the privileged frien-enforcer over a socket is an
// injection choice the daemon makes at startup. Both implementations here honor
// the same contract so the coordinator and admin RPCs never branch on it.
type Client interface {
	// Apply installs the decision's rule if its adapter is in enforce mode.
	Apply(d *frienv1.EnforcementDecision) (applied bool, err error)
	// Rollback removes an applied rule by token.
	Rollback(token, reason string) (status string, err error)
	// Flush removes every frien-managed rule (breakglass).
	Flush(reason string) (count int, err error)
	// List returns active frien-managed rules across adapters.
	List() ([]ActiveRule, error)
	// SetMode transitions an adapter's mode, returning the previous mode.
	SetMode(adapter, mode string) (prev string, err error)
	// GetMode returns an adapter's current mode.
	GetMode(adapter string) (string, error)
	// Heartbeat re-arms the enforcer's dead-man's switch.
	Heartbeat() error
	// Close releases any client resources.
	Close() error
}

// ── in-process client ───────────────────────────────────────────────────────

// InProcClient drives an Enforcer directly in the daemon's own process. It is
// used in single-process deployments and in tests; the dead-man's switch it
// beats (if any) is likewise in-process.
type InProcClient struct {
	e  *Enforcer
	dm *Deadman // optional; may be nil
}

// NewInProcClient wraps an Enforcer (and optional Deadman) as a Client.
func NewInProcClient(e *Enforcer, dm *Deadman) *InProcClient {
	return &InProcClient{e: e, dm: dm}
}

func (c *InProcClient) Apply(d *frienv1.EnforcementDecision) (bool, error) { return c.e.Apply(d) }
func (c *InProcClient) Rollback(token, _ string) (string, error)           { return c.e.Rollback(token) }
func (c *InProcClient) Flush(reason string) (int, error)                   { return c.e.FlushAll(reason), nil }
func (c *InProcClient) List() ([]ActiveRule, error)                        { return listAll(c.e) }
func (c *InProcClient) SetMode(adapter, mode string) (string, error) {
	return c.e.SetMode(adapter, mode)
}
func (c *InProcClient) GetMode(adapter string) (string, error) { return c.e.Mode(adapter), nil }
func (c *InProcClient) Heartbeat() error {
	if c.dm != nil {
		c.dm.Beat()
	}
	return nil
}
func (c *InProcClient) Close() error { return nil }

// ── socket client ───────────────────────────────────────────────────────────

// SocketClient forwards each call to the frien-enforcer helper over its Unix
// socket, one request/response per dial. Dialing per call keeps the client
// stateless and resilient to an enforcer restart (the next call simply
// reconnects), at the cost of a connection setup per request — negligible for
// the low call rate of enforcement control.
type SocketClient struct {
	socketPath string
	timeout    time.Duration
	mu         sync.Mutex // serialize to keep call ordering deterministic
}

// NewSocketClient builds a client for the enforcer listening at socketPath.
func NewSocketClient(socketPath string) *SocketClient {
	return &SocketClient{socketPath: socketPath, timeout: dialTimeout}
}

func (c *SocketClient) roundTrip(req Request) (Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return Response{}, fmt.Errorf("enforcer: dialing %s: %w", c.socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.timeout))

	if err := writeFrame(conn, req); err != nil {
		return Response{}, fmt.Errorf("enforcer: sending %s: %w", req.Kind, err)
	}
	var resp Response
	if err := readFrame(bufio.NewReader(conn), &resp); err != nil {
		return Response{}, fmt.Errorf("enforcer: reading %s reply: %w", req.Kind, err)
	}
	if !resp.OK {
		return resp, fmt.Errorf("enforcer: %s failed: %s", req.Kind, resp.Error)
	}
	return resp, nil
}

func (c *SocketClient) Apply(d *frienv1.EnforcementDecision) (bool, error) {
	resp, err := c.roundTrip(Request{Kind: KindApply, Decision: d})
	return resp.Applied, err
}
func (c *SocketClient) Rollback(token, reason string) (string, error) {
	resp, err := c.roundTrip(Request{Kind: KindRollback, Token: token, Reason: reason})
	return resp.Status, err
}
func (c *SocketClient) Flush(reason string) (int, error) {
	resp, err := c.roundTrip(Request{Kind: KindFlush, Reason: reason})
	return resp.Count, err
}
func (c *SocketClient) List() ([]ActiveRule, error) {
	resp, err := c.roundTrip(Request{Kind: KindList})
	return resp.Rules, err
}
func (c *SocketClient) SetMode(adapter, mode string) (string, error) {
	resp, err := c.roundTrip(Request{Kind: KindSetMode, Adapter: adapter, Mode: mode})
	return resp.Mode, err
}
func (c *SocketClient) GetMode(adapter string) (string, error) {
	resp, err := c.roundTrip(Request{Kind: KindGetMode, Adapter: adapter})
	return resp.Mode, err
}
func (c *SocketClient) Heartbeat() error {
	_, err := c.roundTrip(Request{Kind: KindHeartbeat})
	return err
}
func (c *SocketClient) Close() error { return nil }

// listAll flattens a single-enforcer view for the in-process client.
func listAll(e *Enforcer) ([]ActiveRule, error) {
	e.mu.RLock()
	adapters := make([]Adapter, 0, len(e.adapters))
	for _, a := range e.adapters {
		adapters = append(adapters, a)
	}
	e.mu.RUnlock()
	var out []ActiveRule
	for _, a := range adapters {
		rules, err := a.List()
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}
