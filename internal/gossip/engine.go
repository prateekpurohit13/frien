package gossip

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/membership"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/transport"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Config tunes the gossip engine. Membership timings map onto the SWIM config.
type Config struct {
	NodeID           string
	Zone             string
	LocalAddr        string   // address peers should dial back (advertised in membership)
	Seeds            []string // bootstrap peer addresses
	SubscribedScopes []string // scope keys to anti-entropy ("fleet", "zone:<name>", ...)
	SkewWindow       time.Duration
	GossipInterval   time.Duration
	ProtoVersion     uint32
	MaxUpdatesPerMsg int
	MaxOpsPerScope   int // 0 = unlimited; inbound memory bound

	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	SuspectMultiplier int
	IndirectProbes    int
}

func (c *Config) withDefaults() {
	if c.GossipInterval == 0 {
		c.GossipInterval = time.Second
	}
	if c.SkewWindow == 0 {
		c.SkewWindow = 10 * time.Second
	}
	if c.ProtoVersion == 0 {
		c.ProtoVersion = 1
	}
	if c.MaxUpdatesPerMsg == 0 {
		c.MaxUpdatesPerMsg = 16
	}
	if c.ProbeInterval == 0 {
		c.ProbeInterval = time.Second
	}
	if c.ProbeTimeout == 0 {
		c.ProbeTimeout = 500 * time.Millisecond
	}
	if c.SuspectMultiplier == 0 {
		c.SuspectMultiplier = 4
	}
	if c.IndirectProbes == 0 {
		c.IndirectProbes = 2
	}
}

// Engine assembles transport, membership, the CRDT op set, and the scope router
// into a running mesh node. It serves inbound peer streams, drives SWIM probes
// and per-scope anti-entropy, and ingests ops through the scope + clock-skew
// gates before they enter the set.
type Engine struct {
	cfg    Config
	clock  *crdt.Clock
	set    *crdt.OpSet
	router *scope.Router
	swim   *membership.SWIM
	mgr    *Manager
	log    zerolog.Logger

	seq atomic.Uint64

	mu        sync.Mutex
	watermark map[string]crdt.Timestamp
}

func New(cfg Config, clock *crdt.Clock, set *crdt.OpSet, router *scope.Router, tr *transport.Transport, log zerolog.Logger) *Engine {
	cfg.withDefaults()
	e := &Engine{
		cfg:       cfg,
		clock:     clock,
		set:       set,
		router:    router,
		log:       log,
		watermark: make(map[string]crdt.Timestamp),
	}
	e.mgr = NewManager(tr, e, log)
	e.swim = membership.New(cfg.NodeID, &prober{eng: e}, membership.Config{
		ProbeInterval:     cfg.ProbeInterval,
		ProbeTimeout:      cfg.ProbeTimeout,
		SuspectMultiplier: cfg.SuspectMultiplier,
		IndirectProbes:    cfg.IndirectProbes,
		RetransmitMult:    4,
	}, log, membership.WithLocalAddrs([]string{cfg.LocalAddr}))
	return e
}

// Start brings the node online: it begins accepting peers, dials seeds, and runs
// the membership and anti-entropy loops until ctx is cancelled.
func (e *Engine) Start(ctx context.Context) error {
	if err := e.mgr.Listen(ctx); err != nil {
		return err
	}
	go e.bootstrap(ctx)
	go supervise(ctx, e.log, "swim", loopRestartBackoff, e.swim.Run)
	go supervise(ctx, e.log, "gossip", loopRestartBackoff, e.gossipLoop)
	return nil
}

// Peers returns the current membership roster (for the ListPeers admin RPC).
func (e *Engine) Peers() []membership.Member { return e.swim.List().Members() }

// Watermarks returns the highest HLC observed per origin node, for the Phase 4
// compaction stable cut.
func (e *Engine) Watermarks() map[string]crdt.Timestamp {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]crdt.Timestamp, len(e.watermark))
	for k, v := range e.watermark {
		out[k] = v
	}
	return out
}

// Publish creates a locally-originated op, stamps it with a fresh HLC and the
// node's next sequence number, and adds it to the local set. Signing is applied
// by the Phase 4 verify layer; here the envelope carries identity and ordering.
func (e *Engine) Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error) {
	if _, err := scope.Parse(scopeKey); err != nil {
		return nil, err
	}
	body, err := proto.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gossip: marshal payload: %w", err)
	}
	opID, err := newOpID()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	env := &frienv1.OperationEnvelope{
		ProtoVersion: e.cfg.ProtoVersion,
		OpId:         opID,
		OpType:       opType,
		NodeId:       e.cfg.NodeID,
		Hlc:          e.clock.Now().String(),
		Seq:          e.seq.Add(1),
		PayloadHash:  "sha256:" + hex.EncodeToString(sum[:]),
		Payload:      body,
		SignedBy:     "node",
	}
	if _, err := e.set.Add(env); err != nil {
		return nil, err
	}
	return env, nil
}

func (e *Engine) bootstrap(ctx context.Context) {
	for _, seed := range e.cfg.Seeds {
		for attempt := 0; attempt < 10; attempt++ {
			if ctx.Err() != nil {
				return
			}
			sess, err := e.mgr.Dial(ctx, seed)
			if err == nil {
				e.swim.Seed(sess.NodeID, []string{seed})
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
}

func (e *Engine) gossipLoop(ctx context.Context) {
	t := time.NewTicker(e.cfg.GossipInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.gossipRound(ctx)
		}
	}
}

func (e *Engine) gossipRound(ctx context.Context) {
	for _, m := range e.swim.List().ActiveMembers() {
		if m.NodeID == e.cfg.NodeID || len(m.Addresses) == 0 {
			continue
		}
		sess, err := e.mgr.SessionFor(ctx, m.NodeID, m.Addresses[0])
		if err != nil {
			continue
		}
		for _, scopeKey := range e.cfg.SubscribedScopes {
			req := &frienv1.AntiEntropyRequest{
				ProtoVersion: e.cfg.ProtoVersion,
				RequesterId:  e.cfg.NodeID,
				Zone:         e.cfg.Zone,
				Scope:        scopeKey,
				HaveOpIds:    e.set.OpIDsInScope(scopeKey),
			}
			var resp frienv1.AntiEntropyResponse
			if err := roundtrip(ctx, sess, kindAntiEntropy, req, &resp); err != nil {
				e.mgr.drop(m.NodeID)
				break
			}
			for _, env := range resp.GetMissingOps() {
				e.ingest(env)
			}
		}
	}
}

// ingest applies a received op after the scope and clock-skew gates. A bad HLC
// or out-of-window skew is rejected before the op can enter the set.
func (e *Engine) ingest(env *frienv1.OperationEnvelope) {
	if !e.router.Accept(crdt.EnvelopeScope(env)) {
		return
	}
	ts, err := crdt.ParseTimestamp(env.GetHlc())
	if err != nil {
		return
	}
	if err := e.clock.CheckSkew(ts, e.cfg.SkewWindow); err != nil {
		return
	}
	if e.cfg.MaxOpsPerScope > 0 && !e.set.Has(env.GetOpId()) {
		if len(e.set.OpIDsInScope(crdt.EnvelopeScope(env).String())) >= e.cfg.MaxOpsPerScope {
			return
		}
	}
	if _, err := e.clock.Update(ts); err != nil {
		return
	}
	res, err := e.set.Add(env)
	if err != nil {
		return
	}
	e.recordWatermark(env.GetNodeId(), ts)
	if res.Equivocation != nil {
		e.log.Warn().Str("offender", env.GetNodeId()).Uint64("seq", env.GetSeq()).Msg("equivocation detected")
	}
}

func (e *Engine) recordWatermark(nodeID string, ts crdt.Timestamp) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, ok := e.watermark[nodeID]; !ok || ts.Compare(cur) > 0 {
		e.watermark[nodeID] = ts
	}
}

func (e *Engine) outUpdates() []*frienv1.PeerUpdate {
	self := &frienv1.PeerUpdate{
		NodeId:      e.cfg.NodeID,
		Addresses:   []string{e.cfg.LocalAddr},
		State:       uint32(membership.StateAlive),
		Incarnation: e.swim.List().LocalIncarnation(),
	}
	return append([]*frienv1.PeerUpdate{self}, drainUpdates(e.swim, e.cfg.MaxUpdatesPerMsg)...)
}

// OnPing applies the prober's piggybacked updates and acks with our own.
func (e *Engine) OnPing(p *frienv1.Ping) *frienv1.Ack {
	applyUpdates(e.swim, p.GetUpdates())
	return &frienv1.Ack{ResponderNodeId: e.cfg.NodeID, Reachable: true, Updates: e.outUpdates()}
}

// OnPingReq relays an indirect probe: it pings the requested target and reports
// whether the target was reachable.
func (e *Engine) OnPingReq(ctx context.Context, pr *frienv1.PingReq) *frienv1.Ack {
	applyUpdates(e.swim, pr.GetUpdates())
	reachable := e.directProbe(ctx, pr.GetTargetAddress())
	return &frienv1.Ack{ResponderNodeId: e.cfg.NodeID, Reachable: reachable, Updates: e.outUpdates()}
}

// OnAntiEntropy returns the ops in the requested scope that the requester lacks,
// gated by egress scope rules so a peer only receives scopes meant for its zone.
func (e *Engine) OnAntiEntropy(req *frienv1.AntiEntropyRequest) *frienv1.AntiEntropyResponse {
	sc, err := scope.Parse(req.GetScope())
	if err != nil || !e.router.ShouldSend(sc, req.GetZone()) {
		return &frienv1.AntiEntropyResponse{}
	}
	have := make(map[string]struct{}, len(req.GetHaveOpIds()))
	for _, id := range req.GetHaveOpIds() {
		have[id] = struct{}{}
	}
	var missing []*frienv1.OperationEnvelope
	for _, id := range e.set.OpIDsInScope(req.GetScope()) {
		if _, ok := have[id]; ok {
			continue
		}
		if env, ok := e.set.Get(id); ok {
			missing = append(missing, env)
		}
	}
	return &frienv1.AntiEntropyResponse{MissingOps: missing}
}

func (e *Engine) directProbe(ctx context.Context, addr string) bool {
	if addr == "" {
		return false
	}
	sess, err := e.mgr.Dial(ctx, addr)
	if err != nil {
		return false
	}
	req := &frienv1.Ping{ProtoVersion: e.cfg.ProtoVersion, SenderNodeId: e.cfg.NodeID, Updates: e.outUpdates()}
	var ack frienv1.Ack
	return roundtrip(ctx, sess, kindPing, req, &ack) == nil
}

func newOpID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("gossip: op id: %w", err)
	}
	return "op_" + hex.EncodeToString(b[:]), nil
}
