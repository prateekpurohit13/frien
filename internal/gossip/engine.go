package gossip

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/checkpoint"
	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/membership"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/transport"
	"github.com/prateekpurohit13/frien/internal/verify"
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
	MaxOpsPerMsg     int // max ops returned per anti-entropy response; 0 => default
	GossipFanout     int // max peers anti-entropy'd per round; 0 => default

	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	SuspectMultiplier int
	IndirectProbes    int

	// OperatorPublicKey, when set, is the pinned key used to verify
	// operator-signed control ops (revocations, policies). Nil until an
	// operator root cert is configured.
	OperatorPublicKey ed25519.PublicKey
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
	if c.MaxOpsPerMsg == 0 {
		c.MaxOpsPerMsg = 256
	}
	if c.GossipFanout == 0 {
		c.GossipFanout = 4
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
	cfg            Config
	clock          *crdt.Clock
	set            *crdt.OpSet
	router         *scope.Router
	swim           *membership.SWIM
	mgr            *Manager
	log            zerolog.Logger
	signer         *identity.Ed25519Signer
	keys           *verify.KeyStore
	verifier       *verify.Verifier
	peerWatermarks *checkpoint.PeerWatermarks

	seq atomic.Uint64

	mu        sync.Mutex
	watermark map[string]crdt.Timestamp

	fanoutMu sync.Mutex
	fanout   int // adaptive per-round peer fan-out; 0 until first round
}

// New assembles a gossip engine bound to id's signing key: outgoing ops are
// signed with it, and incoming ops are verified against the sender's key,
// learned opportunistically from established mTLS sessions (see internal/verify).
func New(cfg Config, id *identity.Identity, clock *crdt.Clock, set *crdt.OpSet, router *scope.Router, tr *transport.Transport, log zerolog.Logger) *Engine {
	cfg.withDefaults()
	keys := verify.NewKeyStore()
	if len(cfg.OperatorPublicKey) > 0 {
		keys.SetOperatorKey(cfg.OperatorPublicKey)
	}
	e := &Engine{
		cfg:            cfg,
		clock:          clock,
		set:            set,
		router:         router,
		log:            log,
		signer:         id.Signer(),
		keys:           keys,
		verifier:       verify.NewVerifier(keys),
		peerWatermarks: checkpoint.NewPeerWatermarks(),
		watermark:      make(map[string]crdt.Timestamp),
	}
	e.mgr = NewManager(tr, e, keys, log)
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

// LiveFleetPeers returns the node ids of currently active (alive or suspect)
// peers, excluding self. Suspect peers are included deliberately: they are
// not yet confirmed dead, and a fleet-scope compaction floor must stay
// conservative against a peer that might still come back.
func (e *Engine) LiveFleetPeers() []string {
	members := e.swim.List().ActiveMembers()
	out := make([]string, 0, len(members))
	for _, m := range members {
		if m.NodeID != e.cfg.NodeID {
			out = append(out, m.NodeID)
		}
	}
	return out
}

// PeerWatermarks exposes the tracker of peer-acknowledged anti-entropy
// watermarks, the input internal/checkpoint's Compactor needs to compute a
// safe compaction floor.
func (e *Engine) PeerWatermarks() *checkpoint.PeerWatermarks { return e.peerWatermarks }

// ScopeState exposes the local op set's per-origin contiguous-seq watermark
// for scopeKey, the other input the Compactor needs alongside peer watermarks.
func (e *Engine) ScopeState(scopeKey string) (map[string]uint64, []string) {
	return e.set.ScopeState(scopeKey)
}

// CompactBelow applies a compaction floor to the local op set, forwarding to
// the underlying OpSet (see crdt.OpSet.CompactBelow for the safety contract).
func (e *Engine) CompactBelow(cuts map[string]uint64) []*frienv1.OperationEnvelope {
	return e.set.CompactBelow(cuts)
}

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
// node's next sequence number, signs it with the node's identity key, and adds
// it to the local set.
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
	msg := identity.CanonicalSignedContent(env.GetProtoVersion(), env.GetOpId(), env.GetOpType(), env.GetNodeId(), env.GetHlc(), env.GetSeq(), env.GetParents(), env.GetPayloadHash(), env.GetSignedBy())
	sig, err := e.signer.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("gossip: signing op %s: %w", opID, err)
	}
	env.KeyId = e.signer.PublicKeyID()
	env.Signature = sig

	if _, err := e.set.Add(env); err != nil {
		return nil, err
	}
	return env, nil
}

const (
	bootstrapBaseBackoff = 200 * time.Millisecond
	bootstrapMaxBackoff  = 5 * time.Second
)

func (e *Engine) bootstrap(ctx context.Context) {
	// Spread a fleet-wide simultaneous restart so seeds are not all dialed in
	// lockstep, which would concentrate the rejoin load into one instant.
	if !sleepCtx(ctx, jitter(e.cfg.GossipInterval)) {
		return
	}
	for _, seed := range e.cfg.Seeds {
		backoff := bootstrapBaseBackoff
		for attempt := 0; attempt < 10; attempt++ {
			if ctx.Err() != nil {
				return
			}
			sess, err := e.mgr.Dial(ctx, seed)
			if err == nil {
				e.swim.Seed(sess.NodeID, []string{seed})
				break
			}
			if !sleepCtx(ctx, backoff+jitter(backoff)) {
				return
			}
			if backoff < bootstrapMaxBackoff {
				backoff *= 2
			}
		}
	}
}

// sleepCtx waits for d or until ctx is cancelled, returning true if the full
// duration elapsed and false if the context was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// jitter returns a random duration in [0, d) drawn from crypto/rand, used to
// desynchronize fleet-wide timers. It returns 0 for a non-positive d.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(d))
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

// gossipRound anti-entropies a bounded random subset of peers. The fan-out
// adapts to congestion: it backs off multiplicatively when a round mostly fails
// (peers unreachable or rate-limiting) and recovers additively when healthy, so
// a struggling mesh is not hammered with the full O(N) fan-out every round.
func (e *Engine) gossipRound(ctx context.Context) {
	peers := e.eligiblePeers()
	if len(peers) == 0 {
		return
	}
	e.shufflePeers(peers)
	if fanout := e.fanoutFor(len(peers)); fanout < len(peers) {
		peers = peers[:fanout]
	}

	failed := 0
	for _, m := range peers {
		if !e.syncPeer(ctx, m) {
			failed++
		}
	}
	e.adjustFanout(failed, len(peers))
}

func (e *Engine) eligiblePeers() []membership.Member {
	var out []membership.Member
	for _, m := range e.swim.List().ActiveMembers() {
		if m.NodeID == e.cfg.NodeID || len(m.Addresses) == 0 {
			continue
		}
		out = append(out, m)
	}
	return out
}

// syncPeer runs anti-entropy against one peer across every subscribed scope,
// returning false if the session or any exchange failed.
func (e *Engine) syncPeer(ctx context.Context, m membership.Member) bool {
	sess, err := e.mgr.SessionFor(ctx, m.NodeID, m.Addresses[0])
	if err != nil {
		return false
	}
	for _, scopeKey := range e.cfg.SubscribedScopes {
		haveSeqs, haveAbove := e.set.ScopeState(scopeKey)
		req := &frienv1.AntiEntropyRequest{
			ProtoVersion: e.cfg.ProtoVersion,
			RequesterId:  e.cfg.NodeID,
			Zone:         e.cfg.Zone,
			Scope:        scopeKey,
			HaveSeqs:     haveSeqs,
			HaveAbove:    haveAbove,
		}
		var resp frienv1.AntiEntropyResponse
		if err := roundtrip(ctx, sess, kindAntiEntropy, req, &resp); err != nil {
			e.mgr.drop(m.NodeID)
			return false
		}
		for _, env := range resp.GetMissingOps() {
			e.ingest(env)
		}
		if e.peerWatermarks != nil {
			e.peerWatermarks.Observe(m.NodeID, resp.GetHaveSeqs())
		}
	}
	return true
}

// fanoutFor returns how many of available peers to contact this round, seeding
// the adaptive target optimistically at the configured maximum on first use.
func (e *Engine) fanoutFor(available int) int {
	e.fanoutMu.Lock()
	defer e.fanoutMu.Unlock()
	if e.fanout == 0 {
		e.fanout = e.cfg.GossipFanout
	}
	f := e.fanout
	if f > available {
		f = available
	}
	if f < 1 {
		f = 1
	}
	return f
}

// adjustFanout applies AIMD to the fan-out target: halve it when a round mostly
// failed, otherwise step it back up toward the configured maximum.
func (e *Engine) adjustFanout(failed, contacted int) {
	if contacted == 0 {
		return
	}
	e.fanoutMu.Lock()
	defer e.fanoutMu.Unlock()
	switch {
	case failed*2 > contacted:
		e.fanout /= 2
		if e.fanout < 1 {
			e.fanout = 1
		}
	case e.fanout < e.cfg.GossipFanout:
		e.fanout++
	}
}

func (e *Engine) shufflePeers(peers []membership.Member) {
	for i := len(peers) - 1; i > 0; i-- {
		j := randIntn(i + 1)
		peers[i], peers[j] = peers[j], peers[i]
	}
}

// randIntn returns a uniform-ish int in [0, n) from crypto/rand.
func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

// ingest applies a received op after the scope and clock-skew gates. A bad HLC
// or out-of-window skew is rejected before the op can enter the set, and the
// per-scope cap is enforced atomically inside the set so concurrent ingests
// cannot race past it.
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
	if err := e.verifier.Verify(env); err != nil {
		if errors.Is(err, verify.ErrUnknownSigner) {
			e.log.Debug().Str("node", env.GetNodeId()).Str("op", env.GetOpId()).Msg("op held back: signer key not yet known")
		} else {
			e.log.Warn().Err(err).Str("node", env.GetNodeId()).Str("op", env.GetOpId()).Msg("op rejected: signature verification failed")
		}
		return
	}
	if _, err := e.clock.Update(ts); err != nil {
		return
	}
	res, err := e.set.AddWithLimit(env, e.cfg.MaxOpsPerScope)
	if err != nil {
		if errors.Is(err, crdt.ErrScopeFull) {
			e.log.Warn().Str("scope", crdt.EnvelopeScope(env).String()).Str("op", env.GetOpId()).Msg("op rejected: scope at capacity")
		}
		return
	}
	e.recordWatermark(env.GetNodeId(), ts)
	if res.Equivocation != nil {
		crdt.StampAttribution(res.Equivocation, e.cfg.NodeID, time.Now())
		e.log.Warn().
			Str("offender", env.GetNodeId()).
			Uint64("seq", env.GetSeq()).
			Str("proof_id", res.Equivocation.GetId()).
			Msg("equivocation detected")
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
// The response is capped at MaxOpsPerMsg so a large backlog (e.g. after a long
// partition) drains over several rounds instead of one unbounded message; op ids
// are iterated in sorted order, so successive rounds page forward deterministically.
func (e *Engine) OnAntiEntropy(req *frienv1.AntiEntropyRequest) *frienv1.AntiEntropyResponse {
	if e.peerWatermarks != nil {
		e.peerWatermarks.Observe(req.GetRequesterId(), req.GetHaveSeqs())
	}
	sc, err := scope.Parse(req.GetScope())
	if err != nil || !e.router.ShouldSend(sc, req.GetZone()) {
		return &frienv1.AntiEntropyResponse{}
	}
	above := make(map[string]struct{}, len(req.GetHaveAbove()))
	for _, id := range req.GetHaveAbove() {
		above[id] = struct{}{}
	}
	missing := e.set.MissingInRange(req.GetScope(), req.GetHaveSeqs(), above, e.cfg.MaxOpsPerMsg)
	haveSeqs, _ := e.set.ScopeState(req.GetScope())
	return &frienv1.AntiEntropyResponse{MissingOps: missing, HaveSeqs: haveSeqs}
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
