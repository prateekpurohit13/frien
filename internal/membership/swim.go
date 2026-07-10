package membership

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Prober carries SWIM probes over the network. It is deliberately transport-
// agnostic: the QUIC-backed implementation and the gossip pump that ships
// Updates between peers are wired in alongside the gossip layer. Ping directly
// probes a target; PingReq asks a relay to probe the target on our behalf.
type Prober interface {
	Ping(ctx context.Context, target Member) error
	PingReq(ctx context.Context, relay, target Member) error
}

// Config tunes the failure detector. Values map directly onto the daemon's
// membership config block.
type Config struct {
	ProbeInterval     time.Duration
	ProbeTimeout      time.Duration
	SuspectMultiplier int // suspicion timeout = SuspectMultiplier * ProbeInterval
	IndirectProbes    int // relays asked to indirectly probe a non-responding peer
	RetransmitMult    int // dissemination retransmits scale with this * log10(N)
}

func (c Config) suspicionTimeout() time.Duration {
	mult := c.SuspectMultiplier
	if mult <= 0 {
		mult = 4
	}
	return time.Duration(mult) * c.ProbeInterval
}

// maxAwareness bounds the local-health penalty; the probe interval and suspicion
// timeout scale by (awareness+1), so a degraded node backs off up to this factor.
const maxAwareness = 8

// SWIM is the failure detector and membership disseminator for one node.
type SWIM struct {
	localID    string
	localAddrs []string
	cfg        Config
	list       *MemberList
	prober     Prober
	now        func() time.Time
	log        zerolog.Logger

	rngMu sync.Mutex
	rng   *rand.Rand

	awMu      sync.Mutex
	awareness int // local-health penalty in [0, maxAwareness-1]; 0 == healthy

	queueMu sync.Mutex
	queue   []*broadcast
}

// broadcast is a pending membership update with a bounded retransmit budget,
// so an update is gossiped O(log N) times rather than forever.
type broadcast struct {
	update Update
	sends  int
}

// Option overrides defaults, primarily to make the driver deterministic in tests.
type Option func(*SWIM)

// WithClock injects a clock source.
func WithClock(now func() time.Time) Option { return func(s *SWIM) { s.now = now } }

// WithRand injects a deterministic random source for target selection.
func WithRand(r *rand.Rand) Option { return func(s *SWIM) { s.rng = r } }

// WithLocalAddrs records the node's own advertised addresses for refutation.
func WithLocalAddrs(addrs []string) Option { return func(s *SWIM) { s.localAddrs = addrs } }

func New(localID string, prober Prober, cfg Config, log zerolog.Logger, opts ...Option) *SWIM {
	s := &SWIM{
		localID: localID,
		cfg:     cfg,
		prober:  prober,
		now:     time.Now,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
		log:     log,
	}
	for _, o := range opts {
		o(s)
	}
	s.list = NewMemberList(localID, s.now)
	return s
}

// List exposes the roster for read access (e.g. the ListPeers admin RPC).
func (s *SWIM) List() *MemberList { return s.list }

// Seed records a known peer as alive, used for seed-node bootstrap.
func (s *SWIM) Seed(nodeID string, addrs []string) {
	s.Apply(Update{NodeID: nodeID, Addresses: addrs, State: StateAlive})
}

// Apply merges an incoming membership update and disseminates it onward. An
// accusation against this node is refuted with a higher-incarnation alive claim
// and counts against local health: being seen as dead means our acks are slow.
func (s *SWIM) Apply(u Update) {
	res := s.list.Apply(u)
	if res.AddrConflict {
		s.log.Warn().
			Str("node", u.NodeID).
			Strs("prev_addrs", res.PrevAddresses).
			Strs("new_addrs", u.Addresses).
			Uint64("incarnation", u.Incarnation).
			Msg("membership address conflict: known node now claims a different address")
	}
	switch {
	case res.SelfRefute:
		s.applyAwareness(1)
		s.enqueue(Update{NodeID: s.localID, Addresses: s.localAddrs, State: StateAlive, Incarnation: res.Incarnation})
	case res.Changed:
		s.enqueue(u)
	}
}

// applyAwareness moves the local-health penalty by delta, clamped to range.
func (s *SWIM) applyAwareness(delta int) {
	s.awMu.Lock()
	s.awareness += delta
	switch {
	case s.awareness < 0:
		s.awareness = 0
	case s.awareness > maxAwareness-1:
		s.awareness = maxAwareness - 1
	}
	s.awMu.Unlock()
}

// Awareness reports the current local-health penalty (0 == healthy).
func (s *SWIM) Awareness() int {
	s.awMu.Lock()
	defer s.awMu.Unlock()
	return s.awareness
}

// scaled stretches a base duration by the local-health penalty so a struggling
// node probes less aggressively and holds suspicions longer before declaring death.
func (s *SWIM) scaled(base time.Duration) time.Duration {
	s.awMu.Lock()
	mult := s.awareness + 1
	s.awMu.Unlock()
	return base * time.Duration(mult)
}

// ProbeOnce runs one SWIM protocol period: probe one peer directly, fall back to
// indirect probes through relays, and suspect the peer if all probes fail.
func (s *SWIM) ProbeOnce(ctx context.Context) {
	target, ok := s.pickTarget()
	if !ok {
		return
	}
	if s.directProbe(ctx, target) {
		s.applyAwareness(-1)
		s.Apply(Update{NodeID: target.NodeID, Addresses: target.Addresses, State: StateAlive, Incarnation: target.Incarnation})
		return
	}
	if s.indirectProbe(ctx, target) {
		s.Apply(Update{NodeID: target.NodeID, Addresses: target.Addresses, State: StateAlive, Incarnation: target.Incarnation})
		return
	}
	s.Apply(Update{NodeID: target.NodeID, State: StateSuspect, Incarnation: target.Incarnation})
}

// Tick promotes timed-out suspects to dead and disseminates the result. It is
// run once per protocol period by Run, and called directly in tests.
func (s *SWIM) Tick() {
	for _, u := range s.list.ExpireSuspects(s.scaled(s.cfg.suspicionTimeout())) {
		s.enqueue(u)
	}
}

// Run drives the protocol until the context is cancelled. The period adapts to
// local health so a degraded node paces itself down rather than probing blindly.
func (s *SWIM) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.scaled(s.cfg.ProbeInterval)):
			s.ProbeOnce(ctx)
			s.Tick()
		}
	}
}

func (s *SWIM) directProbe(ctx context.Context, target Member) bool {
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()
	return s.prober.Ping(pctx, target) == nil
}

// indirectProbe asks several relays to probe the target at once and returns on
// the first success, cancelling the stragglers. Racing the relays in parallel
// bounds detection latency at one ProbeTimeout regardless of relay count, so a
// single slow or lossy relay path cannot by itself push a live peer to suspect.
func (s *SWIM) indirectProbe(ctx context.Context, target Member) bool {
	relays := s.pickRelays(target, s.cfg.IndirectProbes)
	if len(relays) == 0 {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()

	results := make(chan bool, len(relays))
	for _, relay := range relays {
		go func(relay Member) {
			results <- s.prober.PingReq(pctx, relay, target) == nil
		}(relay)
	}
	for range relays {
		if <-results {
			return true
		}
	}
	return false
}

func (s *SWIM) pickTarget() (Member, bool) {
	active := s.list.ActiveMembers()
	if len(active) == 0 {
		return Member{}, false
	}
	s.rngMu.Lock()
	i := s.rng.Intn(len(active))
	s.rngMu.Unlock()
	return active[i], true
}

func (s *SWIM) pickRelays(target Member, k int) []Member {
	if k <= 0 {
		k = 1
	}
	active := s.list.ActiveMembers()
	candidates := make([]Member, 0, len(active))
	for _, m := range active {
		if m.NodeID != target.NodeID {
			candidates = append(candidates, m)
		}
	}
	s.rngMu.Lock()
	s.rng.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	s.rngMu.Unlock()
	if len(candidates) > k {
		candidates = candidates[:k]
	}
	return candidates
}

func (s *SWIM) enqueue(u Update) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	for _, b := range s.queue {
		if b.update.NodeID == u.NodeID {
			b.update = u
			b.sends = 0
			return
		}
	}
	s.queue = append(s.queue, &broadcast{update: u})
}

// Updates returns up to max pending membership updates to piggyback on outgoing
// gossip, charging each one a retransmit and retiring those past their budget.
func (s *SWIM) Updates(max int) []Update {
	limit := s.retransmitLimit()

	s.queueMu.Lock()
	defer s.queueMu.Unlock()

	out := make([]Update, 0, len(s.queue))
	kept := s.queue[:0]
	for _, b := range s.queue {
		if max > 0 && len(out) >= max {
			kept = append(kept, b)
			continue
		}
		out = append(out, b.update)
		b.sends++
		if b.sends < limit {
			kept = append(kept, b)
		}
	}
	s.queue = kept
	return out
}

func (s *SWIM) retransmitLimit() int {
	mult := s.cfg.RetransmitMult
	if mult <= 0 {
		mult = 4
	}
	n := len(s.list.Members()) + 1
	return mult * int(math.Ceil(math.Log10(float64(n+1))))
}
