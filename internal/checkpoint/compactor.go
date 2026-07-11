package checkpoint

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/identity"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Publisher is the minimal surface Compactor needs to gossip a signed
// checkpoint op; gossip.Engine satisfies it.
type Publisher interface {
	Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error)
}

// LivePeersFunc returns the node ids of currently active peers that actually
// replicate scopeKey, excluding self -- gossip.Engine.LiveFleetPeers for
// "fleet", gossip.Engine.LiveZonePeers(zone) for a "zone:<name>" key. A
// SafeFloor computed against the wrong set (e.g. the whole fleet for a zone
// scope) would either never be safe to use (an out-of-zone peer never
// legitimately reports a zone watermark, permanently blocking the floor) or,
// worse, compact data a real in-zone peer hasn't synced yet -- see this
// package's former single-scope doc comment for the fleet-only restriction
// this generalization replaces.
type LivePeersFunc func(scopeKey string) []string

type checkpointState struct{ id, treeHead string }

// Compactor periodically computes a peer-acknowledged safe cut for each scope
// it's given, applies it to the local op set, and publishes a signed
// Checkpoint per scope chaining from that scope's previous one recording each
// cut actually taken. Each scope's chain is independent: a fleet checkpoint
// and a zone checkpoint never share a prev_checkpoint lineage.
type Compactor struct {
	set        *crdt.OpSet
	watermarks *PeerWatermarks
	pub        Publisher
	scopes     func() []string
	livePeers  LivePeersFunc
	signer     *identity.Ed25519Signer
	log        zerolog.Logger

	mu   sync.Mutex
	last map[string]checkpointState // scope_key -> latest checkpoint built for it
}

// NewCompactor builds a Compactor. scopes is called fresh each RunOnce so a
// node whose subscribed zones change (an aggregator reconfigured) picks that
// up without a restart.
func NewCompactor(set *crdt.OpSet, watermarks *PeerWatermarks, pub Publisher, scopes func() []string, livePeers LivePeersFunc, signer *identity.Ed25519Signer, log zerolog.Logger) *Compactor {
	return &Compactor{
		set: set, watermarks: watermarks, pub: pub, scopes: scopes, livePeers: livePeers,
		signer: signer, log: log, last: make(map[string]checkpointState),
	}
}

// Latest returns the most recent checkpoint this node has itself built for
// scopeKey (id and its chained tree_head), or ok=false if none has been built
// yet. The anti-entropy loop uses this to populate AntiEntropyRequest's
// since_checkpoint and root_hash fields: a peer that reports the same
// checkpoint id back with a matching tree_head has cheaply confirmed its
// entire history through that cut is identical to this node's, without
// exchanging a single op id.
func (c *Compactor) Latest(scopeKey string) (id, treeHead string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.last[scopeKey]
	return st.id, st.treeHead, ok
}

// Run compacts on an interval until ctx is cancelled. A zero interval defaults
// to one minute.
func (c *Compactor) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.RunOnce()
		}
	}
}

// RunOnce attempts a compaction cut for every currently configured scope.
// Each scope is independent: one scope having no safe floor yet (or nothing
// to compact) does not block the others.
func (c *Compactor) RunOnce() {
	for _, scopeKey := range c.scopes() {
		c.compactScope(scopeKey)
	}
}

// compactScope computes the current safe floor for scopeKey and compacts the
// local set once, publishing a signed checkpoint if anything was removed. It
// is a no-op whenever SafeFloor is not yet safe to use (not every live peer
// that replicates scopeKey has been confirmed) or nothing crosses the
// resulting cut.
func (c *Compactor) compactScope(scopeKey string) {
	peers := c.livePeers(scopeKey)
	selfHave, _ := c.set.ScopeState(scopeKey)
	floor := c.watermarks.SafeFloor(scopeKey, peers, selfHave)
	if len(floor) == 0 {
		return
	}

	removed := c.set.CompactBelow(scopeKey, floor)
	if len(removed) == 0 {
		return
	}

	c.mu.Lock()
	prev := c.last[scopeKey]
	c.mu.Unlock()

	// The tree head chains from the prior checkpoint's for this scope, so it
	// commits to the full compaction history for that scope rather than only
	// the latest round -- a replayed or reordered checkpoint op does not
	// reproduce a later tree head.
	treeHead := chainTreeHead(prev.treeHead, treeHeadFor(removed))
	coversThrough := highestHLC(removed)
	stateHash := c.set.CanonicalHash()

	cp, err := Build(prev.id, treeHead, coversThrough, stateHash, scopeKey, c.signer, time.Now())
	if err != nil {
		c.log.Error().Err(err).Str("scope", scopeKey).Msg("checkpoint: failed to build signed checkpoint")
		return
	}
	env, err := c.pub.Publish(crdt.OpCheckpoint, cp, scopeKey)
	if err != nil {
		c.log.Error().Err(err).Str("scope", scopeKey).Msg("checkpoint: failed to publish checkpoint op")
		return
	}

	c.mu.Lock()
	c.last[scopeKey] = checkpointState{id: cp.GetCheckpointId(), treeHead: treeHead}
	c.mu.Unlock()

	c.log.Info().
		Str("scope", scopeKey).
		Str("checkpoint_id", cp.GetCheckpointId()).
		Int("compacted", len(removed)).
		Str("op_id", env.GetOpId()).
		Msg("compaction checkpoint created")
}

func chainTreeHead(prev, next string) string {
	if prev == "" {
		return next
	}
	return treeHeadFor([]*frienv1.OperationEnvelope{
		{OpId: prev, PayloadHash: prev},
		{OpId: next, PayloadHash: next},
	})
}

// highestHLC returns the largest HLC string among envs by causal order, not
// lexical order. Malformed HLCs are skipped rather than aborting the whole
// checkpoint over one bad record.
func highestHLC(envs []*frienv1.OperationEnvelope) string {
	var best string
	var bestTS crdt.Timestamp
	haveBest := false
	for _, env := range envs {
		ts, err := crdt.ParseTimestamp(env.GetHlc())
		if err != nil {
			continue
		}
		if !haveBest || ts.Compare(bestTS) > 0 {
			best, bestTS, haveBest = env.GetHlc(), ts, true
		}
	}
	return best
}
