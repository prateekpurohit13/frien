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

// fleetScope is the only scope Compactor compacts. A zone scope cannot safely
// use the same mechanism yet: SafeFloor requires a watermark report from
// every live peer, but membership does not carry peer zone metadata, so there
// is no way to restrict "every live peer" to "every live peer that replicates
// this zone" -- a peer outside the zone would never legitimately report a
// watermark for it and would permanently block the floor. Fleet-scoped data
// is replicated to every node, so this restriction does not apply there.
const fleetScope = "fleet"

// Publisher is the minimal surface Compactor needs to gossip a signed
// checkpoint op; gossip.Engine satisfies it.
type Publisher interface {
	Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error)
}

// Compactor periodically computes a peer-acknowledged safe cut for the fleet
// scope, applies it to the local op set, and publishes a signed Checkpoint
// chaining from the previous one recording each cut actually taken.
type Compactor struct {
	set        *crdt.OpSet
	watermarks *PeerWatermarks
	pub        Publisher
	livePeers  func() []string
	signer     *identity.Ed25519Signer
	log        zerolog.Logger

	mu           sync.Mutex
	lastID       string
	lastTreeHead string
}

func NewCompactor(set *crdt.OpSet, watermarks *PeerWatermarks, pub Publisher, livePeers func() []string, signer *identity.Ed25519Signer, log zerolog.Logger) *Compactor {
	return &Compactor{set: set, watermarks: watermarks, pub: pub, livePeers: livePeers, signer: signer, log: log}
}

// Latest returns the most recent checkpoint this node has itself built (id
// and its chained tree_head), or ok=false if none has been built yet. The
// anti-entropy loop uses this to populate AntiEntropyRequest's since_checkpoint
// and root_hash fields: a peer that reports the same checkpoint id back with a
// matching tree_head has cheaply confirmed its entire history through that cut
// is identical to this node's, without exchanging a single op id.
func (c *Compactor) Latest() (id, treeHead string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastID, c.lastTreeHead, c.lastID != ""
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

// RunOnce computes the current safe floor for the fleet scope and compacts
// the local set once, publishing a signed checkpoint if anything was removed.
// It is a no-op whenever SafeFloor is not yet safe to use (not every live
// peer has been confirmed) or nothing crosses the resulting cut.
func (c *Compactor) RunOnce() {
	peers := c.livePeers()
	selfHave, _ := c.set.ScopeState(fleetScope)
	floor := c.watermarks.SafeFloor(peers, selfHave)
	if len(floor) == 0 {
		return
	}

	removed := c.set.CompactBelow(floor)
	if len(removed) == 0 {
		return
	}

	c.mu.Lock()
	prevID, prevTreeHead := c.lastID, c.lastTreeHead
	c.mu.Unlock()

	// The tree head chains from the prior checkpoint's, so it commits to the
	// full compaction history rather than only the latest round -- a replayed
	// or reordered checkpoint op does not reproduce a later tree head.
	treeHead := chainTreeHead(prevTreeHead, treeHeadFor(removed))
	coversThrough := highestHLC(removed)
	stateHash := c.set.CanonicalHash()

	cp, err := Build(prevID, treeHead, coversThrough, stateHash, c.signer, time.Now())
	if err != nil {
		c.log.Error().Err(err).Msg("checkpoint: failed to build signed checkpoint")
		return
	}
	env, err := c.pub.Publish(crdt.OpCheckpoint, cp, fleetScope)
	if err != nil {
		c.log.Error().Err(err).Msg("checkpoint: failed to publish checkpoint op")
		return
	}

	c.mu.Lock()
	c.lastID, c.lastTreeHead = cp.GetCheckpointId(), treeHead
	c.mu.Unlock()

	c.log.Info().
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
