// Package checkpoint computes a conservative, peer-acknowledged safe cut for
// compacting the CRDT op set, and creates the signed Checkpoint op that
// records each cut taken.
package checkpoint

import "sync"

// PeerWatermarks tracks, for each peer this node has directly synced with and
// each scope that sync covered, the peer's own self-reported per-origin
// contiguous-seq watermark (as carried on an AntiEntropyRequest or
// AntiEntropyResponse's have_seqs field). It is the input to SafeFloor: a cut
// is only safe to compact past once every currently-live peer that replicates
// a scope has itself confirmed holding that scope's data up to that point.
//
// Tracking is per-scope, not a single number per peer: a node's anti-entropy
// loop runs one round per subscribed scope (see gossip.Engine.syncPeer), and
// a peer's fleet-scope watermark for an origin and that same peer's
// zone-scope watermark for the same origin are unrelated quantities -- an
// earlier single-map-per-peer version of this type conflated them, which
// would have silently corrupted the floor computation once zone-scope
// compaction (below) started actually using it.
type PeerWatermarks struct {
	mu     sync.RWMutex
	byPeer map[string]map[string]map[string]uint64 // peer_node_id -> scope_key -> origin_node_id -> watermark
}

func NewPeerWatermarks() *PeerWatermarks {
	return &PeerWatermarks{byPeer: make(map[string]map[string]map[string]uint64)}
}

// Observe records peerID's reported watermark for each origin in haveSeqs
// within scopeKey, keeping the maximum ever reported (a genuine watermark
// only advances). It also marks (peerID, scopeKey) as observed even if
// haveSeqs is empty, since a peer legitimately holding nothing yet in a scope
// is still a confirmed data point, not a missing one.
func (w *PeerWatermarks) Observe(peerID, scopeKey string, haveSeqs map[string]uint64) {
	if peerID == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	byScope := w.byPeer[peerID]
	if byScope == nil {
		byScope = make(map[string]map[string]uint64)
		w.byPeer[peerID] = byScope
	}
	m := byScope[scopeKey]
	if m == nil {
		m = make(map[string]uint64)
		byScope[scopeKey] = m
	}
	for origin, seq := range haveSeqs {
		if seq > m[origin] {
			m[origin] = seq
		}
	}
}

// Observed reports whether peerID has ever been recorded for scopeKey.
func (w *PeerWatermarks) Observed(peerID, scopeKey string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.byPeer[peerID][scopeKey]
	return ok
}

// SafeFloor computes, for each origin in selfHaveSeqs, the minimum watermark
// across self and every peer in livePeers within scopeKey. If any peer in
// livePeers has never been observed for scopeKey at all, SafeFloor returns
// nil: nothing is safe to compact until this node has directly confirmed a
// watermark report from every currently-live peer that replicates the scope,
// per the rule that a cut must be acknowledged across the whole live
// membership for that scope, not just a quorum of it -- a single unconfirmed
// partitioned-but-alive peer blocks the floor from advancing rather than
// risking a compaction it still needs.
//
// livePeers must already be restricted to peers that actually replicate
// scopeKey (fleet: every live peer; a zone: only that zone's live members,
// see gossip.Engine.LiveZonePeers) -- SafeFloor performs no such filtering
// itself, trusting its input.
func (w *PeerWatermarks) SafeFloor(scopeKey string, livePeers []string, selfHaveSeqs map[string]uint64) map[string]uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, p := range livePeers {
		if _, ok := w.byPeer[p][scopeKey]; !ok {
			return nil
		}
	}

	floor := make(map[string]uint64, len(selfHaveSeqs))
	for origin, seq := range selfHaveSeqs {
		floor[origin] = seq
	}
	for _, p := range livePeers {
		peerSeqs := w.byPeer[p][scopeKey]
		for origin, cur := range floor {
			if peerSeqs[origin] < cur {
				floor[origin] = peerSeqs[origin]
			}
		}
	}
	return floor
}
