// Package checkpoint computes a conservative, peer-acknowledged safe cut for
// compacting the CRDT op set, and creates the signed Checkpoint op that
// records each cut taken.
package checkpoint

import "sync"

// PeerWatermarks tracks, for each peer this node has directly synced with, the
// peer's own self-reported per-origin contiguous-seq watermark (as carried on
// an AntiEntropyRequest or AntiEntropyResponse's have_seqs field). It is the
// input to SafeFloor: a cut is only safe to compact past once every
// currently-live peer has itself confirmed holding the data up to that point.
type PeerWatermarks struct {
	mu     sync.RWMutex
	byPeer map[string]map[string]uint64 // peer_node_id -> origin_node_id -> watermark
}

func NewPeerWatermarks() *PeerWatermarks {
	return &PeerWatermarks{byPeer: make(map[string]map[string]uint64)}
}

// Observe records peerID's reported watermark for each origin in haveSeqs,
// keeping the maximum ever reported (a genuine watermark only advances). It
// also marks peerID as observed even if haveSeqs is empty, since a peer
// legitimately holding nothing yet is still a confirmed data point, not a
// missing one.
func (w *PeerWatermarks) Observe(peerID string, haveSeqs map[string]uint64) {
	if peerID == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.byPeer[peerID]
	if m == nil {
		m = make(map[string]uint64)
		w.byPeer[peerID] = m
	}
	for origin, seq := range haveSeqs {
		if seq > m[origin] {
			m[origin] = seq
		}
	}
}

// Observed reports whether peerID has ever been recorded.
func (w *PeerWatermarks) Observed(peerID string) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.byPeer[peerID]
	return ok
}

// SafeFloor computes, for each origin in selfHaveSeqs, the minimum watermark
// across self and every peer in livePeers. If any peer in livePeers has never
// been observed at all, SafeFloor returns nil: nothing is safe to compact
// until this node has directly confirmed a watermark report from every
// currently-live peer, per the rule that a cut must be acknowledged across the
// whole live membership, not just a quorum of it -- a single unconfirmed
// partitioned-but-alive peer blocks the floor from advancing rather than
// risking a compaction it still needs.
//
// livePeers must be restricted to peers that actually replicate the scope
// selfHaveSeqs was computed for (see internal/checkpoint's package docs and
// the Compactor for why this matters for anything narrower than fleet scope).
func (w *PeerWatermarks) SafeFloor(livePeers []string, selfHaveSeqs map[string]uint64) map[string]uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, p := range livePeers {
		if _, ok := w.byPeer[p]; !ok {
			return nil
		}
	}

	floor := make(map[string]uint64, len(selfHaveSeqs))
	for origin, seq := range selfHaveSeqs {
		floor[origin] = seq
	}
	for _, p := range livePeers {
		peerSeqs := w.byPeer[p]
		for origin, cur := range floor {
			if peerSeqs[origin] < cur {
				floor[origin] = peerSeqs[origin]
			}
		}
	}
	return floor
}
