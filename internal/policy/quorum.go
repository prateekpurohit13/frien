package policy

import (
	"sort"
	"time"
)

// Contribution is one distinct-identity report for a single indicator, already
// decoded from a present threat-record op by the collector. The op set has
// already deduplicated by op_id, so gossip amplification (the same signed op
// arriving from many peers) cannot appear here twice. QuorumResult additionally
// collapses multiple ops from the same origin identity down to one contributor,
// so a single node cannot inflate quorum by publishing many reports either.
type Contribution struct {
	OpID        string    // op_id of the threat-record envelope
	OriginNode  string    // envelope node_id — the authoring identity
	Fingerprint string    // cert fingerprint of the origin; the distinctness/revocation key
	TrustTier   string    // "standard" | "trusted" | "high"
	Confidence  float64   // report confidence 0.0-1.0
	ReceivedAt  time.Time // LOCAL receive clock (never origin wall-clock)
	Revoked     bool      // origin identity is revoked or tainted — excluded from fresh quorum
}

// identity returns the key a contribution is counted under: the cert
// fingerprint when present, else the origin node id. Two reports sharing this
// key count as one contributor.
func (c Contribution) identity() string {
	if c.Fingerprint != "" {
		return c.Fingerprint
	}
	return c.OriginNode
}

// QuorumResult is the outcome of counting contributions against a policy.
type QuorumResult struct {
	Met            bool
	MatchedWeight  float64
	RequiredWeight float64
	// Identities are the distinct origin identities that counted, sorted for a
	// stable explanation. Excluded (revoked, low-confidence, out-of-window)
	// contributions never appear here.
	Identities []string
	// Reason explains a shortfall (empty when Met).
	Reason string
}

// EvaluateQuorum counts contributions toward the policy's required weight under
// the four rules from docs/FRIEN_ARCHITECTURE.md §8.1:
//
//   - Distinct identities only. Each identity contributes at most once; the
//     strongest tier seen for that identity is used.
//   - Trust-tier weighting. Weight, not raw count.
//   - Bounded window by LOCAL receive time. A report older than the quorum
//     window (measured against now, the local clock) does not count.
//   - Revoked/tainted identities do not count as fresh contributors.
//
// Confidence below the policy's min_confidence also excludes a contribution.
func EvaluateQuorum(p *Policy, contribs []Contribution, now time.Time) QuorumResult {
	window := p.QuorumWindowDuration()
	cutoff := now.Add(-window)

	// Best weight per distinct identity (strongest qualifying report wins).
	byIdentity := make(map[string]float64)
	for _, c := range contribs {
		if c.Revoked {
			continue
		}
		if c.Confidence < p.MinConfidence {
			continue
		}
		// Window is inclusive of now and the cutoff instant; a report exactly at
		// the boundary counts. A future-dated local receive time (clock went
		// backward) is also accepted — the local clock is authoritative here.
		if c.ReceivedAt.Before(cutoff) {
			continue
		}
		w := p.WeightFor(c.TrustTier)
		if w > byIdentity[c.identity()] {
			byIdentity[c.identity()] = w
		}
	}

	res := QuorumResult{RequiredWeight: p.RequireWeight}
	for id, w := range byIdentity {
		res.MatchedWeight += w
		res.Identities = append(res.Identities, id)
	}
	sort.Strings(res.Identities)

	res.Met = res.MatchedWeight >= p.RequireWeight
	if !res.Met {
		res.Reason = "insufficient quorum weight from distinct identities within the window"
	}
	return res
}

// PartitionState is the node's view of how much of the fleet it can currently
// observe, used only for fleet-scoped decisions. LiveDistinct is the count of
// distinct, non-revoked identities currently reachable (alive membership plus
// self); KnownDistinct is every distinct non-revoked identity the node has ever
// learned of. A node is in a safe (majority) partition when it can observe a
// strict majority of the identities it knows about.
type PartitionState struct {
	LiveDistinct  int
	KnownDistinct int
}

// IsMajority reports whether the node can see a strict majority of known
// distinct identities. With no known peers (KnownDistinct <= 1, i.e. a
// single-node fleet) it is trivially a majority — a standalone node acting on
// its own directly-observed evidence is not "partitioned". Fleet enforcement
// is withheld whenever this is false, regardless of how much weight was
// matched: consistency of the decision over availability of enforcement.
func (ps PartitionState) IsMajority() bool {
	if ps.KnownDistinct <= 1 {
		return true
	}
	return ps.LiveDistinct*2 > ps.KnownDistinct
}
