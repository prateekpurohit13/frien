package tui

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Source supplies dashboard snapshots. The real backend (*Client) polls the
// admin socket; the demo source below synthesizes an evolving cluster so the TUI
// can be run and demoed with no daemon, certs, or network — `frienctl dashboard
// --demo`.
type Source interface {
	Fetch(ctx context.Context) Snapshot
}

// demoSource generates a plausible, slowly-evolving mesh: new threats arrive,
// some cross quorum and become self-expiring enforcements, rules expire, peers
// occasionally flap, and the audit tail grows. It keeps state across Fetch calls
// so charts and sparklines actually move.
type demoSource struct {
	mu    sync.Mutex
	rng   *rand.Rand
	start time.Time
	tick  int

	threats      []*frienv1.ThreatRecord
	enforcements []*frienv1.EnforcementDecision
	decisions    []*frienv1.DecisionStat
	audit        []*frienv1.AuditEntrySummary
	mode         string
	shed         int64
	nextIP       int
}

// NewDemoSource builds the synthetic source.
func NewDemoSource() Source {
	return &demoSource{
		rng:    rand.New(rand.NewSource(time.Now().UnixNano())),
		start:  time.Now(),
		mode:   "observe",
		nextIP: 10,
	}
}

var demoSeverities = []string{"low", "medium", "high", "critical"}
var demoDetectors = []string{"ssh_bruteforce", "http_rate_anomaly"}

func (d *demoSource) Fetch(_ context.Context) Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tick++
	now := time.Now()

	// Flip to enforce mode a few seconds in, to show the observe→enforce story.
	if d.tick == 6 {
		d.mode = "enforce"
		d.addAudit(now, "operator", "mode_set", "", "", "promoted nftables to enforce")
	}

	// Occasionally surface a new threat.
	if d.tick <= 2 || d.rng.Float64() < 0.5 {
		d.addThreat(now)
	}

	// Occasionally a present threat crosses quorum → enforce it (once).
	if d.mode == "enforce" && len(d.threats) > 0 && d.rng.Float64() < 0.4 {
		d.enforceOne(now)
	}

	// Expire the oldest enforcement now and then.
	if len(d.enforcements) > 4 && d.rng.Float64() < 0.3 {
		d.enforcements = d.enforcements[1:]
	}
	// Cap the threat list so it stays legible.
	if len(d.threats) > 8 {
		d.threats = d.threats[len(d.threats)-8:]
	}
	if d.rng.Float64() < 0.15 {
		d.shed++
	}

	peersByState := map[string]int64{"alive": 3, "suspect": 0, "dead": 0}
	if d.rng.Float64() < 0.25 {
		peersByState["alive"] = 2
		peersByState["suspect"] = 1
	}

	return Snapshot{
		At: now,
		Status: &frienv1.GetStatusResponse{
			NodeId: "demo-core-1", Status: "healthy", EnforceMode: d.mode,
			PeerCount: peersByState["alive"] + peersByState["suspect"] - 1,
			Uptime:    now.Sub(d.start).Truncate(time.Second).String(), ProtoVersion: "1",
		},
		Peers:        d.demoPeers(peersByState),
		Threats:      cloneThreats(d.threats),
		Enforcements: cloneEnf(d.enforcements),
		Stats:        d.buildStats(peersByState),
		Audit:        cloneAudit(d.audit),
	}
}

func (d *demoSource) addThreat(now time.Time) {
	sev := demoSeverities[d.rng.Intn(len(demoSeverities))]
	det := demoDetectors[d.rng.Intn(len(demoDetectors))]
	ip := fmt.Sprintf("203.0.113.%d", d.nextIP)
	d.nextIP = (d.nextIP+d.rng.Intn(7)+1)%240 + 10
	scope := "fleet"
	if d.rng.Float64() < 0.4 {
		scope = "zone:a"
	}
	d.threats = append(d.threats, &frienv1.ThreatRecord{
		Indicator: ip, IndicatorType: "ip", Severity: sev, Scope: scope,
		Confidence: 0.8 + d.rng.Float64()*0.19, Detector: det,
		Reason:    fmt.Sprintf("%d events in 60s", 5+d.rng.Intn(40)),
		CreatedAt: now.Format(time.RFC3339),
	})
}

func (d *demoSource) enforceOne(now time.Time) {
	t := d.threats[d.rng.Intn(len(d.threats))]
	for _, e := range d.enforcements { // don't double-enforce the same target
		if e.GetTarget() == t.GetIndicator() {
			return
		}
	}
	matched := 3.0 + d.rng.Float64()*2
	d.enforcements = append(d.enforcements, &frienv1.EnforcementDecision{
		Target: t.GetIndicator(), Action: "block", Adapter: "nftables",
		ExpiresAt:     now.Add(time.Hour).Format(time.RFC3339),
		RollbackToken: fmt.Sprintf("rbk_%08x", d.rng.Uint32()),
	})
	d.decisions = append([]*frienv1.DecisionStat{{
		Indicator: t.GetIndicator(), Outcome: "enforced",
		MatchedWeight: matched, RequiredWeight: 3.0, CreatedAt: now.Format(time.RFC3339),
	}}, d.decisions...)
	if len(d.decisions) > 12 {
		d.decisions = d.decisions[:12]
	}
	d.addAudit(now, "demo-core-1", "decision", t.GetIndicator(), "enforced",
		fmt.Sprintf("quorum met (%.1f/3.0)", matched))
}

func (d *demoSource) addAudit(now time.Time, actor, action, target, outcome, reason string) {
	d.audit = append([]*frienv1.AuditEntrySummary{{
		Time: now.Format(time.RFC3339), Actor: actor, Action: action,
		Target: target, Outcome: outcome, Reason: reason,
	}}, d.audit...)
	if len(d.audit) > 40 {
		d.audit = d.audit[:40]
	}
}

func (d *demoSource) demoPeers(byState map[string]int64) []*frienv1.PeerState {
	peers := []*frienv1.PeerState{{NodeId: "demo-edge-2", Status: "alive"}}
	if byState["suspect"] > 0 {
		peers = append(peers, &frienv1.PeerState{NodeId: "demo-edge-3", Status: "suspect"})
	} else {
		peers = append(peers, &frienv1.PeerState{NodeId: "demo-edge-3", Status: "alive"})
	}
	return peers
}

func (d *demoSource) buildStats(peersByState map[string]int64) *frienv1.GetStatsResponse {
	bySev := map[string]int64{}
	byScope := map[string]int64{}
	byDet := map[string]int64{}
	for _, t := range d.threats {
		bySev[t.GetSeverity()]++
		byScope[t.GetScope()]++
		byDet[t.GetDetector()]++
	}
	byAction := map[string]int64{}
	for _, e := range d.enforcements {
		byAction[e.GetAction()]++
	}
	return &frienv1.GetStatsResponse{
		ThreatsTotal:         int64(len(d.threats)),
		ThreatsBySeverity:    bySev,
		ThreatsByScope:       byScope,
		ThreatsByDetector:    byDet,
		ActiveEnforcements:   int64(len(d.enforcements)),
		EnforcementsByAction: byAction,
		PeersByState:         peersByState,
		RateShedTotal:        d.shed,
		AuditEntries:         int64(len(d.audit)),
		RecentDecisions:      append([]*frienv1.DecisionStat(nil), d.decisions...),
		EnforceMode:          d.mode,
	}
}

func cloneThreats(in []*frienv1.ThreatRecord) []*frienv1.ThreatRecord {
	return append([]*frienv1.ThreatRecord(nil), in...)
}
func cloneEnf(in []*frienv1.EnforcementDecision) []*frienv1.EnforcementDecision {
	return append([]*frienv1.EnforcementDecision(nil), in...)
}
func cloneAudit(in []*frienv1.AuditEntrySummary) []*frienv1.AuditEntrySummary {
	return append([]*frienv1.AuditEntrySummary(nil), in...)
}
