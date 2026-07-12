package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func sampleSnapshot() Snapshot {
	return Snapshot{
		At: time.Now(),
		Status: &frienv1.GetStatusResponse{
			NodeId: "core-1.zone-a", Status: "healthy", EnforceMode: "enforce",
			PeerCount: 4, Uptime: "3h12m", ProtoVersion: "1",
		},
		Peers: []*frienv1.PeerState{
			{NodeId: "edge-2", Status: "alive"}, {NodeId: "edge-3", Status: "suspect"},
		},
		Threats: []*frienv1.ThreatRecord{
			{Indicator: "203.0.113.7", IndicatorType: "ip", Severity: "critical", Scope: "fleet", Confidence: 0.96, Detector: "ssh_bruteforce", Reason: "42 failed auths in 60s", CreatedAt: "2026-07-12T10:00:00Z"},
			{Indicator: "198.51.100.9", IndicatorType: "ip", Severity: "high", Scope: "zone:a", Confidence: 0.88, Detector: "http_rate_anomaly", Reason: "rate spike", CreatedAt: "2026-07-12T10:01:00Z"},
		},
		Enforcements: []*frienv1.EnforcementDecision{
			{Target: "203.0.113.7", Action: "block", Adapter: "nftables", ExpiresAt: "2026-07-12T11:00:00Z", RollbackToken: "rbk_abcdef123456"},
		},
		Stats: &frienv1.GetStatsResponse{
			ThreatsTotal:         2,
			ThreatsBySeverity:    map[string]int64{"critical": 1, "high": 1},
			ThreatsByScope:       map[string]int64{"fleet": 1, "zone:a": 1},
			ThreatsByDetector:    map[string]int64{"ssh_bruteforce": 1, "http_rate_anomaly": 1},
			ActiveEnforcements:   1,
			EnforcementsByAction: map[string]int64{"block": 1},
			PeersByState:         map[string]int64{"alive": 3, "suspect": 1},
			RateShedTotal:        0,
			AuditEntries:         5,
			EnforceMode:          "enforce",
			RecentDecisions: []*frienv1.DecisionStat{
				{Indicator: "203.0.113.7", Outcome: "enforced", MatchedWeight: 3, RequiredWeight: 3, CreatedAt: "2026-07-12T10:02:00Z"},
			},
		},
		Audit: []*frienv1.AuditEntrySummary{
			{Time: "2026-07-12T10:02:00Z", Actor: "core-1", Action: "decision", Target: "203.0.113.7", Outcome: "enforced", Reason: "quorum met"},
			{Time: "2026-07-12T09:50:00Z", Actor: "operator", Action: "mode_set", Adapter: "nftables", Reason: "rollout"},
		},
	}
}

// primed returns a model sized and fed one snapshot, ready to render.
func primed() Model {
	m := New(nil, time.Second)
	m2, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = m2.(Model)
	m3, _ := m.Update(snapshotMsg(sampleSnapshot()))
	return m3.(Model)
}

func TestOverviewRenders(t *testing.T) {
	m := primed()
	out := m.View()
	for _, want := range []string{"core-1.zone-a", "healthy", "Overview", "Threats", "THREATS", "PEERS ALIVE", "critical", "alive", "block"} {
		if !strings.Contains(out, want) {
			t.Errorf("overview missing %q", want)
		}
	}
}

func TestTabSwitchingAndContent(t *testing.T) {
	m := primed()
	// Switch to Threats (key "2").
	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	m = m2.(Model)
	if m.tab != tabThreats {
		t.Fatalf("expected tabThreats, got %d", m.tab)
	}
	out := m.View()
	if !strings.Contains(out, "203.0.113.7") || !strings.Contains(out, "ssh_bruteforce") {
		t.Fatalf("threats tab missing threat detail:\n%s", out)
	}

	// Enforcement tab (key "3").
	m3, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = m3.(Model)
	if !strings.Contains(m.View(), "nftables") {
		t.Fatal("enforcement tab missing active rule")
	}

	// Audit tab (key "4").
	m4, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("4")})
	m = m4.(Model)
	if !strings.Contains(m.View(), "quorum met") {
		t.Fatal("audit tab missing audit entry")
	}

	// tab cycles forward and wraps.
	start := m.tab
	for i := 0; i < int(numTabs); i++ {
		mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
		m = mm.(Model)
	}
	if m.tab != start {
		t.Fatalf("full tab cycle should return to start, got %d want %d", m.tab, start)
	}
}

func TestQuitKey(t *testing.T) {
	m := primed()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil {
		t.Fatal("q should return a quit command")
	}
}

func TestHistoryAccumulates(t *testing.T) {
	m := New(nil, time.Second)
	m2, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = m2.(Model)
	for i := 0; i < 3; i++ {
		mm, _ := m.Update(snapshotMsg(sampleSnapshot()))
		m = mm.(Model)
	}
	if len(m.histThreats) != 3 {
		t.Fatalf("expected 3 history points, got %d", len(m.histThreats))
	}
}

func TestDisconnectedKeepsLastGood(t *testing.T) {
	m := primed()
	// An errored snapshot must not wipe the last good data.
	bad := Snapshot{Err: context_DeadlineErr{}}
	m2, _ := m.Update(snapshotMsg(bad))
	m = m2.(Model)
	out := m.View()
	if !strings.Contains(out, "disconnected") {
		t.Fatal("footer should show disconnected")
	}
	if !strings.Contains(out, "core-1.zone-a") {
		t.Fatal("last-good data should still render while disconnected")
	}
}

type context_DeadlineErr struct{}

func (context_DeadlineErr) Error() string { return "deadline exceeded" }
