package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

type tab int

const (
	tabOverview tab = iota
	tabThreats
	tabEnforcement
	tabAudit
	numTabs
)

var tabNames = []string{"Overview", "Threats", "Enforcement", "Audit"}

const histCap = 60

type tickMsg time.Time
type snapshotMsg Snapshot

// Model is the Bubble Tea model for the operator dashboard.
type Model struct {
	src      Source
	interval time.Duration

	snap     Snapshot // most recent poll (may carry an error)
	lastGood Snapshot // most recent successful poll, shown while disconnected
	haveData bool

	tab           tab
	width, height int
	quitting      bool

	// history ring buffers for sparklines
	histThreats []float64
	histRules   []float64
	histAlive   []float64
}

// New builds the dashboard model over any snapshot Source (a live *Client or the
// synthetic demo source).
func New(src Source, interval time.Duration) Model {
	if interval <= 0 {
		interval = time.Second
	}
	return Model{src: src, interval: interval}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), m.tickCmd())
}

func (m Model) fetchCmd() tea.Cmd {
	return func() tea.Msg { return snapshotMsg(m.src.Fetch(context.Background())) }
}

func (m Model) tickCmd() tea.Cmd {
	return tea.Tick(m.interval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.quitting = true
			return m, tea.Quit
		case "tab", "right", "l":
			m.tab = (m.tab + 1) % numTabs
		case "shift+tab", "left", "h":
			m.tab = (m.tab + numTabs - 1) % numTabs
		case "1", "2", "3", "4":
			m.tab = tab(msg.String()[0] - '1')
		case "r":
			return m, m.fetchCmd()
		}
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.fetchCmd(), m.tickCmd())

	case snapshotMsg:
		m.snap = Snapshot(msg)
		if m.snap.Err == nil {
			m.lastGood = m.snap
			m.haveData = true
			m.pushHistory(m.snap)
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) pushHistory(s Snapshot) {
	push := func(buf []float64, v float64) []float64 {
		buf = append(buf, v)
		if len(buf) > histCap {
			buf = buf[len(buf)-histCap:]
		}
		return buf
	}
	var threats, rules, alive float64
	if s.Stats != nil {
		threats = float64(s.Stats.GetThreatsTotal())
		rules = float64(s.Stats.GetActiveEnforcements())
		alive = float64(s.Stats.GetPeersByState()["alive"])
	}
	m.histThreats = push(m.histThreats, threats)
	m.histRules = push(m.histRules, rules)
	m.histAlive = push(m.histAlive, alive)
}

// View renders the full dashboard.
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 {
		return "  connecting to frien admin socket…\n"
	}
	data := m.lastGood
	if !m.haveData {
		data = m.snap
	}

	var body string
	switch m.tab {
	case tabThreats:
		body = m.viewThreats(data)
	case tabEnforcement:
		body = m.viewEnforcement(data)
	case tabAudit:
		body = m.viewAudit(data)
	default:
		body = m.viewOverview(data)
	}

	return strings.Join([]string{
		m.header(data),
		m.tabBar(),
		body,
		m.footer(),
	}, "\n")
}

// ── chrome ──────────────────────────────────────────────────────────────────

func (m Model) header(d Snapshot) string {
	node, status, mode, uptime, peers := "?", "?", "?", "?", "0"
	if d.Status != nil {
		node = d.Status.GetNodeId()
		status = d.Status.GetStatus()
		mode = d.Status.GetEnforceMode()
		uptime = d.Status.GetUptime()
		peers = fmt.Sprintf("%d", d.Status.GetPeerCount())
	}
	left := titleBar.Render("frien ⌘ mesh")
	badge := lipgloss.NewStyle().Foreground(healthColor(status)).Bold(true).Render("● " + status)
	modeStyle := okColor
	if mode == "enforce" {
		modeStyle = dangerColor
	}
	meta := fmt.Sprintf("  %s   %s   mode:%s   up:%s   peers:%s",
		bold.Render(node), badge,
		lipgloss.NewStyle().Foreground(modeStyle).Render(mode),
		dim.Render(uptime), dim.Render(peers))
	return left + meta
}

func (m Model) tabBar() string {
	var parts []string
	for i, name := range tabNames {
		label := fmt.Sprintf("%d %s", i+1, name)
		if tab(i) == m.tab {
			parts = append(parts, tabActive.Render(label))
		} else {
			parts = append(parts, tabInactive.Render(label))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m Model) footer() string {
	conn := lipgloss.NewStyle().Foreground(okColor).Render("● connected")
	if m.snap.Err != nil {
		conn = lipgloss.NewStyle().Foreground(dangerColor).Render("● disconnected")
	}
	refreshed := ""
	if !m.snap.At.IsZero() {
		refreshed = "updated " + m.snap.At.Format("15:04:05")
	}
	keys := "tab/1-4 switch · r refresh · q quit"
	return footerStyle.Render(fmt.Sprintf("%s   %s   %s", conn, refreshed, keys))
}

// ── overview ────────────────────────────────────────────────────────────────

func (m Model) viewOverview(d Snapshot) string {
	st := d.Stats
	tiles := m.kpiRow(st)

	colW := (m.width - 6) / 3
	if colW < 22 {
		colW = 22
	}
	barW := colW - 14
	if barW < 6 {
		barW = 6
	}

	sevRows := statMapRows(mapOr(st, func(s *frienv1.GetStatsResponse) map[string]int64 { return s.GetThreatsBySeverity() }),
		[]string{"critical", "high", "medium", "low"}, severityColor)
	stateRows := statMapRows(mapOr(st, func(s *frienv1.GetStatsResponse) map[string]int64 { return s.GetPeersByState() }),
		[]string{"alive", "suspect", "dead", "left"}, stateColor)
	actionRows := statMapRows(mapOr(st, func(s *frienv1.GetStatsResponse) map[string]int64 { return s.GetEnforcementsByAction() }),
		[]string{"block", "rate_limit", "alert"}, actionColor)

	threatsPane := pane("Threats by severity", colW,
		HBarChart(sevRows, barW)+"\n\n"+
			dim.Render("trend ")+lipgloss.NewStyle().Foreground(warnColor).Render(Sparkline(m.histThreats, colW-8)))
	memberPane := pane("Membership", colW,
		HBarChart(stateRows, barW)+"\n\n"+
			dim.Render("alive ")+lipgloss.NewStyle().Foreground(okColor).Render(Sparkline(m.histAlive, colW-8)))
	enfPane := pane("Enforcement by action", colW,
		HBarChart(actionRows, barW)+"\n\n"+
			dim.Render("rules ")+lipgloss.NewStyle().Foreground(dangerColor).Render(Sparkline(m.histRules, colW-8)))

	charts := lipgloss.JoinHorizontal(lipgloss.Top, threatsPane, memberPane, enfPane)
	decisions := pane("Quorum decisions", m.width-4, m.decisionFeed(d, m.width-24))

	return lipgloss.JoinVertical(lipgloss.Left, tiles, charts, decisions)
}

func (m Model) kpiRow(st *frienv1.GetStatsResponse) string {
	var threats, rules, alive, shed, auditN int64
	mode := "observe"
	if st != nil {
		threats = st.GetThreatsTotal()
		rules = st.GetActiveEnforcements()
		alive = st.GetPeersByState()["alive"]
		shed = st.GetRateShedTotal()
		auditN = st.GetAuditEntries()
		if st.GetEnforceMode() != "" {
			mode = st.GetEnforceMode()
		}
	}
	w := 13
	modeColor := okColor
	if mode == "enforce" {
		modeColor = dangerColor
	}
	tiles := []string{
		StatTile("threats", fmt.Sprintf("%d", threats), warnColor, w),
		StatTile("active rules", fmt.Sprintf("%d", rules), dangerColor, w),
		StatTile("peers alive", fmt.Sprintf("%d", alive), okColor, w),
		StatTile("rate shed", fmt.Sprintf("%d", shed), yellowColor, w),
		StatTile("audit", fmt.Sprintf("%d", auditN), violetColor, w),
		StatTile("mode", mode, modeColor, w),
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, tiles...)
}

func (m Model) decisionFeed(d Snapshot, gaugeW int) string {
	if d.Stats == nil || len(d.Stats.GetRecentDecisions()) == 0 {
		return dim.Render("(no enforcement decisions yet)")
	}
	if gaugeW < 8 {
		gaugeW = 8
	}
	var b strings.Builder
	for i, dec := range d.Stats.GetRecentDecisions() {
		if i >= 8 {
			break
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		g := Gauge(dec.GetMatchedWeight(), maxF(dec.GetRequiredWeight(), dec.GetMatchedWeight()), gaugeW, violetColor)
		fmt.Fprintf(&b, "%s %s %s",
			padRight(dec.GetIndicator(), 20),
			g,
			dim.Render(fmt.Sprintf("%.1f/%.1f", dec.GetMatchedWeight(), dec.GetRequiredWeight())))
	}
	return b.String()
}

// ── threats ─────────────────────────────────────────────────────────────────

func (m Model) viewThreats(d Snapshot) string {
	sevRows := statMapRows(mapOr(d.Stats, func(s *frienv1.GetStatsResponse) map[string]int64 { return s.GetThreatsBySeverity() }),
		[]string{"critical", "high", "medium", "low"}, severityColor)
	chart := pane("By severity", m.width-4, HBarChart(sevRows, 24))

	headers := []string{"INDICATOR", "TYPE", "SEV", "SCOPE", "CONF", "DETECTOR", "REASON"}
	var rows [][]string
	var colors []lipgloss.Color
	for _, t := range d.Threats {
		rows = append(rows, []string{
			t.GetIndicator(), t.GetIndicatorType(), t.GetSeverity(), t.GetScope(),
			fmt.Sprintf("%.2f", t.GetConfidence()), t.GetDetector(), truncate(t.GetReason(), 30),
		})
		colors = append(colors, severityColor(t.GetSeverity()))
	}
	table := pane(fmt.Sprintf("Present threats (%d)", len(d.Threats)), m.width-4, renderTable(headers, rows, colors, 2))
	return lipgloss.JoinVertical(lipgloss.Left, chart, table)
}

// ── enforcement ─────────────────────────────────────────────────────────────

func (m Model) viewEnforcement(d Snapshot) string {
	actionRows := statMapRows(mapOr(d.Stats, func(s *frienv1.GetStatsResponse) map[string]int64 { return s.GetEnforcementsByAction() }),
		[]string{"block", "rate_limit", "alert"}, actionColor)
	chart := pane("By action", m.width-4, HBarChart(actionRows, 24))

	headers := []string{"TARGET", "ACTION", "ADAPTER", "EXPIRES", "TOKEN"}
	var rows [][]string
	var colors []lipgloss.Color
	for _, e := range d.Enforcements {
		rows = append(rows, []string{
			e.GetTarget(), e.GetAction(), e.GetAdapter(), shortTime(e.GetExpiresAt()), short(e.GetRollbackToken(), 12),
		})
		colors = append(colors, actionColor(e.GetAction()))
	}
	table := pane(fmt.Sprintf("Active rules (%d)", len(d.Enforcements)), m.width-4, renderTable(headers, rows, colors, 2))
	feed := pane("Quorum decisions", m.width-4, m.decisionFeed(d, m.width-24))
	return lipgloss.JoinVertical(lipgloss.Left, chart, table, feed)
}

// ── audit ───────────────────────────────────────────────────────────────────

func (m Model) viewAudit(d Snapshot) string {
	headers := []string{"TIME", "ACTOR", "ACTION", "TARGET", "OUTCOME", "REASON"}
	var rows [][]string
	var colors []lipgloss.Color
	for _, a := range d.Audit {
		rows = append(rows, []string{
			shortTime(a.GetTime()), a.GetActor(), a.GetAction(), a.GetTarget(), a.GetOutcome(), truncate(a.GetReason(), 34),
		})
		colors = append(colors, auditActionColor(a.GetAction()))
	}
	return pane(fmt.Sprintf("Audit tail (%d) — tamper-evident, newest first", len(d.Audit)), m.width-4,
		renderTable(headers, rows, colors, 2))
}

func auditActionColor(a string) lipgloss.Color {
	switch a {
	case "breakglass":
		return dangerColor
	case "mode_set":
		return warnColor
	case "rollback":
		return yellowColor
	case "decision":
		return violetColor
	default:
		return accentColor
	}
}

// ── shared view helpers ─────────────────────────────────────────────────────

func pane(title string, width int, content string) string {
	if width < 10 {
		width = 10
	}
	inner := paneTitle.Render(title) + "\n" + content
	return paneBox.Width(width).Render(inner)
}

// renderTable lays out a simple fixed-width table. rowColors (optional, may be
// nil) tints the first column of each row.
func renderTable(headers []string, rows [][]string, rowColors []lipgloss.Color, pad int) string {
	if len(rows) == 0 {
		return dim.Render("(none)")
	}
	cols := len(headers)
	widths := make([]int, cols)
	for i, h := range headers {
		widths[i] = lipgloss.Width(h)
	}
	for _, r := range rows {
		for i := 0; i < cols && i < len(r); i++ {
			if w := lipgloss.Width(r[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	sep := strings.Repeat(" ", pad)
	var b strings.Builder
	// header
	var hcells []string
	for i, h := range headers {
		hcells = append(hcells, dim.Render(padRight(h, widths[i])))
	}
	b.WriteString(strings.Join(hcells, sep))
	for ri, r := range rows {
		b.WriteByte('\n')
		var cells []string
		for i := 0; i < cols; i++ {
			val := ""
			if i < len(r) {
				val = r[i]
			}
			cell := padRight(val, widths[i])
			if i == 0 && rowColors != nil && ri < len(rowColors) {
				cell = lipgloss.NewStyle().Foreground(rowColors[ri]).Render(cell)
			}
			cells = append(cells, cell)
		}
		b.WriteString(strings.Join(cells, sep))
	}
	return b.String()
}

// statMapRows builds bar rows from a count map, in a fixed category order,
// skipping absent categories.
func statMapRows(counts map[string]int64, order []string, color func(string) lipgloss.Color) []BarRow {
	var rows []BarRow
	for _, k := range order {
		if v, ok := counts[k]; ok {
			rows = append(rows, BarRow{Label: k, Value: float64(v), Color: color(k)})
		}
	}
	// Include any categories not in the fixed order (e.g. "unknown").
	for k, v := range counts {
		known := false
		for _, o := range order {
			if o == k {
				known = true
				break
			}
		}
		if !known {
			rows = append(rows, BarRow{Label: k, Value: float64(v), Color: color(k)})
		}
	}
	return rows
}

func mapOr(st *frienv1.GetStatsResponse, get func(*frienv1.GetStatsResponse) map[string]int64) map[string]int64 {
	if st == nil {
		return nil
	}
	return get(st)
}

func truncate(s string, n int) string {
	if lipgloss.Width(s) <= n {
		return s
	}
	r := []rune(s)
	if n < 1 {
		return ""
	}
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func shortTime(rfc string) string {
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	return t.Format("15:04:05")
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
