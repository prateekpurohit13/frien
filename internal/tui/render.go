// Package tui is frien's operator dashboard: a terminal UI over the local admin
// gRPC socket (the same trust boundary as frienctl — no new network surface). It
// renders live mesh, threat, and enforcement state as bar charts, sparklines,
// gauges, and stat tiles. This file holds the pure rendering primitives, kept
// free of any Bubble Tea or network dependency so they can be unit-tested in
// isolation.
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Eighth-block runes for sub-cell precision on horizontal bars and gauges.
var eighths = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'}

// Sparkline levels (▁..█), plus a leading space for a true zero.
var sparkLevels = []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// BarRow is one labeled, colored bar in a horizontal bar chart.
type BarRow struct {
	Label string
	Value float64
	Color lipgloss.Color
}

// HBarChart renders labeled horizontal bars scaled to the largest value in the
// set, with sub-cell precision via eighth-blocks. Labels are right-padded to a
// common width and each row shows its numeric value. An empty set renders a
// muted placeholder so a pane never collapses.
func HBarChart(rows []BarRow, barWidth int) string {
	if len(rows) == 0 {
		return dim.Render("(none)")
	}
	if barWidth < 1 {
		barWidth = 1
	}
	labelW, max := 0, 0.0
	for _, r := range rows {
		if w := lipgloss.Width(r.Label); w > labelW {
			labelW = w
		}
		if r.Value > max {
			max = r.Value
		}
	}
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		bar := scaledBar(r.Value, max, barWidth)
		color := r.Color
		if color == "" {
			color = accentColor
		}
		fmt.Fprintf(&b, "%s %s %s",
			dim.Render(padRight(r.Label, labelW)),
			lipgloss.NewStyle().Foreground(color).Render(bar),
			bold.Render(trimNum(r.Value)),
		)
	}
	return b.String()
}

// scaledBar renders value/max across barWidth cells using eighth-block precision.
func scaledBar(value, max float64, barWidth int) string {
	if max <= 0 {
		return strings.Repeat(" ", barWidth)
	}
	frac := value / max
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	eighthsTotal := int(frac*float64(barWidth)*8 + 0.5)
	full := eighthsTotal / 8
	rem := eighthsTotal % 8
	var b strings.Builder
	for i := 0; i < full && i < barWidth; i++ {
		b.WriteRune('█')
	}
	if full < barWidth && rem > 0 {
		b.WriteRune(eighths[rem])
		full++
	}
	for i := full; i < barWidth; i++ {
		b.WriteRune(' ')
	}
	return b.String()
}

// Sparkline renders the last `width` values as a single line of ▁..█, scaled to
// the series' own min/max. Fewer values than width left-pads with blanks.
func Sparkline(vals []float64, width int) string {
	if width < 1 {
		width = 1
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	min, max := 0.0, 0.0
	for i, v := range vals {
		if i == 0 || v < min {
			min = v
		}
		if i == 0 || v > max {
			max = v
		}
	}
	var b strings.Builder
	for i := 0; i < width-len(vals); i++ {
		b.WriteRune(' ')
	}
	span := max - min
	for _, v := range vals {
		level := 0
		if span > 0 {
			level = int((v-min)/span*float64(len(sparkLevels)-1) + 0.5)
		} else if v > 0 {
			level = len(sparkLevels) - 1
		}
		if level < 0 {
			level = 0
		}
		if level >= len(sparkLevels) {
			level = len(sparkLevels) - 1
		}
		b.WriteRune(sparkLevels[level])
	}
	return b.String()
}

// Gauge renders a value/max meter across width cells with eighth-block
// precision, colored by fill (green→yellow→red as it approaches full is left to
// the caller via color). A met threshold (value>=max) is shown fully filled.
func Gauge(value, max float64, width int, color lipgloss.Color) string {
	bar := scaledBar(value, max, width)
	track := lipgloss.NewStyle().Foreground(mutedColor)
	filled := lipgloss.NewStyle().Foreground(color)
	// Split into filled vs empty for a two-tone track.
	var b strings.Builder
	for _, r := range bar {
		if r == ' ' {
			b.WriteString(track.Render("·"))
		} else {
			b.WriteString(filled.Render(string(r)))
		}
	}
	return b.String()
}

// StatTile renders a compact KPI card: a dim label over a large accented value.
func StatTile(label, value string, accent lipgloss.Color, width int) string {
	inner := lipgloss.NewStyle().Width(width).Align(lipgloss.Left)
	body := lipgloss.JoinVertical(lipgloss.Left,
		dim.Render(strings.ToUpper(label)),
		lipgloss.NewStyle().Foreground(accent).Bold(true).Render(value),
	)
	return tileBox.Render(inner.Render(body))
}

func padRight(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// trimNum renders a float without a trailing ".0" for whole numbers.
func trimNum(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.1f", v)
}
