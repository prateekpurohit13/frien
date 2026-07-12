package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestScaledBar(t *testing.T) {
	// Full value fills the whole width.
	if got := scaledBar(10, 10, 8); strings.Count(got, "█") != 8 {
		t.Fatalf("full bar should be 8 blocks, got %q", got)
	}
	// Zero value is all spaces of the right width.
	if got := scaledBar(0, 10, 8); got != strings.Repeat(" ", 8) {
		t.Fatalf("zero bar should be blank, got %q", got)
	}
	// Half value fills about half.
	got := scaledBar(5, 10, 8)
	if lipgloss.Width(got) != 8 {
		t.Fatalf("bar width must be constant 8, got %d (%q)", lipgloss.Width(got), got)
	}
	if strings.Count(got, "█") < 3 || strings.Count(got, "█") > 4 {
		t.Fatalf("half bar should be ~4 blocks, got %q", got)
	}
	// max<=0 never divides by zero.
	if got := scaledBar(3, 0, 5); got != strings.Repeat(" ", 5) {
		t.Fatalf("zero-max bar should be blank, got %q", got)
	}
}

func TestHBarChartAlignmentAndEmpty(t *testing.T) {
	if !strings.Contains(HBarChart(nil, 10), "none") {
		t.Fatal("empty chart should render a placeholder")
	}
	rows := []BarRow{
		{Label: "critical", Value: 3, Color: dangerColor},
		{Label: "low", Value: 1, Color: infoColor},
	}
	out := HBarChart(rows, 10)
	lines := strings.Split(out, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(lines))
	}
	// The larger value's bar has more block runes than the smaller.
	if strings.Count(lines[0], "█") <= strings.Count(lines[1], "█") {
		t.Fatalf("bars not scaled by value:\n%s", out)
	}
	// Values are shown.
	if !strings.Contains(out, "3") || !strings.Contains(out, "1") {
		t.Fatalf("values missing from chart:\n%s", out)
	}
}

func TestSparkline(t *testing.T) {
	// Ascending series ends higher than it starts.
	s := Sparkline([]float64{0, 1, 2, 3, 4, 5, 6, 7}, 8)
	runes := []rune(s)
	if len(runes) != 8 {
		t.Fatalf("sparkline width = %d, want 8", len(runes))
	}
	if runes[0] == '█' || runes[7] != '█' {
		t.Fatalf("ascending sparkline should rise to full: %q", s)
	}
	// Fewer values than width left-pads with spaces.
	s2 := Sparkline([]float64{5, 5}, 6)
	if len([]rune(s2)) != 6 || !strings.HasPrefix(s2, "    ") {
		t.Fatalf("short sparkline should left-pad: %q", s2)
	}
	// Flat series does not panic and stays constant width.
	if len([]rune(Sparkline([]float64{3, 3, 3}, 5))) != 5 {
		t.Fatal("flat sparkline width wrong")
	}
	// Empty series is all blanks.
	if Sparkline(nil, 4) != "    " {
		t.Fatalf("empty sparkline should be blank, got %q", Sparkline(nil, 4))
	}
}

func TestGaugeWidthConstant(t *testing.T) {
	g := Gauge(2, 4, 10, okColor)
	// Two-tone track uses '·' for empty and blocks for filled; total visible
	// cells stay constant.
	if lipgloss.Width(g) != 10 {
		t.Fatalf("gauge width = %d, want 10", lipgloss.Width(g))
	}
}

func TestStatTileContainsLabelAndValue(t *testing.T) {
	out := StatTile("threats", "42", dangerColor, 12)
	if !strings.Contains(out, "THREATS") || !strings.Contains(out, "42") {
		t.Fatalf("tile missing label/value:\n%s", out)
	}
}

func TestTrimNum(t *testing.T) {
	if trimNum(3.0) != "3" {
		t.Fatalf("whole float should trim to int, got %q", trimNum(3.0))
	}
	if trimNum(2.5) != "2.5" {
		t.Fatalf("fractional should keep one decimal, got %q", trimNum(2.5))
	}
}
