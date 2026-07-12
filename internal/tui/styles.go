package tui

import "github.com/charmbracelet/lipgloss"

// Palette — a cohesive set of adaptive colors that read well on both light and
// dark terminals (lipgloss picks the right member per background).
var (
	accentColor = lipgloss.Color("39")  // cyan-blue — primary accent
	mutedColor  = lipgloss.Color("240") // track / hairlines
	okColor     = lipgloss.Color("42")  // green  — healthy / alive / enforced-safe
	warnColor   = lipgloss.Color("214") // orange — suspect / high
	dangerColor = lipgloss.Color("196") // red    — dead / critical / denied
	infoColor   = lipgloss.Color("75")  // blue   — low severity / info
	yellowColor = lipgloss.Color("220") // medium severity / warn
	violetColor = lipgloss.Color("141") // decisions / quorum

	dim  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	bold = lipgloss.NewStyle().Bold(true)

	titleBar = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("231")).
			Background(accentColor).
			Padding(0, 1)

	paneBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mutedColor).
		Padding(0, 1)

	tileBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(mutedColor).
		Padding(0, 1).
		MarginRight(1)

	paneTitle = lipgloss.NewStyle().Bold(true).Foreground(accentColor)

	tabActive   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(violetColor).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1)

	footerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

// severityColor maps a threat severity to its palette color.
func severityColor(sev string) lipgloss.Color {
	switch sev {
	case "critical":
		return dangerColor
	case "high":
		return warnColor
	case "medium":
		return yellowColor
	case "low":
		return infoColor
	default:
		return mutedColor
	}
}

// stateColor maps a membership state to its palette color.
func stateColor(state string) lipgloss.Color {
	switch state {
	case "alive":
		return okColor
	case "suspect":
		return warnColor
	case "dead":
		return dangerColor
	case "left":
		return mutedColor
	default:
		return mutedColor
	}
}

// actionColor maps an enforcement action to its palette color.
func actionColor(action string) lipgloss.Color {
	switch action {
	case "block":
		return dangerColor
	case "rate_limit":
		return warnColor
	case "alert":
		return infoColor
	default:
		return accentColor
	}
}

// healthColor maps a node status to its palette color.
func healthColor(status string) lipgloss.Color {
	switch status {
	case "healthy":
		return okColor
	case "degraded":
		return warnColor
	default:
		return mutedColor
	}
}
