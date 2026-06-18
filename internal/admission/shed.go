package admission

// severityRank orders severities so shedding can spare the most important
// signals. Unknown severities rank lowest and are shed first.
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// Shedder is the priority-shedding policy. Under storm it drops low-priority,
// low-confidence signals first; high and critical severities are never shed so
// the mesh keeps flowing the observations that matter most.
type Shedder struct {
	minConfidence float64
}

func NewShedder(minConfidence float64) *Shedder {
	return &Shedder{minConfidence: minConfidence}
}

// Keep reports whether a signal survives shedding. Outside a storm everything is
// kept; under storm a signal is dropped only when it is both below the
// confidence floor and below high severity.
func (s *Shedder) Keep(severity string, confidence float64, underStorm bool) bool {
	if !underStorm {
		return true
	}
	if severityRank(severity) >= severityRank("high") {
		return true
	}
	return confidence >= s.minConfidence
}
