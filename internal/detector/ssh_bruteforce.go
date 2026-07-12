package detector

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/reporter"
)

// Config is the common shape for a log-file detector.
type Config struct {
	LogPath    string
	Threshold  int
	Window     time.Duration
	Confidence float64
	Scope      string // "local" | "zone:<name>" | "fleet"; default "fleet"
	Poll       time.Duration
}

func (c Config) scope() string {
	if c.Scope == "" {
		return "fleet"
	}
	return c.Scope
}

// SSHBruteForce watches an auth log and reports a source IP that accumulates
// `threshold` failed authentications within `window`.
type SSHBruteForce struct {
	rep     Reporter
	cfg     Config
	counter *windowCounter
	log     zerolog.Logger
	now     func() time.Time
}

// A failure marker plus an extractable source address is what distinguishes an
// attack line from a normal one. "from <ip>" (sshd) and "rhost=<ip>" (PAM) are
// both handled.
var (
	sshFailureMarkers = []string{"failed password", "authentication failure", "invalid user", "failed publickey"}
	ipRe              = regexp.MustCompile(`(?:from|rhost=)\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
)

// NewSSHBruteForce builds the detector.
func NewSSHBruteForce(rep Reporter, cfg Config, log zerolog.Logger, now func() time.Time) *SSHBruteForce {
	if now == nil {
		now = time.Now
	}
	return &SSHBruteForce{
		rep:     rep,
		cfg:     cfg,
		counter: newWindowCounter(cfg.Window, cfg.Threshold, now),
		log:     log,
		now:     now,
	}
}

func (d *SSHBruteForce) Name() string { return "ssh_bruteforce" }

func (d *SSHBruteForce) Run(ctx context.Context) error {
	d.log.Info().Str("log", d.cfg.LogPath).Int("threshold", d.cfg.Threshold).
		Dur("window", d.cfg.Window).Msg("ssh_bruteforce detector watching")
	return tailFile(ctx, d.cfg.LogPath, d.cfg.Poll, d.onLine, d.log)
}

// onLine is exported-for-test via ProcessLine; kept small so the parsing is unit
// testable without a real file.
func (d *SSHBruteForce) onLine(line string) { d.ProcessLine(line) }

// ProcessLine parses one auth-log line and reports if a source crosses the
// threshold. Returns the IP and whether a threat was emitted (for tests).
func (d *SSHBruteForce) ProcessLine(line string) (string, bool) {
	if !isSSHFailure(line) {
		return "", false
	}
	m := ipRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	ip := m[1]
	fired, count := d.counter.observe(ip)
	if !fired {
		return ip, false
	}
	_, err := d.rep.Report(reporter.Params{
		Indicator:     ip,
		IndicatorType: "ip",
		Reason:        fmt.Sprintf("%d failed SSH authentications within %s", count, d.cfg.Window),
		Severity:      "high",
		Confidence:    d.cfg.Confidence,
		TTL:           "1h",
		Scope:         d.cfg.scope(),
		Detector:      d.Name(),
	})
	if err != nil {
		d.log.Warn().Err(err).Str("ip", ip).Msg("ssh_bruteforce: report rejected")
		return ip, false
	}
	d.log.Warn().Str("ip", ip).Int("failures", count).Msg("ssh_bruteforce: threat reported")
	return ip, true
}

func isSSHFailure(line string) bool {
	l := strings.ToLower(line)
	for _, m := range sshFailureMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
