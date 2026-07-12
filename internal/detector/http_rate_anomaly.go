package detector

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/reporter"
)

// HTTPRateAnomaly watches an access log (common/combined format) and reports a
// source IP that makes more than `threshold` requests within `window` — a crude
// but effective flood/scan signal.
type HTTPRateAnomaly struct {
	rep     Reporter
	cfg     Config
	counter *windowCounter
	log     zerolog.Logger
	now     func() time.Time
}

// The client IP is the first field of a common/combined access-log line.
var accessLogIPRe = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// NewHTTPRateAnomaly builds the detector.
func NewHTTPRateAnomaly(rep Reporter, cfg Config, log zerolog.Logger, now func() time.Time) *HTTPRateAnomaly {
	if now == nil {
		now = time.Now
	}
	return &HTTPRateAnomaly{
		rep:     rep,
		cfg:     cfg,
		counter: newWindowCounter(cfg.Window, cfg.Threshold, now),
		log:     log,
		now:     now,
	}
}

func (d *HTTPRateAnomaly) Name() string { return "http_rate_anomaly" }

func (d *HTTPRateAnomaly) Run(ctx context.Context) error {
	d.log.Info().Str("log", d.cfg.LogPath).Int("threshold", d.cfg.Threshold).
		Dur("window", d.cfg.Window).Msg("http_rate_anomaly detector watching")
	return tailFile(ctx, d.cfg.LogPath, d.cfg.Poll, d.onLine, d.log)
}

func (d *HTTPRateAnomaly) onLine(line string) { d.ProcessLine(line) }

// ProcessLine parses one access-log line and reports if a source crosses the
// rate threshold. Returns the IP and whether a threat was emitted (for tests).
func (d *HTTPRateAnomaly) ProcessLine(line string) (string, bool) {
	m := accessLogIPRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	ip := m[1]
	fired, count := d.counter.observe(ip)
	if !fired {
		return ip, false
	}
	// A request flood is medium severity by default: noisier and more prone to
	// false positives (shared NAT, legitimate spikes) than a credential attack.
	_, err := d.rep.Report(reporter.Params{
		Indicator:     ip,
		IndicatorType: "ip",
		Reason:        fmt.Sprintf("%d HTTP requests within %s (rate anomaly)", count, d.cfg.Window),
		Severity:      "medium",
		Confidence:    d.cfg.Confidence,
		TTL:           "30m",
		Scope:         d.cfg.scope(),
		Detector:      d.Name(),
	})
	if err != nil {
		d.log.Warn().Err(err).Str("ip", ip).Msg("http_rate_anomaly: report rejected")
		return ip, false
	}
	d.log.Warn().Str("ip", ip).Int("requests", count).Msg("http_rate_anomaly: threat reported")
	return ip, true
}
