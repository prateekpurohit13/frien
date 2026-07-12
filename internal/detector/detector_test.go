package detector

import (
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/reporter"
)

// fakeReporter records reports and always accepts.
type fakeReporter struct {
	mu      sync.Mutex
	reports []reporter.Params
}

func (f *fakeReporter) Report(p reporter.Params) (reporter.Result, error) {
	f.mu.Lock()
	f.reports = append(f.reports, p)
	f.mu.Unlock()
	return reporter.Result{Status: reporter.StatusAccepted, OpID: "op", ThreatID: "t"}, nil
}

func (f *fakeReporter) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.reports) }

// controllable clock for the window counter.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestWindowCounterFiresAtThreshold(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	w := newWindowCounter(time.Minute, 3, clk.now)
	if fired, _ := w.observe("a"); fired {
		t.Fatal("should not fire on first event")
	}
	w.observe("a")
	fired, count := w.observe("a")
	if !fired || count != 3 {
		t.Fatalf("should fire at threshold 3, got fired=%v count=%d", fired, count)
	}
}

func TestWindowCounterCooldown(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	w := newWindowCounter(time.Minute, 2, clk.now)
	w.observe("a")
	if fired, _ := w.observe("a"); !fired {
		t.Fatal("should fire at threshold")
	}
	// Immediately after firing, further events are in cooldown.
	if fired, _ := w.observe("a"); fired {
		t.Fatal("should be in cooldown, not re-fire")
	}
	// After the window elapses, it can fire again.
	clk.add(2 * time.Minute)
	w.observe("a")
	if fired, _ := w.observe("a"); !fired {
		t.Fatal("should fire again after cooldown")
	}
}

func TestWindowCounterExpiresOldEvents(t *testing.T) {
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	w := newWindowCounter(time.Minute, 3, clk.now)
	w.observe("a")
	w.observe("a")
	// Two events, then wait past the window — they age out.
	clk.add(2 * time.Minute)
	if fired, count := w.observe("a"); fired || count != 1 {
		t.Fatalf("aged events should not count; got fired=%v count=%d", fired, count)
	}
}

func TestSSHDetectorParsesAndReports(t *testing.T) {
	rep := &fakeReporter{}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	d := NewSSHBruteForce(rep, Config{Threshold: 3, Window: time.Minute, Confidence: 0.9}, zerolog.Nop(), clk.now)

	lines := []string{
		"Jul 12 10:00:00 host sshd[1]: Failed password for root from 203.0.113.7 port 40222 ssh2",
		"Jul 12 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 40223 ssh2",
		"Jul 12 10:00:02 host sshd[1]: Accepted password for alice from 10.0.0.5 port 5 ssh2", // not a failure
		"Jul 12 10:00:03 host sshd[1]: Failed password for root from 203.0.113.7 port 40224 ssh2",
	}
	var fired bool
	for _, l := range lines {
		if _, f := d.ProcessLine(l); f {
			fired = true
		}
	}
	if !fired || rep.count() != 1 {
		t.Fatalf("expected one report after 3 failures from same IP, got %d", rep.count())
	}
	if got := rep.reports[0]; got.Indicator != "203.0.113.7" || got.Severity != "high" || got.Detector != "ssh_bruteforce" {
		t.Fatalf("unexpected report: %+v", got)
	}
}

func TestSSHDetectorIgnoresNonFailureAndNoIP(t *testing.T) {
	rep := &fakeReporter{}
	d := NewSSHBruteForce(rep, Config{Threshold: 1, Window: time.Minute, Confidence: 0.9}, zerolog.Nop(), nil)
	if _, f := d.ProcessLine("Jul 12 sshd: session opened for user alice"); f {
		t.Fatal("non-failure line should not fire")
	}
	if _, f := d.ProcessLine("Failed password for root from not-an-ip"); f {
		t.Fatal("line without a valid IP should not fire")
	}
	if rep.count() != 0 {
		t.Fatal("no reports expected")
	}
}

func TestHTTPRateDetector(t *testing.T) {
	rep := &fakeReporter{}
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	d := NewHTTPRateAnomaly(rep, Config{Threshold: 3, Window: time.Minute, Confidence: 0.8}, zerolog.Nop(), clk.now)

	line := `203.0.113.9 - - [12/Jul/2026:10:00:00 +0000] "GET /login HTTP/1.1" 401 55`
	for i := 0; i < 3; i++ {
		d.ProcessLine(line)
	}
	if rep.count() != 1 {
		t.Fatalf("expected one rate-anomaly report, got %d", rep.count())
	}
	if got := rep.reports[0]; got.Indicator != "203.0.113.9" || got.Severity != "medium" {
		t.Fatalf("unexpected report: %+v", got)
	}
	// A malformed line (no leading IP) is ignored.
	if _, f := d.ProcessLine("garbage line"); f {
		t.Fatal("malformed line should not fire")
	}
}

func TestScopeDefaultsToFleet(t *testing.T) {
	if (Config{}).scope() != "fleet" {
		t.Fatal("default detector scope should be fleet")
	}
	if (Config{Scope: "zone:a"}).scope() != "zone:a" {
		t.Fatal("explicit scope should be honored")
	}
}
