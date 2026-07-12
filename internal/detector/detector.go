// Package detector holds frien's pluggable detection backends. A Detector
// observes a local signal source (a log file today; eBPF in Phase 7) and, when a
// source crosses a configured threshold within a window, emits a ThreatRecord
// through the reporter — which applies admission control before the threat ever
// enters replicated state. Detectors produce evidence, never firewall actions:
// whether a threat leads to enforcement is a downstream policy/quorum decision.
package detector

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/reporter"
)

// Detector is a single detection backend.
type Detector interface {
	Name() string
	// Run drives the detector until ctx is cancelled. It should return nil on a
	// clean shutdown and an error only on an unrecoverable setup failure.
	Run(ctx context.Context) error
}

// Reporter is the subset of *reporter.Reporter a detector needs.
type Reporter interface {
	Report(p reporter.Params) (reporter.Result, error)
}

// windowCounter counts events per key within a sliding time window and fires
// when a key reaches the threshold, then arms a per-key cooldown so one ongoing
// attack does not re-fire every event (admission coalescing is the second line
// of defense, but cooling down here avoids spamming it). It is safe for a single
// detector goroutine; no cross-goroutine use is intended.
type windowCounter struct {
	window    time.Duration
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	events     map[string][]time.Time
	cooldUntil map[string]time.Time
}

func newWindowCounter(window time.Duration, threshold int, now func() time.Time) *windowCounter {
	if now == nil {
		now = time.Now
	}
	if window <= 0 {
		window = time.Minute
	}
	if threshold < 1 {
		threshold = 1
	}
	return &windowCounter{
		window:     window,
		threshold:  threshold,
		cooldown:   window, // one alert per key per window
		now:        now,
		events:     make(map[string][]time.Time),
		cooldUntil: make(map[string]time.Time),
	}
}

// observe records one event for key and returns (fired, count) when the key has
// reached the threshold within the window and is not in cooldown.
func (w *windowCounter) observe(key string) (bool, int) {
	t := w.now()
	if until, ok := w.cooldUntil[key]; ok {
		if t.Before(until) {
			return false, 0
		}
		delete(w.cooldUntil, key)
	}
	cutoff := t.Add(-w.window)
	kept := w.events[key][:0]
	for _, e := range w.events[key] {
		if e.After(cutoff) {
			kept = append(kept, e)
		}
	}
	kept = append(kept, t)
	w.events[key] = kept
	if len(kept) >= w.threshold {
		w.cooldUntil[key] = t.Add(w.cooldown)
		delete(w.events, key)
		return true, len(kept)
	}
	return false, len(kept)
}

// tailFile follows a file, delivering each newly appended line to onLine, until
// ctx is cancelled. It waits for the file to appear, starts at end-of-file (so a
// restart does not re-alert on historical log lines), and resets to the start if
// the file shrinks (rotation/truncation). Poll-based so it needs no
// platform-specific inotify dependency.
func tailFile(ctx context.Context, path string, poll time.Duration, onLine func(string), log zerolog.Logger) error {
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	var (
		f      *os.File
		reader *bufio.Reader
		offset int64
	)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	open := func() {
		file, err := os.Open(path)
		if err != nil {
			return
		}
		if fi, err := file.Stat(); err == nil {
			offset = fi.Size() // start at EOF
			_, _ = file.Seek(offset, io.SeekStart)
		}
		f = file
		reader = bufio.NewReader(f)
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		if f == nil {
			open()
			if f == nil {
				continue // not present yet; keep waiting
			}
		}

		// Detect truncation/rotation.
		if fi, err := f.Stat(); err == nil && fi.Size() < offset {
			_, _ = f.Seek(0, io.SeekStart)
			reader = bufio.NewReader(f)
			offset = 0
		}

		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				if trimmed := trimNewline(line); trimmed != "" {
					onLine(trimmed)
				}
			}
			if err != nil {
				break // EOF or transient; resume on next tick
			}
		}
	}
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// Manager runs a set of detectors under one lifecycle with panic recovery, so a
// crash in one detector's loop cannot take down the daemon or its siblings.
type Manager struct {
	detectors []Detector
	log       zerolog.Logger
}

func NewManager(log zerolog.Logger, detectors ...Detector) *Manager {
	return &Manager{detectors: detectors, log: log}
}

// Run starts every detector in its own supervised goroutine and blocks until
// ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, d := range m.detectors {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()
			m.supervise(ctx, d)
		}(d)
	}
	wg.Wait()
}

func (m *Manager) supervise(ctx context.Context, d Detector) {
	for {
		if ctx.Err() != nil {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					m.log.Error().Interface("panic", r).Str("detector", d.Name()).Msg("detector panicked; restarting")
				}
			}()
			if err := d.Run(ctx); err != nil {
				m.log.Warn().Err(err).Str("detector", d.Name()).Msg("detector exited with error")
			}
		}()
		if ctx.Err() != nil {
			return
		}
		// Brief backoff before restart to avoid a tight crash loop.
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
