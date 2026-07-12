package enforcer

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// Deadman is the enforcer's dead-man's switch. It expects a heartbeat from the
// friend daemon at least every `timeout`; if none arrives in time, it fires
// onExpire (which flushes frien-managed rules) and keeps watching so a later
// heartbeat can re-arm it. Cleanup fails open: losing contact with the daemon
// removes mitigations rather than freezing them in place.
type Deadman struct {
	timeout  time.Duration
	onExpire func()
	log      zerolog.Logger

	beat     chan struct{}
	fired    atomic.Int64 // frien_deadman_triggered_total
	clock    func() time.Time
	newTimer func(time.Duration) *time.Timer
}

// NewDeadman builds a switch with the given timeout and expiry action. onExpire
// runs on the Run goroutine and should be quick (it typically calls
// Enforcer.flushAll).
func NewDeadman(timeout time.Duration, onExpire func(), log zerolog.Logger) *Deadman {
	return &Deadman{
		timeout:  timeout,
		onExpire: onExpire,
		log:      log,
		beat:     make(chan struct{}, 1),
		clock:    time.Now,
		newTimer: time.NewTimer,
	}
}

// Beat records a heartbeat from the daemon, re-arming the switch. It never
// blocks: the channel is buffered to one and a full buffer already means a
// pending beat, so a dropped duplicate is harmless.
func (d *Deadman) Beat() {
	select {
	case d.beat <- struct{}{}:
	default:
	}
}

// TriggeredCount reports how many times the switch has fired (metric seam).
func (d *Deadman) TriggeredCount() int64 { return d.fired.Load() }

// Run watches for heartbeats until ctx is cancelled. Each missed window fires
// onExpire exactly once; the switch then re-arms and a subsequent heartbeat
// resumes normal operation. A heartbeat received while already expired simply
// re-arms without a second fire.
func (d *Deadman) Run(ctx context.Context) {
	timer := d.newTimer(d.timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.beat:
			if !timer.Stop() {
				// Drain a timer that already fired so the reset is clean.
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d.timeout)
		case <-timer.C:
			d.fired.Add(1)
			d.log.Warn().
				Dur("deadman_timeout", d.timeout).
				Int64("deadman_triggered_total", d.fired.Load()).
				Msg("dead-man's switch fired: no daemon heartbeat within timeout; flushing frien-managed rules")
			if d.onExpire != nil {
				d.onExpire()
			}
			// Re-arm so a returning daemon can recover and so a still-dead
			// daemon keeps rules flushed on each subsequent window.
			timer.Reset(d.timeout)
		}
	}
}
