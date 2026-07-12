package enforcer

import (
	"sync"
	"time"
)

// rateLimiter is a minimal token-bucket capping how many NEW rules the enforcer
// will install per unit time. It lives in the privileged enforcer — the
// authoritative boundary — so even a runaway or compromised daemon that floods
// Apply calls cannot make frien install an unbounded number of firewall rules
// (docs/FRIEN_ARCHITECTURE.md §Layer 7: "max changes per minute"). Over-cap
// applies are shed fail-safe: the rule is simply not created.
//
// It is deliberately self-contained (no dependency on internal/admission) to
// keep the privileged component's code small and auditable.
type rateLimiter struct {
	mu       sync.Mutex
	capacity float64
	rate     float64 // tokens per second
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// newRateLimiter builds a limiter admitting perMinute new rules per minute, with
// burst == perMinute. A non-positive perMinute returns nil (unlimited).
func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{
		capacity: float64(perMinute),
		rate:     float64(perMinute) / 60.0,
		tokens:   float64(perMinute),
		last:     now(),
		now:      now,
	}
}

// allow consumes one token, returning false when the bucket is empty (shed).
func (r *rateLimiter) allow() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.now()
	if elapsed := t.Sub(r.last).Seconds(); elapsed > 0 {
		r.tokens += elapsed * r.rate
		if r.tokens > r.capacity {
			r.tokens = r.capacity
		}
		r.last = t
	}
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}
