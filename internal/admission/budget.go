package admission

import (
	"sync"
	"time"
)

// tokenBucket is a standard rate limiter: it refills at rate tokens/sec up to
// capacity, and a request consumes one token.
type tokenBucket struct {
	mu       sync.Mutex
	capacity float64
	rate     float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

func newTokenBucket(rate float64, burst int, now func() time.Time) *tokenBucket {
	if now == nil {
		now = time.Now
	}
	return &tokenBucket{
		capacity: float64(burst),
		rate:     rate,
		tokens:   float64(burst),
		last:     now(),
		now:      now,
	}
}

func (b *tokenBucket) refill() {
	t := b.now()
	if elapsed := t.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = t
	}
}

func (b *tokenBucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// refund returns a previously-taken token, used when a multi-bucket admission
// fails after this bucket already granted one.
func (b *tokenBucket) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tokens+1 <= b.capacity {
		b.tokens++
	}
}

func (b *tokenBucket) fillRatio() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	if b.capacity == 0 {
		return 0
	}
	return b.tokens / b.capacity
}

// BudgetConfig mirrors the admission budget settings from the daemon config.
type BudgetConfig struct {
	PerDetectorRate  float64
	PerDetectorBurst int
	PerNodeRate      float64
	PerNodeBurst     int
}

// Budget enforces operation-creation rate limits both per detector and across
// the whole node, so neither a single noisy detector nor the node as a whole can
// flood the mesh with operations.
type Budget struct {
	cfg  BudgetConfig
	now  func() time.Time
	node *tokenBucket

	mu        sync.Mutex
	detectors map[string]*tokenBucket
}

func NewBudget(cfg BudgetConfig, now func() time.Time) *Budget {
	if now == nil {
		now = time.Now
	}
	return &Budget{
		cfg:       cfg,
		now:       now,
		node:      newTokenBucket(cfg.PerNodeRate, cfg.PerNodeBurst, now),
		detectors: make(map[string]*tokenBucket),
	}
}

func (b *Budget) detectorBucket(detector string) *tokenBucket {
	b.mu.Lock()
	defer b.mu.Unlock()
	tb, ok := b.detectors[detector]
	if !ok {
		tb = newTokenBucket(b.cfg.PerDetectorRate, b.cfg.PerDetectorBurst, b.now)
		b.detectors[detector] = tb
	}
	return tb
}

// Allow admits one operation from detector only if both the detector's bucket
// and the node-wide bucket have capacity. If the detector grants a token but the
// node bucket is exhausted, the detector token is refunded so it is not lost.
func (b *Budget) Allow(detector string) bool {
	det := b.detectorBucket(detector)
	if !det.take() {
		return false
	}
	if !b.node.take() {
		det.refund()
		return false
	}
	return true
}

// NodeFillRatio is the fraction of node budget currently available; the
// admission controller reads it to detect storm conditions.
func (b *Budget) NodeFillRatio() float64 { return b.node.fillRatio() }
