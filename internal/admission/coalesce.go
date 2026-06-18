package admission

import (
	"sync"
	"time"
)

// Coalescer collapses repeated identical signals into a single logical record
// carrying a running count, so a burst of the same observation becomes one
// ThreatRecord with coalesced_count rather than thousands of duplicates.
//
// A key's coalescing group lasts for window from its first observation; the
// next observation after the window starts a fresh group.
type Coalescer struct {
	mu     sync.Mutex
	window time.Duration
	now    func() time.Time
	groups map[string]*coalesceGroup
}

type coalesceGroup struct {
	count uint32
	first time.Time
	last  time.Time
}

func NewCoalescer(window time.Duration, now func() time.Time) *Coalescer {
	if now == nil {
		now = time.Now
	}
	return &Coalescer{
		window: window,
		now:    now,
		groups: make(map[string]*coalesceGroup),
	}
}

// Observe records one signal for key. It returns the running count for the key's
// current group and whether this observation started a new group (the caller
// emits a new record on newGroup, and updates the existing record's count
// otherwise).
func (c *Coalescer) Observe(key string) (count uint32, newGroup bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.now()
	g, ok := c.groups[key]
	if !ok || t.Sub(g.first) >= c.window {
		c.groups[key] = &coalesceGroup{count: 1, first: t, last: t}
		return 1, true
	}
	g.count++
	g.last = t
	return g.count, false
}

// Expire drops groups whose window has elapsed, returning the number removed so
// the map cannot grow without bound under a churn of distinct keys.
func (c *Coalescer) Expire() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := c.now()
	removed := 0
	for key, g := range c.groups {
		if t.Sub(g.first) >= c.window {
			delete(c.groups, key)
			removed++
		}
	}
	return removed
}
