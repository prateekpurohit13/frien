package crdt

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const wallLayout = "2006-01-02T15:04:05.000Z07:00"

// Timestamp is an immutable Hybrid Logical Clock value. Wall is milliseconds
// since the Unix epoch; Counter disambiguates events within the same wall
// millisecond; NodeID is the final total-order tiebreaker and the origin of the
// stamp. Its wire form is "<rfc3339-millis>-<counter>-<node_id>".
type Timestamp struct {
	Wall    int64
	Counter uint32
	NodeID  string
}

func (t Timestamp) String() string {
	wall := time.UnixMilli(t.Wall).UTC().Format(wallLayout)
	return fmt.Sprintf("%s-%d-%s", wall, t.Counter, t.NodeID)
}

// IsZero reports whether the timestamp is the zero value.
func (t Timestamp) IsZero() bool {
	return t.Wall == 0 && t.Counter == 0 && t.NodeID == ""
}

// Compare orders timestamps by (Wall, Counter, NodeID), giving a deterministic
// total order across the mesh.
func (t Timestamp) Compare(o Timestamp) int {
	switch {
	case t.Wall != o.Wall:
		return cmpInt64(t.Wall, o.Wall)
	case t.Counter != o.Counter:
		return cmpUint32(t.Counter, o.Counter)
	default:
		return strings.Compare(t.NodeID, o.NodeID)
	}
}

// ParseTimestamp parses the wire form. The wall portion (RFC3339) and the node
// id may both contain hyphens, so the wall is delimited by its trailing "Z" and
// the counter is the numeric run immediately after it.
func ParseTimestamp(s string) (Timestamp, error) {
	z := strings.IndexByte(s, 'Z')
	if z < 0 || z+1 >= len(s) || s[z+1] != '-' {
		return Timestamp{}, fmt.Errorf("hlc: malformed timestamp %q", s)
	}
	wall, err := time.Parse(wallLayout, s[:z+1])
	if err != nil {
		return Timestamp{}, fmt.Errorf("hlc: parsing wall in %q: %w", s, err)
	}
	rest := s[z+2:] // skip 'Z' and the following '-'
	dash := strings.IndexByte(rest, '-')
	if dash < 0 {
		return Timestamp{}, fmt.Errorf("hlc: missing node id in %q", s)
	}
	counter, err := strconv.ParseUint(rest[:dash], 10, 32)
	if err != nil {
		return Timestamp{}, fmt.Errorf("hlc: parsing counter in %q: %w", s, err)
	}
	nodeID := rest[dash+1:]
	if nodeID == "" {
		return Timestamp{}, fmt.Errorf("hlc: empty node id in %q", s)
	}
	return Timestamp{Wall: wall.UnixMilli(), Counter: uint32(counter), NodeID: nodeID}, nil
}

// Clock is the live Hybrid Logical Clock for the local node. It guarantees a
// monotonically non-decreasing stream of timestamps even when the physical clock
// jumps backwards, and bounds how far a peer's clock can drag ours forward.
type Clock struct {
	mu       sync.Mutex
	nodeID   string
	wall     int64
	counter  uint32
	physical func() time.Time
	maxDrift int64 // milliseconds; 0 disables the drift guard
}

// ClockOption configures a Clock.
type ClockOption func(*Clock)

// WithPhysicalClock injects the physical time source (default time.Now).
func WithPhysicalClock(now func() time.Time) ClockOption {
	return func(c *Clock) { c.physical = now }
}

// WithMaxDrift bounds how far ahead of local physical time a remote timestamp
// may push the clock during Update, and is the skew window CheckSkew enforces.
func WithMaxDrift(d time.Duration) ClockOption {
	return func(c *Clock) { c.maxDrift = d.Milliseconds() }
}

// WithInitial seeds the clock from a persisted timestamp so it never regresses
// across a restart.
func WithInitial(ts Timestamp) ClockOption {
	return func(c *Clock) {
		c.wall = ts.Wall
		c.counter = ts.Counter
	}
}

func NewClock(nodeID string, opts ...ClockOption) *Clock {
	c := &Clock{nodeID: nodeID, physical: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Clock) physicalMillis() int64 { return c.physical().UnixMilli() }

// Now returns a fresh timestamp for a locally-originated event.
func (c *Clock) Now() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()

	pt := c.physicalMillis()
	if pt > c.wall {
		c.wall = pt
		c.counter = 0
	} else {
		c.tick()
	}
	return c.current()
}

// Update advances the clock on receipt of a remote timestamp and returns the
// merged local timestamp. It errors if the remote wall exceeds local physical
// time by more than the configured drift, so a peer cannot run our clock away.
func (c *Clock) Update(remote Timestamp) (Timestamp, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	pt := c.physicalMillis()
	if c.maxDrift > 0 && remote.Wall-pt > c.maxDrift {
		return Timestamp{}, fmt.Errorf("hlc: remote wall ahead of local by more than %dms drift", c.maxDrift)
	}

	l := maxInt64(c.wall, maxInt64(remote.Wall, pt))
	switch {
	case l == c.wall && l == remote.Wall:
		c.counter = maxUint32(c.counter, remote.Counter) + 1
	case l == c.wall:
		c.tick()
	case l == remote.Wall:
		c.counter = remote.Counter + 1
	default:
		c.counter = 0
	}
	c.wall = l
	return c.current(), nil
}

// CheckSkew reports whether a remote timestamp's wall deviates from local
// physical time by more than window in either direction. It is the ingress gate
// for transport.clock_skew_window: an op outside the window is rejected before
// it touches the clock or the state.
func (c *Clock) CheckSkew(remote Timestamp, window time.Duration) error {
	if window <= 0 {
		return nil
	}
	c.mu.Lock()
	pt := c.physicalMillis()
	c.mu.Unlock()

	skew := remote.Wall - pt
	if skew < 0 {
		skew = -skew
	}
	if skew > window.Milliseconds() {
		return fmt.Errorf("hlc: remote clock skew %dms exceeds window %dms", skew, window.Milliseconds())
	}
	return nil
}

// Snapshot returns the current clock state for persistence.
func (c *Clock) Snapshot() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current()
}

// tick increments the counter, rolling into the next wall millisecond on the
// (rare) overflow so the clock never produces a duplicate timestamp.
func (c *Clock) tick() {
	if c.counter == ^uint32(0) {
		c.wall++
		c.counter = 0
		return
	}
	c.counter++
}

func (c *Clock) current() Timestamp {
	return Timestamp{Wall: c.wall, Counter: c.counter, NodeID: c.nodeID}
}

func cmpInt64(a, b int64) int {
	if a < b {
		return -1
	}
	return 1
}

func cmpUint32(a, b uint32) int {
	if a < b {
		return -1
	}
	return 1
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxUint32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}
