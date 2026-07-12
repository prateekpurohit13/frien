package enforcer

import (
	"sync"
	"time"
)

// MemAdapter is an in-memory Adapter that simulates kernel-native rule expiry:
// a rule installed with a Timeout is considered gone once its ExpiresAt has
// passed, exactly as an nftables element with a `timeout` would be reaped by
// the kernel. It is the backend used on non-Linux platforms, in observe/dry-run
// contexts, and in tests — including the tests that prove the two hardest exit
// criteria (a rule self-expires; a "crashed" daemon leaks no rule past the
// timeout) without needing a real kernel.
//
// Time is injectable so tests can advance it deterministically instead of
// sleeping. In production it uses time.Now.
type MemAdapter struct {
	name string
	now  func() time.Time

	mu    sync.Mutex
	rules map[string]memRule // token -> rule
}

type memRule struct {
	target    string
	action    string
	expiresAt time.Time // zero = no expiry (only valid for non-enforcing actions)
}

// NewMemAdapter creates an in-memory adapter. now may be nil (defaults to
// time.Now).
func NewMemAdapter(name string, now func() time.Time) *MemAdapter {
	if now == nil {
		now = time.Now
	}
	return &MemAdapter{name: name, now: now, rules: make(map[string]memRule)}
}

func (m *MemAdapter) Name() string { return m.name }

func (m *MemAdapter) Apply(r Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapLocked()
	mr := memRule{target: r.Target, action: r.Action}
	if r.Timeout > 0 {
		mr.expiresAt = m.now().Add(r.Timeout)
	}
	m.rules[r.Token] = mr
	return nil
}

func (m *MemAdapter) Remove(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rules, token) // absent token is success (fail-open)
	return nil
}

func (m *MemAdapter) List() ([]ActiveRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapLocked()
	out := make([]ActiveRule, 0, len(m.rules))
	for token, mr := range m.rules {
		out = append(out, ActiveRule{Token: token, Target: mr.target, Action: mr.action, ExpiresAt: mr.expiresAt})
	}
	return out, nil
}

func (m *MemAdapter) FlushAll() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reapLocked()
	n := len(m.rules)
	m.rules = make(map[string]memRule)
	return n, nil
}

// reapLocked drops rules whose kernel timeout has elapsed, modeling the
// kernel's own reaper. Callers hold m.mu.
func (m *MemAdapter) reapLocked() {
	now := m.now()
	for token, mr := range m.rules {
		if !mr.expiresAt.IsZero() && !now.Before(mr.expiresAt) {
			delete(m.rules, token)
		}
	}
}
