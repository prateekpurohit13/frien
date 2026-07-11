package identity

import (
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// TrustBundle holds the CA material a node currently accepts peer
// certificates against, supporting a bounded overlap window during CA
// rotation: preparing a new bundle does not immediately retire the old one.
// A peer that hasn't yet observed the new bundle (still presenting an
// old-CA-issued cert) is not rejected, and a peer that has already rotated
// to a new-CA-issued cert is accepted right away too -- both directions stay
// valid until the window elapses, at which point the old material is
// dropped automatically on the next read. This replaces the atomic,
// single-pool CA cutover the daemon used before (see docs/task-checklist.md's
// Phase 4 follow-up section).
type TrustBundle struct {
	mu         sync.Mutex
	currentPEM []byte
	nextPEM    []byte
	stagedAt   time.Time
	window     time.Duration
	now        func() time.Time
}

// NewTrustBundle wraps an initial CA bundle (PEM, possibly multiple certs).
// window bounds how long a prepared next bundle stays valid alongside the
// current one before superseding it; zero defaults to 24 hours.
func NewTrustBundle(initialPEM []byte, window time.Duration) (*TrustBundle, error) {
	if _, err := buildPool(initialPEM); err != nil {
		return nil, err
	}
	if window <= 0 {
		window = 24 * time.Hour
	}
	return &TrustBundle{currentPEM: initialPEM, window: window, now: time.Now}, nil
}

// NewTrustBundleFromFile loads the initial bundle from path.
func NewTrustBundleFromFile(path string, window time.Duration) (*TrustBundle, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: reading CA bundle %s: %w", path, err)
	}
	return NewTrustBundle(pem, window)
}

// PrepareNext stages a new CA bundle. From this call onward, Pool returns
// the union of the current and next bundles until the overlap window
// elapses (measured from this call), after which next silently supersedes
// current (see Pool). The bundle is validated (must parse to at least one
// certificate) before it's staged, so a malformed rotation attempt fails
// loudly here rather than silently locking peers out later.
func (b *TrustBundle) PrepareNext(nextPEM []byte) error {
	if _, err := buildPool(nextPEM); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextPEM = nextPEM
	b.stagedAt = b.now()
	return nil
}

// PrepareNextFromFile stages a new CA bundle read from path.
func (b *TrustBundle) PrepareNextFromFile(path string) error {
	pem, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("identity: reading CA bundle %s: %w", path, err)
	}
	return b.PrepareNext(pem)
}

// Pool returns the currently effective trust pool: the current bundle alone,
// or the union of current and next during an active overlap window. It also
// performs the implicit cutover once the window elapses -- next becomes
// current and the old material is dropped -- so a caller never needs a
// separate background timer to complete a rotation; it completes itself the
// next time anything asks for the pool after the window has passed.
func (b *TrustBundle) Pool() (*x509.CertPool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.nextPEM == nil {
		return buildPool(b.currentPEM)
	}
	if b.now().Sub(b.stagedAt) >= b.window {
		b.currentPEM = b.nextPEM
		b.nextPEM = nil
		return buildPool(b.currentPEM)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.currentPEM) || !pool.AppendCertsFromPEM(b.nextPEM) {
		return nil, fmt.Errorf("identity: trust bundle overlap pool failed to parse")
	}
	return pool, nil
}

// InOverlap reports whether a prepared next bundle is still within its
// overlap window (for admin status / observability).
func (b *TrustBundle) InOverlap() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.nextPEM != nil && b.now().Sub(b.stagedAt) < b.window
}

// SetClock overrides the bundle's time source, for deterministic tests of
// overlap-window expiry without a real sleep.
func (b *TrustBundle) SetClock(now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
}

func buildPool(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("identity: no valid certificates in CA bundle")
	}
	return pool, nil
}
