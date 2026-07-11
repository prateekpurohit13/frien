package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/identity"
)

// TrustSource supplies the currently effective CA pool. identity.TrustBundle
// satisfies it; a Transport built from a plain *x509.CertPool wraps it in a
// static source that always returns the same pool.
type TrustSource interface {
	Pool() (*x509.CertPool, error)
}

type staticTrust struct{ pool *x509.CertPool }

func (s staticTrust) Pool() (*x509.CertPool, error) { return s.pool, nil }

// Config holds the transport tunables drawn from the daemon's transport config.
type Config struct {
	BindAddr        string // "host:port" UDP address for the peer listener
	MaxMessageBytes int    // per-message ceiling enforced on every frame
	DialTimeout     time.Duration
	IdleTimeout     time.Duration // connection closed after this much silence
	KEM             KEMMode
}

// Transport establishes authenticated QUIC peer sessions. It is the single entry
// point for both listening (accepting peers) and dialing (connecting to seeds and
// peers); every session it returns has completed mTLS and protocol negotiation.
type Transport struct {
	id       *identity.Identity
	tlsConf  *tls.Config
	quicConf *quic.Config
	bindAddr string
	maxBytes int
	dialTO   time.Duration
	log      zerolog.Logger

	trustSrc TrustSource
	trustMu  sync.RWMutex
	trust    *x509.CertPool // last pool resolved from trustSrc; read by every handshake
}

// New builds a Transport bound to a node identity and the mesh CA pool. rc may be
// nil until the revocation set exists (Phase 4); a nil checker revokes nothing.
// For a CA pool that never rotates, pass a plain *x509.CertPool; for one that
// does, build a Transport with NewWithTrustSource instead.
func New(id *identity.Identity, caPool *x509.CertPool, cfg Config, rc RevocationChecker, log zerolog.Logger) (*Transport, error) {
	if caPool == nil {
		return nil, fmt.Errorf("transport: CA pool is required for peer verification")
	}
	return NewWithTrustSource(id, staticTrust{pool: caPool}, cfg, rc, log)
}

// NewWithTrustSource builds a Transport whose trust pool is resolved from src
// at construction and again on every RefreshTrust call, so a live CA rotation
// (see identity.TrustBundle) takes effect without rebuilding the Transport.
func NewWithTrustSource(id *identity.Identity, src TrustSource, cfg Config, rc RevocationChecker, log zerolog.Logger) (*Transport, error) {
	if cfg.MaxMessageBytes <= 0 {
		return nil, fmt.Errorf("transport: max_message_bytes must be positive, got %d", cfg.MaxMessageBytes)
	}
	if src == nil {
		return nil, fmt.Errorf("transport: trust source is required for peer verification")
	}
	initial, err := src.Pool()
	if err != nil {
		return nil, fmt.Errorf("transport: resolving initial CA pool: %w", err)
	}
	t := &Transport{id: id, trustSrc: src, trust: initial, log: log}
	tlsConf, err := tlsConfig(id, t.currentPool, cfg.KEM, rc)
	if err != nil {
		return nil, err
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = 30 * time.Second
	}
	t.tlsConf = tlsConf
	t.quicConf = &quic.Config{MaxIdleTimeout: idle, KeepAlivePeriod: idle / 2}
	t.bindAddr = cfg.BindAddr
	t.maxBytes = cfg.MaxMessageBytes
	t.dialTO = cfg.DialTimeout
	return t, nil
}

// currentPool returns the last resolved trust pool. It is the accessor every
// handshake reads through (see tlsConfig); RefreshTrust is what actually
// updates it.
func (t *Transport) currentPool() *x509.CertPool {
	t.trustMu.RLock()
	defer t.trustMu.RUnlock()
	return t.trust
}

// RefreshTrust re-queries the Transport's TrustSource and, on success, swaps
// in the result for every subsequent handshake. On error the previous pool
// stays in effect (fail-safe: a transient read/parse error on a prepared
// rotation must never leave the node unable to verify any peer at all).
func (t *Transport) RefreshTrust() error {
	pool, err := t.trustSrc.Pool()
	if err != nil {
		return fmt.Errorf("transport: refreshing trust pool: %w", err)
	}
	t.trustMu.Lock()
	t.trust = pool
	t.trustMu.Unlock()
	return nil
}

// Listen opens the QUIC listener on the configured bind address.
func (t *Transport) Listen() (*Listener, error) {
	ql, err := quic.ListenAddr(t.bindAddr, t.tlsConf, t.quicConf)
	if err != nil {
		return nil, fmt.Errorf("transport: listen on %s: %w", t.bindAddr, err)
	}
	t.log.Info().Str("addr", ql.Addr().String()).Msg("peer transport listening")
	return &Listener{ql: ql, t: t}, nil
}

// Dial connects to a peer, completing mTLS and the initiator side of protocol
// negotiation before returning a ready session.
func (t *Transport) Dial(ctx context.Context, addr string) (*Session, error) {
	dialCtx := ctx
	if t.dialTO > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, t.dialTO)
		defer cancel()
	}
	conn, err := quic.DialAddr(dialCtx, addr, t.tlsConf, t.quicConf)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	sess, err := newSession(conn, t.maxBytes, t.log)
	if err != nil {
		_ = conn.CloseWithError(0, "session setup failed")
		return nil, err
	}
	if err := sess.negotiateClient(ctx); err != nil {
		_ = conn.CloseWithError(0, "negotiation failed")
		return nil, err
	}
	t.log.Info().Str("peer", sess.NodeID).Uint32("proto_version", sess.Version).Msg("dialed peer session")
	return sess, nil
}

// Listener accepts inbound peer sessions from the QUIC listener.
type Listener struct {
	ql *quic.Listener
	t  *Transport
}

// Accept blocks until a peer connects, then completes the responder side of
// protocol negotiation before returning the session.
func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	conn, err := l.ql.Accept(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := newSession(conn, l.t.maxBytes, l.t.log)
	if err != nil {
		_ = conn.CloseWithError(0, "session setup failed")
		return nil, err
	}
	if err := sess.negotiateServer(ctx); err != nil {
		_ = conn.CloseWithError(0, "negotiation failed")
		return nil, err
	}
	l.t.log.Info().Str("peer", sess.NodeID).Uint32("proto_version", sess.Version).Msg("accepted peer session")
	return sess, nil
}

// Addr returns the listener's local UDP address.
func (l *Listener) Addr() net.Addr { return l.ql.Addr() }

// Close stops accepting new connections.
func (l *Listener) Close() error { return l.ql.Close() }
