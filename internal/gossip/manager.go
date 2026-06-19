package gossip

import (
	"context"
	"sync"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/transport"
)

// Manager owns peer connections: it accepts inbound sessions, dials and pools
// outbound ones, and runs a stream-serve loop on every session so a single QUIC
// connection carries traffic in both directions.
type Manager struct {
	tr      *transport.Transport
	handler Handler
	log     zerolog.Logger

	mu       sync.Mutex
	sessions map[string]*transport.Session
	ln       *transport.Listener
}

func NewManager(tr *transport.Transport, handler Handler, log zerolog.Logger) *Manager {
	return &Manager{
		tr:       tr,
		handler:  handler,
		log:      log,
		sessions: make(map[string]*transport.Session),
	}
}

// Listen starts accepting inbound peer connections until ctx is cancelled.
func (m *Manager) Listen(ctx context.Context) error {
	ln, err := m.tr.Listen()
	if err != nil {
		return err
	}
	m.ln = ln
	go m.acceptLoop(ctx, ln)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	return nil
}

func (m *Manager) acceptLoop(ctx context.Context, ln *transport.Listener) {
	for {
		sess, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		m.register(sess)
		go m.serve(ctx, sess)
	}
}

func (m *Manager) serve(ctx context.Context, sess *transport.Session) {
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			m.drop(sess.NodeID)
			return
		}
		go func() {
			if err := serveStream(ctx, sess, stream, m.handler); err != nil {
				m.log.Debug().Err(err).Str("peer", sess.NodeID).Msg("stream served with error")
			}
		}()
	}
}

// Dial connects to addr, pools the session by its peer node id, and starts
// serving inbound streams over it.
func (m *Manager) Dial(ctx context.Context, addr string) (*transport.Session, error) {
	sess, err := m.tr.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	m.register(sess)
	go m.serve(ctx, sess)
	return sess, nil
}

// SessionFor returns a pooled session for nodeID, dialing addr if none exists.
func (m *Manager) SessionFor(ctx context.Context, nodeID, addr string) (*transport.Session, error) {
	m.mu.Lock()
	s := m.sessions[nodeID]
	m.mu.Unlock()
	if s != nil {
		return s, nil
	}
	return m.Dial(ctx, addr)
}

func (m *Manager) register(sess *transport.Session) {
	m.mu.Lock()
	m.sessions[sess.NodeID] = sess
	m.mu.Unlock()
}

func (m *Manager) drop(nodeID string) {
	m.mu.Lock()
	delete(m.sessions, nodeID)
	m.mu.Unlock()
}
