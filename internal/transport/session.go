package transport

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/version"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

const frameHeaderBytes = 4

// ErrMessageTooLarge is returned when a frame would exceed the negotiated
// per-message ceiling. It is enforced on both write and read so a hostile peer
// cannot force an unbounded allocation.
var ErrMessageTooLarge = errors.New("transport: message exceeds max size")

// Session is an authenticated QUIC connection to one peer. Its identity fields
// are derived from the verified mTLS leaf certificate; Version is the protocol
// version both peers agreed on at handshake.
type Session struct {
	conn        *quic.Conn
	NodeID      string
	Fingerprint string
	// PeerKey is the ed25519 public key bound in the peer's already CA-verified
	// leaf certificate. Per the architecture, this is the same key the peer signs
	// operation envelopes with, so an established session is a trustworthy source
	// for populating a node's envelope-verification key without a separate
	// key-distribution step. Nil if the peer's certificate does not carry an
	// ed25519 key (should not happen for a conforming node).
	PeerKey ed25519.PublicKey
	// TrustTier is the quorum trust tier bound in the peer's CA-signed leaf
	// certificate (see identity.TrustTierFromCert). It is authoritative precisely
	// because it comes from the signed cert, not a self-report a node could
	// inflate.
	TrustTier string
	Version   uint32
	maxBytes  int
	log       zerolog.Logger
}

func newSession(conn *quic.Conn, maxBytes int, log zerolog.Logger) (*Session, error) {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("transport: peer presented no certificate")
	}
	leaf := certs[0]
	peerKey, _ := leaf.PublicKey.(ed25519.PublicKey)
	return &Session{
		conn:        conn,
		NodeID:      leaf.Subject.CommonName,
		Fingerprint: identity.CertFingerprint(leaf),
		PeerKey:     peerKey,
		TrustTier:   identity.TrustTierFromCert(leaf),
		maxBytes:    maxBytes,
		log:         log,
	}, nil
}

// OpenStream opens a new bidirectional stream for application traffic (gossip,
// anti-entropy). Negotiation has already completed by the time a caller holds a
// Session, so every stream runs at the agreed protocol version.
func (s *Session) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return s.conn.OpenStreamSync(ctx)
}

// AcceptStream accepts the next inbound application stream from the peer.
func (s *Session) AcceptStream(ctx context.Context) (*quic.Stream, error) {
	return s.conn.AcceptStream(ctx)
}

// Close tears the session down.
func (s *Session) Close() error { return s.conn.CloseWithError(0, "session closed") }

// negotiateClient runs the initiator side of version negotiation on the first
// stream: advertise supported versions, then validate the responder's choice.
func (s *Session) negotiateClient(ctx context.Context) error {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("transport: opening negotiation stream: %w", err)
	}
	defer stream.Close()

	req := &frienv1.NegotiateRequest{SupportedVersions: version.SupportedVersions}
	if err := writeFrame(stream, req, s.maxBytes); err != nil {
		return fmt.Errorf("transport: sending negotiation: %w", err)
	}
	var resp frienv1.NegotiateResponse
	if err := readFrame(stream, &resp, s.maxBytes); err != nil {
		return fmt.Errorf("transport: reading negotiation: %w", err)
	}
	v, err := version.Accept(resp.GetNegotiatedVersion())
	if err != nil {
		return fmt.Errorf("transport: negotiating with %s: %w", s.NodeID, err)
	}
	s.Version = v
	return nil
}

// negotiateServer runs the responder side: read the peer's supported versions,
// pick the highest common one, and reply. A peer with no common version is told
// explicitly (negotiated_version = 0) and the handshake fails.
func (s *Session) negotiateServer(ctx context.Context) error {
	stream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("transport: accepting negotiation stream: %w", err)
	}
	defer stream.Close()

	var req frienv1.NegotiateRequest
	if err := readFrame(stream, &req, s.maxBytes); err != nil {
		return fmt.Errorf("transport: reading negotiation: %w", err)
	}
	v, rerr := version.Resolve(req.GetSupportedVersions())
	if werr := writeFrame(stream, &frienv1.NegotiateResponse{NegotiatedVersion: v}, s.maxBytes); werr != nil {
		return fmt.Errorf("transport: sending negotiation: %w", werr)
	}
	if rerr != nil {
		return fmt.Errorf("transport: negotiating with %s: %w", s.NodeID, rerr)
	}
	s.Version = v
	return nil
}

// writeFrame writes a length-prefixed protobuf message: a 4-byte big-endian
// length followed by the marshaled payload.
func writeFrame(w io.Writer, msg proto.Message, maxBytes int) error {
	b, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("transport: marshaling frame: %w", err)
	}
	if len(b) > maxBytes {
		return ErrMessageTooLarge
	}
	var hdr [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readFrame reads one length-prefixed protobuf message, rejecting any frame
// whose declared length exceeds maxBytes before allocating for it.
func readFrame(r io.Reader, msg proto.Message, maxBytes int) error {
	var hdr [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if int(n) > maxBytes {
		return ErrMessageTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return proto.Unmarshal(buf, msg)
}

// WriteMessage writes a framed protobuf message to an application stream.
func (s *Session) WriteMessage(w io.Writer, msg proto.Message) error {
	return writeFrame(w, msg, s.maxBytes)
}

// ReadMessage reads a framed protobuf message from an application stream.
func (s *Session) ReadMessage(r io.Reader, msg proto.Message) error {
	return readFrame(r, msg, s.maxBytes)
}
