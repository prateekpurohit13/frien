package gossip

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/transport"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// streamKind tags each peer stream with the exchange it carries. It is written
// as a single leading byte before the request frame.
type streamKind byte

const (
	kindPing streamKind = iota + 1
	kindPingReq
	kindAntiEntropy
)

const streamTimeout = 5 * time.Second

// Handler serves inbound peer exchanges. The engine implements it.
type Handler interface {
	OnPing(*frienv1.Ping) *frienv1.Ack
	OnPingReq(context.Context, *frienv1.PingReq) *frienv1.Ack
	OnAntiEntropy(*frienv1.AntiEntropyRequest) *frienv1.AntiEntropyResponse
}

// roundtrip performs one request/response exchange on a fresh stream.
func roundtrip(ctx context.Context, sess *transport.Session, kind streamKind, req, resp proto.Message) error {
	stream, err := sess.OpenStream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(streamTimeout))

	if _, err := stream.Write([]byte{byte(kind)}); err != nil {
		return err
	}
	if err := sess.WriteMessage(stream, req); err != nil {
		return err
	}
	return sess.ReadMessage(stream, resp)
}

// serveStream reads one request from an accepted stream, dispatches it to the
// handler by kind, and writes the response.
func serveStream(ctx context.Context, sess *transport.Session, stream *quic.Stream, h Handler) error {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(streamTimeout))

	var kb [1]byte
	if _, err := io.ReadFull(stream, kb[:]); err != nil {
		return err
	}
	switch streamKind(kb[0]) {
	case kindPing:
		var req frienv1.Ping
		if err := sess.ReadMessage(stream, &req); err != nil {
			return err
		}
		return sess.WriteMessage(stream, h.OnPing(&req))
	case kindPingReq:
		var req frienv1.PingReq
		if err := sess.ReadMessage(stream, &req); err != nil {
			return err
		}
		return sess.WriteMessage(stream, h.OnPingReq(ctx, &req))
	case kindAntiEntropy:
		var req frienv1.AntiEntropyRequest
		if err := sess.ReadMessage(stream, &req); err != nil {
			return err
		}
		return sess.WriteMessage(stream, h.OnAntiEntropy(&req))
	default:
		return fmt.Errorf("gossip: unknown stream kind %d", kb[0])
	}
}
