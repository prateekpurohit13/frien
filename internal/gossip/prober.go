package gossip

import (
	"context"
	"fmt"

	"github.com/prateekpurohit13/frien/internal/membership"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// prober implements membership.Prober over QUIC. Every probe and ack piggybacks
// membership updates (including the local node's own alive state and address),
// so the failure detector and the roster disseminate together — closing the
// Phase 2 deferral.
type prober struct {
	eng *Engine
}

func (p *prober) Ping(ctx context.Context, target membership.Member) error {
	if len(target.Addresses) == 0 {
		return fmt.Errorf("gossip: no address for %s", target.NodeID)
	}
	sess, err := p.eng.mgr.SessionFor(ctx, target.NodeID, target.Addresses[0])
	if err != nil {
		return err
	}
	req := &frienv1.Ping{
		ProtoVersion: p.eng.cfg.ProtoVersion,
		SenderNodeId: p.eng.cfg.NodeID,
		Updates:      p.eng.outUpdates(),
	}
	var ack frienv1.Ack
	if err := roundtrip(ctx, sess, kindPing, req, &ack); err != nil {
		p.eng.mgr.drop(target.NodeID)
		return err
	}
	applyUpdates(p.eng.swim, ack.GetUpdates())
	return nil
}

func (p *prober) PingReq(ctx context.Context, relay, target membership.Member) error {
	if len(relay.Addresses) == 0 {
		return fmt.Errorf("gossip: no address for relay %s", relay.NodeID)
	}
	sess, err := p.eng.mgr.SessionFor(ctx, relay.NodeID, relay.Addresses[0])
	if err != nil {
		return err
	}
	addr := ""
	if len(target.Addresses) > 0 {
		addr = target.Addresses[0]
	}
	req := &frienv1.PingReq{
		ProtoVersion:  p.eng.cfg.ProtoVersion,
		SenderNodeId:  p.eng.cfg.NodeID,
		TargetAddress: addr,
		Updates:       p.eng.outUpdates(),
	}
	var ack frienv1.Ack
	if err := roundtrip(ctx, sess, kindPingReq, req, &ack); err != nil {
		return err
	}
	applyUpdates(p.eng.swim, ack.GetUpdates())
	if !ack.GetReachable() {
		return fmt.Errorf("gossip: relay %s could not reach %s", relay.NodeID, target.NodeID)
	}
	return nil
}
