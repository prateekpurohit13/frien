package gossip

import (
	"github.com/prateekpurohit13/frien/internal/membership"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func drainUpdates(swim *membership.SWIM, max int) []*frienv1.PeerUpdate {
	ups := swim.Updates(max)
	out := make([]*frienv1.PeerUpdate, 0, len(ups))
	for _, u := range ups {
		out = append(out, &frienv1.PeerUpdate{
			NodeId:      u.NodeID,
			Addresses:   u.Addresses,
			State:       uint32(u.State),
			Incarnation: u.Incarnation,
		})
	}
	return out
}

func applyUpdates(swim *membership.SWIM, ups []*frienv1.PeerUpdate) {
	for _, pu := range ups {
		swim.Apply(membership.Update{
			NodeID:      pu.GetNodeId(),
			Addresses:   pu.GetAddresses(),
			State:       membership.State(pu.GetState()),
			Incarnation: pu.GetIncarnation(),
		})
	}
}
