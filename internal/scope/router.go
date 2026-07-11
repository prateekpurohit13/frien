package scope

import (
	"fmt"
	"sort"
	"strings"
)

// Kind is the replication class of an op's scope.
type Kind uint8

const (
	Local Kind = iota // stored only on the origin node; never gossiped
	Zone              // gossiped only within a named zone
	Fleet             // gossiped to every node
)

const maxZoneNameLen = 64

// Scope is a parsed `scope` field: "local", "fleet", or "zone:<name>".
type Scope struct {
	Kind Kind
	Zone string
}

func (s Scope) String() string {
	switch s.Kind {
	case Local:
		return "local"
	case Fleet:
		return "fleet"
	case Zone:
		return "zone:" + s.Zone
	default:
		return "unknown"
	}
}

// Parse parses a scope string, rejecting malformed zone names so a bad scope is
// caught at ingress rather than silently widening replication.
func Parse(s string) (Scope, error) {
	switch {
	case s == "local":
		return Scope{Kind: Local}, nil
	case s == "fleet":
		return Scope{Kind: Fleet}, nil
	case strings.HasPrefix(s, "zone:"):
		name := s[len("zone:"):]
		if err := validateZone(name); err != nil {
			return Scope{}, err
		}
		return Scope{Kind: Zone, Zone: name}, nil
	default:
		return Scope{}, fmt.Errorf("scope: invalid scope %q", s)
	}
}

func validateZone(name string) error {
	if name == "" || len(name) > maxZoneNameLen {
		return fmt.Errorf("scope: zone name must be 1-%d chars, got %q", maxZoneNameLen, name)
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("scope: zone name %q has invalid character %q", name, r)
		}
	}
	return nil
}

// Router decides, for this node, which scopes are replicated and which ops may
// flow to or from a given peer. Scope is enforced on both egress and ingress so
// a bug or a hostile peer on one side cannot widen replication on its own.
type Router struct {
	nodeZone   string
	subscribed map[string]bool // zone names this node replicates (always incl. nodeZone)
}

// NewRouter builds a router for a node in nodeZone. The node always replicates
// its own zone and the fleet scope; extraZones lets a core/aggregator node
// subscribe to additional zones.
func NewRouter(nodeZone string, extraZones ...string) *Router {
	sub := map[string]bool{nodeZone: true}
	for _, z := range extraZones {
		sub[z] = true
	}
	return &Router{nodeZone: nodeZone, subscribed: sub}
}

// SubscribedZones returns the zone names this node replicates, sorted for
// determinism -- its own zone plus any extra zones an aggregator carries.
func (r *Router) SubscribedZones() []string {
	out := make([]string, 0, len(r.subscribed))
	for z := range r.subscribed {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// Replicates reports whether this node stores ops of the given scope at all.
func (r *Router) Replicates(s Scope) bool {
	switch s.Kind {
	case Local:
		return true // only ever the node's own locally-created ops
	case Fleet:
		return true
	case Zone:
		return r.subscribed[s.Zone]
	default:
		return false
	}
}

// ShouldSend reports whether an op of scope s should be gossiped to a peer in
// peerZone. Local ops never leave the origin; fleet goes everywhere; a zone op
// goes only to peers in that zone.
func (r *Router) ShouldSend(s Scope, peerZone string) bool {
	switch s.Kind {
	case Local:
		return false
	case Fleet:
		return true
	case Zone:
		return s.Zone == peerZone
	default:
		return false
	}
}

// Accept reports whether an op of scope s received from a peer may enter local
// state. A received local op is always illegitimate (local never gossips); a
// zone op is accepted only for a zone this node replicates.
func (r *Router) Accept(s Scope) bool {
	switch s.Kind {
	case Local:
		return false
	case Fleet:
		return true
	case Zone:
		return r.subscribed[s.Zone]
	default:
		return false
	}
}
