package policy

import (
	"fmt"
	"net"
	"strings"
)

// DefaultProtectedCIDRs are the addresses frien policy must never block,
// enforced before the enforcer is ever called. IPv6 entries are mandatory —
// an IPv4-only protected list is a configuration error (see
// docs/ENFORCEMENT_SAFETY.md §3). 169.254.0.0/16 covers the cloud metadata
// endpoint (169.254.169.254); losing it can strand an instance.
var DefaultProtectedCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"169.254.0.0/16", // link-local incl. cloud metadata
	"::1/128",        // IPv6 loopback
	"fc00::/7",       // IPv6 unique local
	"fe80::/10",      // IPv6 link-local
}

// ProtectedSet answers "may frien block this target?". It combines the policy's
// protected CIDRs (or the safe defaults) with self-plane addresses added
// dynamically at startup (mesh peer, admin socket, metrics, management/SSH), so
// a policy can never lock frien out of its own control paths.
type ProtectedSet struct {
	cidrs         []*net.IPNet
	selfIPs       map[string]string // ip string -> human reason
	adminEndpoint string            // "ip:port" or "ip"; matched when DenyIfTargetIsAdminEndpoint
	denyAdmin     bool
}

// NewProtectedSet builds the set from a list of CIDR strings. An empty list is
// replaced by DefaultProtectedCIDRs. It fails if any CIDR is malformed or if
// the resulting list has no IPv6 entry (the IPv4-only guard).
func NewProtectedSet(cidrs []string) (*ProtectedSet, error) {
	if len(cidrs) == 0 {
		cidrs = DefaultProtectedCIDRs
	}
	ps := &ProtectedSet{selfIPs: make(map[string]string)}
	sawV6 := false
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("protected: invalid CIDR %q: %w", c, err)
		}
		if n.IP.To4() == nil {
			sawV6 = true
		}
		ps.cidrs = append(ps.cidrs, n)
	}
	if !sawV6 {
		return nil, fmt.Errorf("protected: list has no IPv6 CIDR; an IPv4-only protected list is a configuration error")
	}
	return ps, nil
}

// FromPolicy builds a ProtectedSet from a policy's protected_cidrs and wires
// deny_if_target_is_admin_endpoint. Self-plane addresses are added afterward
// via AddSelfPlane when protect_self_planes is set.
func FromPolicy(p *Policy) (*ProtectedSet, error) {
	ps, err := NewProtectedSet(p.ProtectedCIDRs)
	if err != nil {
		return nil, err
	}
	ps.denyAdmin = p.DenyIfTargetIsAdminEndpoint
	return ps, nil
}

// AddSelfPlane registers one self-plane address (an "ip", "ip:port", or bare
// host) as protected with a human-readable reason. Blank or unparseable
// host parts are ignored rather than erroring, so a partially-configured
// management path never blocks startup.
func (ps *ProtectedSet) AddSelfPlane(addr, reason string) {
	ip := extractIP(addr)
	if ip == "" {
		return
	}
	ps.selfIPs[ip] = reason
}

// SetAdminEndpoint records the admin endpoint used by
// deny_if_target_is_admin_endpoint.
func (ps *ProtectedSet) SetAdminEndpoint(addr string) {
	ps.adminEndpoint = extractIP(addr)
}

// IsProtected reports whether target (an indicator value) may not be blocked,
// and why. It only meaningfully applies to ip/cidr indicators; hostname/user/
// hash indicators return (false, "") since they are not addresses a firewall
// rule would match against a protected range. The admin-endpoint check applies
// only when the policy set DenyIfTargetIsAdminEndpoint.
func (ps *ProtectedSet) IsProtected(target string) (bool, string) {
	ip, ipnet := parseTarget(target)
	if ip == nil && ipnet == nil {
		return false, "" // not an address; protected-CIDR logic does not apply
	}

	// Self-plane exact-IP match first (most specific).
	if ip != nil {
		if reason, ok := ps.selfIPs[ip.String()]; ok {
			return true, "self-plane: " + reason
		}
		if ps.denyAdmin && ps.adminEndpoint != "" && ip.String() == ps.adminEndpoint {
			return true, "target is the admin endpoint"
		}
	}

	for _, n := range ps.cidrs {
		switch {
		case ip != nil && n.Contains(ip):
			return true, "within protected CIDR " + n.String()
		case ipnet != nil && cidrOverlaps(n, ipnet):
			// A CIDR indicator that overlaps a protected range is refused: a
			// block on 10.0.0.0/8 must not slip through just because it is a
			// range rather than a single protected IP.
			return true, "overlaps protected CIDR " + n.String()
		}
	}
	return false, ""
}

// parseTarget interprets an indicator as a single IP or a CIDR. Exactly one of
// the returns is non-nil on success; both nil means "not an address".
func parseTarget(target string) (net.IP, *net.IPNet) {
	target = strings.TrimSpace(target)
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}
	if _, n, err := net.ParseCIDR(target); err == nil {
		return nil, n
	}
	return nil, nil
}

// extractIP pulls the IP out of an "ip", "ip:port", or "host:port" string.
// Returns "" if no IP can be recovered.
func extractIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

// cidrOverlaps reports whether two networks share any address.
func cidrOverlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}
