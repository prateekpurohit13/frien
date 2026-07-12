// Package enforcer owns the lifetime of frien's mitigations. It is the only
// component that ever touches a firewall, and it is built around one
// non-negotiable: frien cannot leak a permanent rule. Every rule an Adapter
// installs carries a kernel-native timeout so it self-removes even if every
// frien process dies; a dead-man's switch flushes frien's own chains if the
// daemon stops heartbeating; and every applied rule is recorded as a durable
// rollback token so a crash mid-change is reconciled on restart.
//
// The daemon (internal/policy) decides WHAT to enforce and only ever hands this
// package a decision that already passed quorum, protected-target, and
// partition-safety checks. This package decides HOW and, crucially, guarantees
// the rule's removal.
package enforcer

import (
	"time"
)

// Rule is a single mitigation to install. Token is the durable rollback handle
// (also used to find the rule again for removal); Timeout is the kernel-native
// expiry and must be > 0 for any enforcing action.
type Rule struct {
	Token   string
	Target  string        // IP or CIDR
	Action  string        // "block" | "rate_limit"
	Timeout time.Duration // kernel-native TTL; the rule self-removes when it elapses
	Chain   string        // frien chain to install into ("" = the adapter's default input chain)
}

// ActiveRule is a frien-managed rule currently installed on an adapter.
type ActiveRule struct {
	Token     string
	Target    string
	Action    string
	ExpiresAt time.Time
}

// Adapter is a pluggable enforcement backend (nftables, and later Kubernetes
// NetworkPolicy / Cilium / SIEM). Every method operates ONLY on frien's own
// chains/sets, never the host baseline — cleanup must never touch a rule frien
// did not create.
//
// Removal is fail-open by contract: Remove and FlushAll treat an
// already-absent rule as success, because the whole point of kernel timeouts
// and the dead-man's switch is that a rule may already be gone. Installation is
// fail-closed: Apply returns an error rather than pretending a rule exists.
type Adapter interface {
	// Name is the adapter key used in decisions and mode selection.
	Name() string
	// Apply installs a self-expiring rule. It is idempotent by Token: applying
	// the same token again refreshes rather than duplicates.
	Apply(r Rule) error
	// Remove deletes the rule identified by token. An absent token is success.
	Remove(token string) error
	// List returns the frien-managed rules currently active on this adapter.
	List() ([]ActiveRule, error)
	// FlushAll removes every frien-managed rule and returns how many were
	// removed. Used by the dead-man's switch and breakglass.
	FlushAll() (int, error)
}
