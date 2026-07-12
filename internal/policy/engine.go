package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// EvalInput is everything Evaluate needs to decide one indicator. The daemon
// assembles it from the op set (Contributions), the operator-signed active
// Policy, the node's per-adapter enforce-mode, its partition view, and the
// protected-target set. Evaluate performs no I/O and mutates nothing.
type EvalInput struct {
	Indicator     string
	IndicatorType string // "ip" | "cidr" | "hostname" | "user" | "hash"
	Scope         string // "local" | "zone:<name>" | "fleet"
	Contributions []Contribution
	NodeMode      string // this node/adapter's operator-promoted mode: observe|enforce
	Partition     PartitionState
	Protected     *ProtectedSet
	// RecordTTL is the (already coalesced) TTL declared by the threat record,
	// capped by the policy's max_ttl to produce the kernel timeout. Zero means
	// the record carried no TTL, in which case max_ttl (if any) is used.
	RecordTTL time.Duration
	Now       time.Time
}

// Decision is the full, explainable outcome for one indicator. It is the single
// source of truth behind both an EnforcementDecision op (when Outcome==enforced)
// and the ExplainDecision/TestPolicy admin responses.
type Decision struct {
	Indicator string
	Outcome   string // enforced | observe_only | denied_by_policy | no_record
	Reason    string
	Action    string
	Adapter   string
	Mode      string // observe | enforce — the mode actually applied

	MatchedWeight    float64
	RequiredWeight   float64
	Identities       []string
	ProtectedReasons []string

	PolicyID      string
	PolicyVersion int64

	KernelTimeout time.Duration
	ExpiresAt     time.Time
}

// Evaluate runs the full decision pipeline for one indicator and returns a
// Decision. The ordering encodes the safety priority: a protected target is
// denied before any quorum is even counted, and enforcement is only ever the
// outcome when every gate — record present, not protected, quorum met, not a
// minority partition (fleet scope), node promoted to enforce — passes.
func Evaluate(p *Policy, in EvalInput) Decision {
	d := Decision{
		Indicator:      in.Indicator,
		Action:         p.Action,
		Adapter:        p.AdapterName(),
		Mode:           ModeObserve,
		RequiredWeight: p.RequireWeight,
		PolicyID:       p.ID,
		PolicyVersion:  p.Version,
	}

	// 0. No evidence at all.
	if len(in.Contributions) == 0 {
		d.Outcome = OutcomeNoRecord
		d.Reason = "no present threat record for this indicator"
		return d
	}

	// 1. Protected target — a hard stop, checked before quorum. Even with
	// unanimous quorum, frien never blocks a protected address.
	if in.Protected != nil {
		if prot, reason := in.Protected.IsProtected(in.Indicator); prot {
			d.Outcome = OutcomeDeniedByPolicy
			d.Reason = "target is protected: " + reason
			d.ProtectedReasons = []string{reason}
			return d
		}
	}

	// 2. Weighted quorum of distinct, non-revoked identities within the window.
	q := EvaluateQuorum(p, in.Contributions, in.Now)
	d.MatchedWeight = q.MatchedWeight
	d.Identities = q.Identities
	if !q.Met {
		d.Outcome = OutcomeObserveOnly
		d.Reason = fmt.Sprintf("quorum not met: matched weight %g < required %g (%s)",
			q.MatchedWeight, q.RequiredWeight, q.Reason)
		return d
	}

	// 3. Partition safety — fleet-scoped enforcement is withheld in a minority
	// partition even when quorum weight was matched. Local/zone decisions on
	// directly-observed evidence are not subject to this.
	if isFleetScope(in.Scope) && !in.Partition.IsMajority() {
		d.Outcome = OutcomeObserveOnly
		d.Reason = fmt.Sprintf("minority partition (%d of %d known identities observable): "+
			"fleet-scoped enforcement withheld, intelligence-only",
			in.Partition.LiveDistinct, in.Partition.KnownDistinct)
		return d
	}

	// 4. Everything a decision needs is satisfied. Whether it is actually
	// applied depends on the node's operator-promoted mode. In observe mode the
	// decision is fully computed (and explainable) but no rule is applied.
	d.KernelTimeout = kernelTimeout(p, in.RecordTTL)
	if d.KernelTimeout > 0 {
		d.ExpiresAt = in.Now.Add(d.KernelTimeout)
	}

	if in.NodeMode != ModeEnforce {
		d.Outcome = OutcomeObserveOnly
		d.Reason = "quorum and policy satisfied; node/adapter in observe mode (no rule applied)"
		return d
	}

	// A block/rate_limit that self-expires in the kernel is required when the
	// policy demands it; a decision with no timeout under kernel_timeout_required
	// is refused rather than applied as a permanent rule.
	if p.KernelTimeoutRequired && d.KernelTimeout <= 0 && enforceable(p.Action) {
		d.Outcome = OutcomeDeniedByPolicy
		d.Reason = "policy requires a kernel timeout but the record/policy yields none"
		return d
	}

	d.Outcome = OutcomeEnforced
	d.Mode = ModeEnforce
	d.Reason = fmt.Sprintf("quorum met (weight %g >= %g) from %d distinct identities; enforcing %s on %s",
		q.MatchedWeight, q.RequiredWeight, len(q.Identities), p.Action, d.Adapter)
	return d
}

// enforceable reports whether an action produces a firewall rule that needs a
// kernel timeout. "alert" (SIEM) and "allow" do not.
func enforceable(action string) bool {
	return action == "block" || action == "rate_limit"
}

func isFleetScope(scope string) bool { return scope == "fleet" }

// kernelTimeout is the record TTL capped by the policy's max_ttl. When the
// record carries no TTL, the policy max is used as the timeout; when neither is
// set, the result is 0 (no kernel timeout — only valid for non-enforcing
// actions, gated above).
func kernelTimeout(p *Policy, recordTTL time.Duration) time.Duration {
	maxTTL := p.MaxTTLDuration()
	switch {
	case recordTTL <= 0:
		return maxTTL
	case maxTTL > 0 && recordTTL > maxTTL:
		return maxTTL
	default:
		return recordTTL
	}
}

// ToProto renders the policy-owned fields of an EnforcementDecision. The
// enforcer fills the remaining columns it owns (rollback_token, owner, applied,
// rolled_back) when it acts on the decision. id and created_at are supplied by
// the caller (the daemon mints a ULID and stamps the clock) so this function
// stays pure.
func (d Decision) ToProto(id, threatID, target, createdAt string) *frienv1.EnforcementDecision {
	out := &frienv1.EnforcementDecision{
		Id:                     id,
		ThreatId:               threatID,
		Action:                 d.Action,
		Target:                 target,
		Adapter:                d.Adapter,
		Mode:                   d.Mode,
		CreatedAt:              createdAt,
		ApprovedByPolicy:       d.PolicyID,
		PolicyVersion:          d.PolicyVersion,
		RequiredWeight:         d.RequiredWeight,
		MatchedWeight:          d.MatchedWeight,
		ContributingIdentities: append([]string(nil), d.Identities...),
	}
	if !d.ExpiresAt.IsZero() {
		out.ExpiresAt = d.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if d.KernelTimeout > 0 {
		out.KernelTimeout = d.KernelTimeout.String()
	}
	return out
}

// Summary is a compact one-line rendering of a decision for logs.
func (d Decision) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s -> %s", d.Indicator, d.Outcome)
	if d.Reason != "" {
		fmt.Fprintf(&b, " (%s)", d.Reason)
	}
	return b.String()
}

// SortIdentities is a small helper for callers assembling explanations.
func SortIdentities(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}
