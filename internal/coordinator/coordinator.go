// Package coordinator is the daemon-level bridge between frien's replicated
// state and its enforcement path. It gathers the present threat reports for an
// indicator, hands them to the pure policy engine (internal/policy), and — when
// a decision comes back "enforced" and the operator has promoted the adapter —
// applies it through the enforcement Client (which drives the privileged
// frien-enforcer), records an immutable audit entry, and publishes the
// resulting EnforcementDecision back into the mesh.
//
// It owns no decision logic of its own: every safety judgment (quorum,
// protected targets, partition safety, observe-vs-enforce) lives in
// internal/policy. This package only collects inputs, sequences side effects,
// and dedupes so a standing threat is enforced once rather than every sweep.
package coordinator

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// StateReader supplies the present threat ops and their local receive times.
// gossip.Engine satisfies it.
type StateReader interface {
	PresentThreatOps(now time.Time) []*frienv1.OperationEnvelope
	ReceivedAt(opID string) time.Time
}

// Publisher publishes a decision op into the mesh. gossip.Engine satisfies it.
type Publisher interface {
	Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error)
}

// TrustResolver maps an origin identity to its trust tier and reports whether
// it is excluded from fresh quorum (revoked or tainted). The daemon backs it
// with the membership roster's tiers and the revocation set.
type TrustResolver interface {
	TrustTier(nodeID, fingerprint string) string
	Excluded(nodeID, fingerprint string) bool
}

// PartitionResolver reports the node's current partition view for fleet-scope
// safety. The daemon computes it from live vs. known distinct membership.
type PartitionResolver interface {
	Partition() policy.PartitionState
}

// Coordinator wires the pieces together. It is safe for concurrent use.
type Coordinator struct {
	nodeID string
	log    zerolog.Logger
	clock  func() time.Time

	client    enforcer.Client
	auditLog  *audit.Log
	state     StateReader
	publisher Publisher
	trust     TrustResolver
	partition PartitionResolver

	mu        sync.Mutex
	policy    *policy.Policy
	protected *policy.ProtectedSet
}

// Deps bundles the coordinator's collaborators.
type Deps struct {
	NodeID    string
	Clock     func() time.Time
	Client    enforcer.Client
	Audit     *audit.Log
	State     StateReader
	Publisher Publisher
	Trust     TrustResolver
	Partition PartitionResolver
	Log       zerolog.Logger
}

// New builds a Coordinator. No active policy is set until SetPolicy is called;
// until then every Evaluate returns a no-policy error and nothing is enforced —
// the fail-safe default.
func New(d Deps) *Coordinator {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Coordinator{
		nodeID:    d.NodeID,
		log:       d.Log,
		clock:     d.Clock,
		client:    d.Client,
		auditLog:  d.Audit,
		state:     d.State,
		publisher: d.Publisher,
		trust:     d.Trust,
		partition: d.Partition,
	}
}

// SetPolicy installs a verified active policy and its derived protected set. A
// new policy simply re-evaluates everything on the next sweep; there is no
// per-indicator memory to reset because dedup is computed against the
// enforcer's actual active rules, not a cached map (see Sweep). The caller is
// responsible for having verified the policy's operator signature first.
func (c *Coordinator) SetPolicy(p *policy.Policy, protected *policy.ProtectedSet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policy = p
	c.protected = protected
	if c.auditLog != nil && p != nil {
		_, _ = c.auditLog.Append(audit.Entry{
			Actor:    "operator",
			Action:   audit.ActionPolicyLoad,
			PolicyID: p.ID,
			Reason:   fmt.Sprintf("policy %s v%d activated", p.ID, p.Version),
		})
	}
}

// ActivePolicy returns the current policy (may be nil).
func (c *Coordinator) ActivePolicy() *policy.Policy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.policy
}

// Explain evaluates one indicator without any side effect (no apply, no
// publish, no audit) and returns a full explanation. It is the read-only path
// behind the ExplainDecision admin RPC.
func (c *Coordinator) Explain(indicator string) (audit.Explanation, error) {
	c.mu.Lock()
	p, protected := c.policy, c.protected
	c.mu.Unlock()

	if p == nil {
		return audit.Explanation{Indicator: indicator, Decision: policy.OutcomeNoRecord, Reason: "no active policy"}, nil
	}
	// Surface the live rollback token if this indicator is currently enforced,
	// looked up from the enforcer's actual active rules (authoritative) rather
	// than any cached view.
	token := c.activeTokenFor(indicator)

	in, ok := c.buildInput(indicator, p, protected)
	if !ok {
		return audit.Explanation{Indicator: indicator, Decision: policy.OutcomeNoRecord, Reason: "no present threat record for this indicator"}, nil
	}
	in.NodeMode = c.mode(p.AdapterName())
	d := policy.Evaluate(p, in.EvalInput)
	return audit.FromDecision(d, token, ""), nil
}

// EvaluateAndEnforce evaluates one indicator and, when the outcome is enforced
// and not already applied, mints a decision, applies it through the enforcement
// client, records an audit entry, and publishes the decision op. It returns the
// decision and the rollback token (empty if nothing was applied). It is
// idempotent per indicator under a fixed policy version.
func (c *Coordinator) EvaluateAndEnforce(indicator string) (policy.Decision, string, error) {
	c.mu.Lock()
	p, protected := c.policy, c.protected
	c.mu.Unlock()
	if p == nil {
		return policy.Decision{Indicator: indicator, Outcome: policy.OutcomeNoRecord, Reason: "no active policy"}, "", nil
	}

	in, ok := c.buildInput(indicator, p, protected)
	if !ok {
		return policy.Decision{Indicator: indicator, Outcome: policy.OutcomeNoRecord}, "", nil
	}
	in.NodeMode = c.mode(p.AdapterName())
	d := policy.Evaluate(p, in.EvalInput)

	if d.Outcome != policy.OutcomeEnforced {
		c.log.Debug().Str("indicator", indicator).Str("outcome", d.Outcome).Msg("coordinator: not enforcing")
		return d, "", nil
	}

	// Dedup against the enforcer's ACTUAL active rules (the authoritative
	// source), not a cached map: if a live rule already covers this indicator we
	// do not mint a second decision. This is crash-safe by construction (a
	// restart re-reads live state) and self-healing (once a rule kernel-expires
	// while the threat persists, the next pass re-enforces it).
	if tok := c.activeTokenFor(indicator); tok != "" {
		return d, tok, nil
	}

	token, err := c.applyDecision(indicator, in, d)
	return d, token, err
}

// applyDecision mints and applies a decision, then (only if a rule was actually
// installed) audits and publishes it. When the client reports applied=false —
// the adapter is in observe mode, the action produces no rule, or the enforcer
// shed it under the new-rule rate cap — no audit/publish/mesh side effect
// occurs and an empty token is returned. This keeps the mesh's immutable
// decision log honest: it records rules that exist, not ones that were withheld.
func (c *Coordinator) applyDecision(indicator string, in evalInput, d policy.Decision) (string, error) {
	token := newID("rbk_")
	decID := newID("dec_")
	createdAt := c.clock().UTC().Format(time.RFC3339)
	dec := d.ToProto(decID, in.ThreatID, indicator, createdAt)
	dec.RollbackToken = token
	dec.Owner = "frien-enforcer"

	applied, err := c.client.Apply(dec)
	if err != nil {
		c.log.Error().Err(err).Str("indicator", indicator).Msg("coordinator: enforcement apply failed")
		return "", fmt.Errorf("applying enforcement: %w", err)
	}
	if !applied {
		// Computed but not installed (observe mode / no-rule action / rate cap).
		c.log.Info().Str("indicator", indicator).Str("outcome", d.Outcome).
			Msg("coordinator: decision computed but not applied by enforcer")
		return "", nil
	}
	dec.Applied = true

	auditID := ""
	if c.auditLog != nil {
		entry, aerr := c.auditLog.Append(audit.Entry{
			Actor:    c.nodeID,
			Action:   audit.ActionDecision,
			Adapter:  d.Adapter,
			Target:   indicator,
			Outcome:  d.Outcome,
			PolicyID: d.PolicyID,
			Reason:   d.Reason,
			Details: map[string]string{
				"decision_id":    decID,
				"rollback_token": token,
				"matched_weight": fmt.Sprintf("%g", d.MatchedWeight),
			},
		})
		if aerr == nil {
			auditID = entry.ID
		}
	}

	// Publish the immutable decision back into the mesh at the indicator's scope.
	if _, perr := c.publisher.Publish(crdt.OpEnforcementDecision, dec, in.Scope); perr != nil {
		c.log.Warn().Err(perr).Str("indicator", indicator).Msg("coordinator: publishing decision op")
	}

	c.log.Info().
		Str("indicator", indicator).
		Str("decision", decID).
		Str("token", token).
		Str("audit", auditID).
		Msg("coordinator: enforcement decision applied")
	return token, nil
}

// Sweep evaluates and (where warranted) enforces every present indicator. It
// snapshots the enforcer's active rules ONCE up front and skips indicators
// already covered, so a sweep is O(threats + rules) with a single List call
// regardless of fleet size, and repeated sweeps never re-apply a live rule.
func (c *Coordinator) Sweep() {
	c.mu.Lock()
	p, protected := c.policy, c.protected
	c.mu.Unlock()
	if p == nil {
		return
	}

	active := c.activeTargetSet()
	now := c.clock()
	seen := make(map[string]struct{})
	for _, env := range c.state.PresentThreatOps(now) {
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) != nil {
			continue
		}
		ind := tr.GetIndicator()
		if ind == "" {
			continue
		}
		if _, dup := seen[ind]; dup {
			continue
		}
		seen[ind] = struct{}{}
		if _, covered := active[ind]; covered {
			continue // a live rule already covers this indicator
		}

		in, ok := c.buildInput(ind, p, protected)
		if !ok {
			continue
		}
		in.NodeMode = c.mode(p.AdapterName())
		d := policy.Evaluate(p, in.EvalInput)
		if d.Outcome != policy.OutcomeEnforced {
			continue
		}
		if _, err := c.applyDecision(ind, in, d); err != nil {
			c.log.Warn().Err(err).Str("indicator", ind).Msg("coordinator: sweep enforce error")
		}
	}
}

// activeTargetSet returns the set of indicators the enforcer currently has a
// live rule for. A List error yields an empty set, which fails safe toward
// re-evaluation rather than assuming coverage.
func (c *Coordinator) activeTargetSet() map[string]struct{} {
	set := make(map[string]struct{})
	rules, err := c.client.List()
	if err != nil {
		c.log.Warn().Err(err).Msg("coordinator: listing active rules for dedup")
		return set
	}
	for _, r := range rules {
		set[r.Target] = struct{}{}
	}
	return set
}

// activeTokenFor returns the rollback token of the live rule covering indicator,
// or "" if none. Used by Explain and single-indicator dedup.
func (c *Coordinator) activeTokenFor(indicator string) string {
	rules, err := c.client.List()
	if err != nil {
		return ""
	}
	for _, r := range rules {
		if r.Target == indicator {
			return r.Token
		}
	}
	return ""
}

// evalInput is EvalInput plus the threat id carried through for the decision op.
type evalInput struct {
	policy.EvalInput
	ThreatID string
}

// buildInput gathers all present contributions for an indicator into an
// EvalInput. It returns ok=false when no present threat names the indicator.
func (c *Coordinator) buildInput(indicator string, p *policy.Policy, protected *policy.ProtectedSet) (evalInput, bool) {
	now := c.clock()
	var (
		contribs []policy.Contribution
		widest   = "local"
		indType  string
		threatID string
		maxTTL   time.Duration
		anyMatch bool
	)
	for _, env := range c.state.PresentThreatOps(now) {
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) != nil {
			continue
		}
		if tr.GetIndicator() != indicator {
			continue
		}
		anyMatch = true
		if indType == "" {
			indType = tr.GetIndicatorType()
		}
		if threatID == "" {
			threatID = tr.GetId()
		}
		widest = widerScope(widest, tr.GetScope())
		if ttl := recordTTL(&tr, now); ttl > maxTTL {
			maxTTL = ttl
		}
		fp := env.GetKeyId()
		contribs = append(contribs, policy.Contribution{
			OpID:        env.GetOpId(),
			OriginNode:  env.GetNodeId(),
			Fingerprint: fp,
			TrustTier:   c.trust.TrustTier(env.GetNodeId(), fp),
			Confidence:  tr.GetConfidence(),
			ReceivedAt:  c.state.ReceivedAt(env.GetOpId()),
			Revoked:     c.trust.Excluded(env.GetNodeId(), fp),
		})
	}
	if !anyMatch {
		return evalInput{}, false
	}
	return evalInput{
		EvalInput: policy.EvalInput{
			Indicator:     indicator,
			IndicatorType: indType,
			Scope:         widest,
			Contributions: contribs,
			Partition:     c.partition.Partition(),
			Protected:     protected,
			RecordTTL:     maxTTL,
			Now:           now,
		},
		ThreatID: threatID,
	}, true
}

func (c *Coordinator) mode(adapter string) string {
	m, err := c.client.GetMode(adapter)
	if err != nil || m == "" {
		return policy.ModeObserve // fail safe
	}
	return m
}

// widerScope returns the broader of two scopes (fleet > zone > local). When a
// mix of scopes report the same indicator, evaluating at the widest is the
// conservative choice: it subjects the decision to fleet partition safety.
func widerScope(a, b string) string {
	if scopeRank(b) > scopeRank(a) {
		return b
	}
	return a
}

func scopeRank(s string) int {
	switch {
	case s == "fleet":
		return 2
	case len(s) >= 5 && s[:5] == "zone:":
		return 1
	default:
		return 0
	}
}

// recordTTL derives a record's remaining lifetime: its declared TTL, else the
// interval until its expires_at, else 0.
func recordTTL(tr *frienv1.ThreatRecord, now time.Time) time.Duration {
	if s := tr.GetTtl(); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	if s := tr.GetExpiresAt(); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Sub(now)
		}
	}
	return 0
}

// newID returns a random, prefixed identifier. Used for decision ids and
// rollback tokens, which need uniqueness but not lexical ordering.
func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
