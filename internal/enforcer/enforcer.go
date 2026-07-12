package enforcer

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Enforcement modes, mirroring policy.Mode* and the proto vocabulary.
const (
	ModeObserve = "observe"
	ModeEnforce = "enforce"
)

// Rollback outcome codes, matching RollbackEnforcementResponse.status.
const (
	RollbackRemoved  = "removed"
	RollbackExpired  = "already_expired"
	RollbackNotFound = "not_found"
)

// Enforcer is the per-node enforcement manager. It owns the set of adapters,
// the per-adapter observe/enforce mode, and the durable rollback store. The
// daemon hands it decisions that already cleared policy; it installs the ones
// that should be applied, records every applied rule durably, and can flush
// everything for the dead-man's switch or breakglass.
type Enforcer struct {
	log      zerolog.Logger
	rollback *RollbackStore
	now      func() time.Time

	mu       sync.RWMutex
	adapters map[string]Adapter
	modes    map[string]string // adapter -> observe|enforce
}

// New builds an Enforcer. rollback may be nil (rules are still applied, just not
// durably tracked — used in tests that don't exercise reconciliation). now may
// be nil (time.Now).
func New(rollback *RollbackStore, now func() time.Time, log zerolog.Logger) *Enforcer {
	if now == nil {
		now = time.Now
	}
	return &Enforcer{
		log:      log,
		rollback: rollback,
		now:      now,
		adapters: make(map[string]Adapter),
		modes:    make(map[string]string),
	}
}

// Register adds an adapter under its Name(), defaulting it to observe mode. An
// adapter must be registered before decisions targeting it can be applied.
func (e *Enforcer) Register(a Adapter, initialMode string) {
	if initialMode != ModeEnforce {
		initialMode = ModeObserve
	}
	e.mu.Lock()
	e.adapters[a.Name()] = a
	e.modes[a.Name()] = initialMode
	e.mu.Unlock()
}

// Mode returns the current mode for an adapter (observe if unknown, the
// fail-safe default).
func (e *Enforcer) Mode(adapter string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if m, ok := e.modes[adapter]; ok {
		return m
	}
	return ModeObserve
}

// SetMode transitions an adapter's mode and returns the previous mode. It does
// NOT retroactively apply pending observe decisions, nor flush existing rules
// on demotion — those are separate operator actions (see docs/ENFORCEMENT_SAFETY).
func (e *Enforcer) SetMode(adapter, mode string) (prev string, err error) {
	if mode != ModeObserve && mode != ModeEnforce {
		return "", fmt.Errorf("enforcer: invalid mode %q", mode)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.adapters[adapter]; !ok {
		return "", fmt.Errorf("enforcer: unknown adapter %q", adapter)
	}
	prev = e.modes[adapter]
	e.modes[adapter] = mode
	return prev, nil
}

// Apply installs the rule described by an enforcement decision, provided the
// decision's adapter is in enforce mode. It returns applied=false (no error)
// when the adapter is in observe mode: the decision is real and explainable but
// no rule is written. A decision whose action does not produce a rule ("alert",
// "allow") is likewise not installed here.
//
// Every actually-installed rule is recorded in the durable rollback store
// BEFORE returning, so a crash immediately after Apply still leaves a
// reconcilable record.
func (e *Enforcer) Apply(d *frienv1.EnforcementDecision) (applied bool, err error) {
	if d == nil {
		return false, fmt.Errorf("enforcer: nil decision")
	}
	adapterName := d.GetAdapter()

	e.mu.RLock()
	a, ok := e.adapters[adapterName]
	mode := e.modes[adapterName]
	e.mu.RUnlock()
	if !ok {
		return false, fmt.Errorf("enforcer: no adapter registered for %q", adapterName)
	}
	if mode != ModeEnforce {
		return false, nil // observe: decision computed, no rule applied
	}
	if !producesRule(d.GetAction()) {
		return false, nil
	}

	timeout, err := ruleTimeout(d)
	if err != nil {
		return false, err
	}
	if timeout <= 0 {
		// A guard in policy.Evaluate should already prevent this, but the
		// enforcer independently refuses to install a rule with no kernel
		// timeout: that is exactly the permanent-leak this whole package exists
		// to prevent.
		return false, fmt.Errorf("enforcer: refusing to apply %s with no kernel timeout", d.GetId())
	}

	token := d.GetRollbackToken()
	if token == "" {
		return false, fmt.Errorf("enforcer: decision %s has no rollback_token", d.GetId())
	}

	now := e.now()
	rec := RollbackToken{
		Token:      token,
		DecisionID: d.GetId(),
		Adapter:    adapterName,
		Target:     d.GetTarget(),
		Action:     d.GetAction(),
		AppliedAt:  now,
		ExpiresAt:  now.Add(timeout),
		Applied:    true,
	}
	// Persist the intent-to-apply first so a crash between the record and the
	// kernel write is reconcilable (reconcile will find no live rule and close
	// the token out) rather than an untracked live rule.
	if e.rollback != nil {
		if err := e.rollback.Put(rec); err != nil {
			return false, fmt.Errorf("enforcer: persisting rollback token: %w", err)
		}
	}

	if err := a.Apply(Rule{Token: token, Target: d.GetTarget(), Action: d.GetAction(), Timeout: timeout}); err != nil {
		return false, fmt.Errorf("enforcer: applying rule on %s: %w", adapterName, err)
	}

	e.log.Info().
		Str("decision", d.GetId()).
		Str("adapter", adapterName).
		Str("target", d.GetTarget()).
		Str("action", d.GetAction()).
		Dur("kernel_timeout", timeout).
		Str("token", token).
		Msg("enforcement rule applied")
	return true, nil
}

// Rollback removes an applied rule by token and marks it rolled back. It is
// fail-open: a token whose rule the kernel already expired reports
// already_expired rather than an error.
func (e *Enforcer) Rollback(token string) (status string, err error) {
	if e.rollback == nil {
		return "", fmt.Errorf("enforcer: no rollback store")
	}
	rec, ok, err := e.rollback.Get(token)
	if err != nil {
		return "", err
	}
	if !ok {
		return RollbackNotFound, nil
	}

	e.mu.RLock()
	a := e.adapters[rec.Adapter]
	e.mu.RUnlock()

	status = RollbackRemoved
	if a != nil {
		active, _ := a.List()
		present := false
		for _, r := range active {
			if r.Token == token {
				present = true
				break
			}
		}
		if !present {
			status = RollbackExpired
		} else if err := a.Remove(token); err != nil {
			return "", fmt.Errorf("enforcer: removing rule: %w", err)
		}
	}
	if err := e.rollback.MarkRolledBack(token); err != nil {
		return "", err
	}
	e.log.Info().Str("token", token).Str("status", status).Msg("enforcement rolled back")
	return status, nil
}

// FlushAll removes every frien-managed rule from every adapter and marks their
// tokens rolled back. It backs both the dead-man's switch and breakglass, and
// returns the total number of rules removed. Errors from individual adapters
// are logged but never abort the flush — cleanup fails open.
func (e *Enforcer) FlushAll(reason string) int {
	e.mu.RLock()
	adapters := make([]Adapter, 0, len(e.adapters))
	for _, a := range e.adapters {
		adapters = append(adapters, a)
	}
	e.mu.RUnlock()

	total := 0
	for _, a := range adapters {
		active, _ := a.List()
		n, err := a.FlushAll()
		if err != nil {
			e.log.Error().Err(err).Str("adapter", a.Name()).Msg("flush: adapter error (continuing)")
		}
		total += n
		if e.rollback != nil {
			for _, r := range active {
				_ = e.rollback.MarkRolledBack(r.Token)
			}
		}
	}
	e.log.Warn().Str("reason", reason).Int("rules_removed", total).Msg("flushed all frien-managed rules")
	return total
}

// ForceObserve sets every registered adapter back to observe mode. Used by
// breakglass alongside FlushAll.
func (e *Enforcer) ForceObserve() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for name := range e.modes {
		e.modes[name] = ModeObserve
	}
}

// Reconcile runs on daemon restart. For every token that was applied and not
// rolled back, it checks whether the kernel rule is still present: if the
// adapter no longer has it (a kernel timeout fired while frien was down), the
// token is closed out; if it is still present but past its recorded expiry, it
// is removed. This guarantees no partial-enforcement state survives a crash
// silently. It returns how many tokens it closed out.
func (e *Enforcer) Reconcile() (int, error) {
	if e.rollback == nil {
		return 0, nil
	}
	outstanding, err := e.rollback.Outstanding()
	if err != nil {
		return 0, err
	}
	now := e.now()
	closed := 0
	for _, t := range outstanding {
		e.mu.RLock()
		a := e.adapters[t.Adapter]
		e.mu.RUnlock()

		if a == nil {
			// No adapter for this token's backend this run; leave the record so
			// a future run with the adapter registered can reconcile it.
			continue
		}
		active, _ := a.List()
		present := false
		for _, r := range active {
			if r.Token == t.Token {
				present = true
				break
			}
		}
		switch {
		case !present:
			// Kernel already reaped it while we were down — close the token.
			_ = e.rollback.MarkRolledBack(t.Token)
			closed++
			e.log.Info().Str("token", t.Token).Msg("reconcile: rule already expired in kernel; token closed")
		case !now.Before(t.ExpiresAt):
			// Present but past its recorded expiry — remove and close.
			_ = a.Remove(t.Token)
			_ = e.rollback.MarkRolledBack(t.Token)
			closed++
			e.log.Warn().Str("token", t.Token).Msg("reconcile: rule past expiry still present; removed")
		default:
			e.log.Info().Str("token", t.Token).Time("expires_at", t.ExpiresAt).
				Msg("reconcile: rule still valid; left to its kernel timeout")
		}
	}
	return closed, nil
}

// producesRule reports whether an action installs a firewall rule. "alert" and
// "allow" do not.
func producesRule(action string) bool {
	return action == "block" || action == "rate_limit"
}

// ruleTimeout parses a decision's kernel_timeout, falling back to the interval
// until expires_at when kernel_timeout is absent.
func ruleTimeout(d *frienv1.EnforcementDecision) (time.Duration, error) {
	if s := d.GetKernelTimeout(); s != "" {
		dur, err := time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("enforcer: invalid kernel_timeout %q: %w", s, err)
		}
		return dur, nil
	}
	if s := d.GetExpiresAt(); s != "" {
		exp, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return 0, fmt.Errorf("enforcer: invalid expires_at %q: %w", s, err)
		}
		return time.Until(exp), nil
	}
	return 0, nil
}
