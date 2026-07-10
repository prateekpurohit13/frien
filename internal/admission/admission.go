package admission

import (
	"context"
	"time"
)

// stormFillThreshold is the node-budget fill ratio below which the controller
// considers itself under storm and engages priority shedding. It is an internal
// tuning constant, not a wire- or config-level value.
const stormFillThreshold = 0.5

// Signal is the minimal description of a detector observation the admission
// layer needs to decide on. The caller computes Key as the coalescing identity
// (e.g. detector|indicator|indicator_type).
type Signal struct {
	Detector   string
	Key        string
	Severity   string
	Confidence float64
}

// Decision is the outcome of admitting a signal.
type Decision uint8

const (
	Admit         Decision = iota // create or update an operation
	Coalesced                     // folded into an existing record; no new operation
	DroppedShed                   // shed under storm due to low priority
	DroppedBudget                 // rate budget exhausted
)

func (d Decision) String() string {
	switch d {
	case Admit:
		return "admit"
	case Coalesced:
		return "coalesced"
	case DroppedShed:
		return "dropped_shed"
	case DroppedBudget:
		return "dropped_budget"
	default:
		return "unknown"
	}
}

// Config bundles the admission settings.
type Config struct {
	Budget            BudgetConfig
	CoalesceWindow    time.Duration
	ShedMinConfidence float64
}

// Controller composes the storm-protection primitives into one decision: it
// coalesces duplicates, sheds low-priority signals under storm, and enforces the
// rate budget. The decision order matters — duplicates are folded before they
// can consume budget, and shedding runs before the budget check so low-priority
// signals do not spend tokens that a high-priority signal will need.
type Controller struct {
	coalescer *Coalescer
	shedder   *Shedder
	budget    *Budget
}

func New(cfg Config, now func() time.Time) *Controller {
	return &Controller{
		coalescer: NewCoalescer(cfg.CoalesceWindow, now),
		shedder:   NewShedder(cfg.ShedMinConfidence),
		budget:    NewBudget(cfg.Budget, now),
	}
}

// Admit decides the fate of one signal and returns the running coalesced count
// for its key. A Coalesced decision means the signal was folded into an existing
// record whose count is now `count`; an Admit means a new record should be
// created (also with the returned count, which is 1 for a fresh group).
func (c *Controller) Admit(sig Signal) (decision Decision, count uint32) {
	count, newGroup := c.coalescer.Observe(sig.Key)
	if !newGroup {
		return Coalesced, count
	}
	underStorm := c.budget.NodeFillRatio() < stormFillThreshold
	if !c.shedder.Keep(sig.Severity, sig.Confidence, underStorm) {
		return DroppedShed, count
	}
	if !c.budget.Allow(sig.Detector) {
		return DroppedBudget, count
	}
	return Admit, count
}

// Expire reclaims memory held by elapsed coalescing groups.
func (c *Controller) Expire() int { return c.coalescer.Expire() }

// Run reclaims elapsed coalescing groups on an interval until ctx is cancelled,
// so the controller bounds its own memory rather than relying on the caller to
// drive Expire. A zero interval defaults to the coalesce window.
func (c *Controller) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = c.coalescer.window
	}
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Expire()
		}
	}
}
