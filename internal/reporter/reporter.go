// Package reporter is the local threat-ingestion path: it takes a detector (or
// operator) observation, runs it through admission control (coalesce → shed →
// budget), and — only if admitted — stamps a ThreatRecord and publishes it as a
// signed op into the mesh. It is the single choke point between "something was
// observed" and "a threat exists in replicated state", so both the ReportThreat
// admin RPC and every detector go through it and inherit the same storm
// protection.
package reporter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/admission"
	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/scope"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Publisher publishes a signed op into the mesh. gossip.Engine satisfies it.
type Publisher interface {
	Publish(opType string, payload proto.Message, scopeKey string) (*frienv1.OperationEnvelope, error)
}

// Params is one normalized observation to report.
type Params struct {
	Indicator     string
	IndicatorType string // "ip" | "cidr" | "hostname" | "user" | "hash"
	Reason        string
	Severity      string // "low" | "medium" | "high" | "critical"
	Confidence    float64
	TTL           string // duration string, e.g. "1h"
	Scope         string // "local" | "zone:<name>" | "fleet"
	Detector      string // detector name (or "operator" for a manual report)
	EvidenceJSON  []byte // optional; max 65536 bytes
}

// Result reports the outcome of a report.
type Result struct {
	OpID     string
	ThreatID string
	Status   string // "accepted" | "coalesced" | "shed"
}

const (
	StatusAccepted  = "accepted"
	StatusCoalesced = "coalesced"
	StatusShed      = "shed"
)

const maxEvidenceBytes = 65536

// Reporter turns observations into admitted, published threat records.
type Reporter struct {
	ctrl   *admission.Controller
	pub    Publisher
	nodeID string
	now    func() time.Time
}

// New builds a Reporter. now may be nil (time.Now).
func New(ctrl *admission.Controller, pub Publisher, nodeID string, now func() time.Time) *Reporter {
	if now == nil {
		now = time.Now
	}
	return &Reporter{ctrl: ctrl, pub: pub, nodeID: nodeID, now: now}
}

var (
	validSeverity      = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	validIndicatorType = map[string]bool{"ip": true, "cidr": true, "hostname": true, "user": true, "hash": true}
)

// Report validates, admits, and (if admitted) publishes one observation.
func (r *Reporter) Report(p Params) (Result, error) {
	if err := r.validate(p); err != nil {
		return Result{}, err
	}
	now := r.now()

	sig := admission.Signal{
		Detector:   orDefault(p.Detector, "operator"),
		Key:        p.Detector + "|" + p.Indicator + "|" + p.IndicatorType,
		Severity:   p.Severity,
		Confidence: p.Confidence,
	}
	decision, count := admission.Decision(admission.Admit), uint32(1)
	if r.ctrl != nil {
		decision, count = r.ctrl.Admit(sig)
	}

	switch decision {
	case admission.Coalesced:
		// Folded into an existing record; no new op is published.
		return Result{Status: StatusCoalesced}, nil
	case admission.DroppedShed, admission.DroppedBudget:
		return Result{Status: StatusShed}, nil
	}

	ttl := parseTTL(p.TTL)
	tr := &frienv1.ThreatRecord{
		IndicatorType:  p.IndicatorType,
		Id:             newID("threat_"),
		Indicator:      p.Indicator,
		Reason:         p.Reason,
		Severity:       p.Severity,
		Confidence:     p.Confidence,
		Ttl:            p.TTL,
		Scope:          p.Scope,
		Detector:       sig.Detector,
		EvidenceJson:   p.EvidenceJSON,
		CoalescedCount: count,
		ReportedBy:     r.nodeID,
		CreatedAt:      now.UTC().Format(time.RFC3339),
		ExpiresAt:      now.Add(ttl).UTC().Format(time.RFC3339),
	}

	env, err := r.pub.Publish(crdt.OpThreatRecord, tr, p.Scope)
	if err != nil {
		return Result{}, fmt.Errorf("reporter: publishing threat: %w", err)
	}
	return Result{OpID: env.GetOpId(), ThreatID: tr.GetId(), Status: StatusAccepted}, nil
}

func (r *Reporter) validate(p Params) error {
	if p.Indicator == "" || len(p.Indicator) > 512 {
		return fmt.Errorf("reporter: indicator required, max 512 bytes")
	}
	if !validIndicatorType[p.IndicatorType] {
		return fmt.Errorf("reporter: invalid indicator_type %q", p.IndicatorType)
	}
	if !validSeverity[p.Severity] {
		return fmt.Errorf("reporter: invalid severity %q", p.Severity)
	}
	if p.Confidence < 0 || p.Confidence > 1 {
		return fmt.Errorf("reporter: confidence must be 0.0-1.0, got %v", p.Confidence)
	}
	if p.TTL != "" {
		if _, err := time.ParseDuration(p.TTL); err != nil {
			return fmt.Errorf("reporter: invalid ttl %q: %w", p.TTL, err)
		}
	}
	if _, err := scope.Parse(p.Scope); err != nil {
		return fmt.Errorf("reporter: invalid scope %q: %w", p.Scope, err)
	}
	if len(p.EvidenceJSON) > maxEvidenceBytes {
		return fmt.Errorf("reporter: evidence too large (%d > %d bytes)", len(p.EvidenceJSON), maxEvidenceBytes)
	}
	// An ip/cidr indicator must actually parse, so a malformed target never
	// becomes a threat that a downstream enforcer would choke on.
	switch p.IndicatorType {
	case "ip":
		if net.ParseIP(p.Indicator) == nil {
			return fmt.Errorf("reporter: indicator %q is not a valid IP", p.Indicator)
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(p.Indicator); err != nil {
			return fmt.Errorf("reporter: indicator %q is not a valid CIDR", p.Indicator)
		}
	}
	return nil
}

func parseTTL(s string) time.Duration {
	if s == "" {
		return time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
