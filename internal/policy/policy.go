// Package policy is the trust-and-policy decision core of frien's enforcement
// path. It is deliberately pure: given a set of distinct-identity threat
// contributions for one indicator, an operator-signed Policy, the node's
// enforce-mode, its partition view, and the protected-target set, Evaluate
// returns a Decision (and a full explanation) without performing any I/O or
// touching any firewall. The daemon (Phase 5d) collects the inputs from the
// op set, membership roster, and receive-time index and hands them here; the
// enforcer (internal/enforcer) acts on the Decision.
//
// The two safety properties this package owns:
//
//   - Provenance is not truth. A verified signature only proves who authored a
//     report. Whether that report may trigger action is a policy decision made
//     here: min confidence, weighted quorum of distinct non-revoked identities
//     within a local-receive-time window, protected targets, and partition
//     safety must all pass before a decision is "enforced".
//   - Fail-safe under partition. A node that cannot observe a majority of the
//     known distinct identities must not take fleet-scoped enforcement; it
//     falls back to observe/intelligence-only. Consistency of the enforcement
//     decision is favored over availability of enforcement (an explicit CAP
//     choice, see docs/FRIEN_ARCHITECTURE.md §8.1).
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Enforcement modes and decision outcomes, matching the proto/CLI vocabulary.
const (
	ModeObserve = "observe"
	ModeEnforce = "enforce"

	OutcomeEnforced         = "enforced"
	OutcomeObserveOnly      = "observe_only"
	OutcomeDeniedByPolicy   = "denied_by_policy"
	OutcomeNoRecord         = "no_record"
	OutcomeWouldEnforce     = "would_enforce" // dry-run / TestPolicy variant of OutcomeEnforced
	OutcomeDeniedTestPolicy = "denied"        // TestPolicy variant of OutcomeDeniedByPolicy
)

// DefaultTrustWeights are the conservative per-tier weights used when a policy
// does not override them. "one trusted sensor equals three standard edges."
var DefaultTrustWeights = map[string]float64{
	"standard": 1.0,
	"trusted":  3.0,
	"high":     5.0,
}

// DefaultAdapter is used when a policy does not name one.
const DefaultAdapter = "nftables"

// Policy is an operator-signed, versioned control-plane object. A node accepts
// a policy only if SignedBy=="operator" and Signature verifies against the
// pinned operator public key over CanonicalBytes() — never because a peer sent
// it. The YAML shape matches docs/FRIEN_ARCHITECTURE.md §Layer 5.
type Policy struct {
	ID                          string   `yaml:"id"`
	Version                     int64    `yaml:"version"`
	Action                      string   `yaml:"action"`       // "block" | "allow" | "rate_limit" | "alert"
	Adapter                     string   `yaml:"adapter"`      // enforcement adapter; default nftables
	DefaultMode                 string   `yaml:"default_mode"` // "observe" | "enforce"
	MinConfidence               float64  `yaml:"min_confidence"`
	RequireWeight               float64  `yaml:"require_weight"`
	QuorumWindow                string   `yaml:"quorum_window"` // duration string, local receive time
	MaxTTL                      string   `yaml:"max_ttl"`       // duration string; caps record TTL
	KernelTimeoutRequired       bool     `yaml:"kernel_timeout_required"`
	ProtectedCIDRs              []string `yaml:"protected_cidrs"`
	ProtectSelfPlanes           bool     `yaml:"protect_self_planes"`
	DenyIfTargetIsAdminEndpoint bool     `yaml:"deny_if_target_is_admin_endpoint"`
	RollbackOnError             bool     `yaml:"rollback_on_error"`

	// TrustWeights overrides DefaultTrustWeights per tier when non-empty.
	TrustWeights map[string]float64 `yaml:"trust_weights"`

	// Operator signature envelope. SignedBy must be "operator". Signature is
	// base64(ed25519 over CanonicalBytes()). These three fields are themselves
	// excluded from CanonicalBytes so the policy signs its own semantic content
	// and nothing else.
	SignedBy      string `yaml:"signed_by"`
	OperatorKeyID string `yaml:"operator_key_id"`
	Signature     string `yaml:"signature"`
}

// Load reads and parses a policy YAML file. It does NOT verify the signature —
// call Verify separately with the pinned operator key so the caller controls
// what "trusted" means (e.g. a dry-run TestPolicy path may parse without a key).
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: reading %s: %w", path, err)
	}
	return Parse(data)
}

// Parse unmarshals a policy from YAML bytes and validates its structural
// invariants (unsigned checks only; signature verification is separate).
func Parse(data []byte) (*Policy, error) {
	// The example body nests everything under a top-level "policy:" key.
	var wrapper struct {
		Policy *Policy `yaml:"policy"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("policy: parsing yaml: %w", err)
	}
	p := wrapper.Policy
	if p == nil {
		// Allow an un-wrapped document too, for convenience/testing.
		p = &Policy{}
		if err := yaml.Unmarshal(data, p); err != nil {
			return nil, fmt.Errorf("policy: parsing yaml: %w", err)
		}
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Policy) validate() error {
	if p.ID == "" {
		return fmt.Errorf("policy: id is required")
	}
	if p.Version <= 0 {
		return fmt.Errorf("policy: version must be positive, got %d", p.Version)
	}
	validActions := map[string]bool{"block": true, "allow": true, "rate_limit": true, "alert": true}
	if !validActions[p.Action] {
		return fmt.Errorf("policy: action must be block|allow|rate_limit|alert, got %q", p.Action)
	}
	if p.DefaultMode == "" {
		p.DefaultMode = ModeObserve
	} else if p.DefaultMode != ModeObserve && p.DefaultMode != ModeEnforce {
		return fmt.Errorf("policy: default_mode must be observe|enforce, got %q", p.DefaultMode)
	}
	if p.MinConfidence < 0 || p.MinConfidence > 1 {
		return fmt.Errorf("policy: min_confidence must be 0.0-1.0, got %v", p.MinConfidence)
	}
	if p.RequireWeight < 0 {
		return fmt.Errorf("policy: require_weight must be >= 0, got %v", p.RequireWeight)
	}
	if p.QuorumWindow != "" {
		if _, err := time.ParseDuration(p.QuorumWindow); err != nil {
			return fmt.Errorf("policy: invalid quorum_window %q: %w", p.QuorumWindow, err)
		}
	}
	if p.MaxTTL != "" {
		if _, err := time.ParseDuration(p.MaxTTL); err != nil {
			return fmt.Errorf("policy: invalid max_ttl %q: %w", p.MaxTTL, err)
		}
	}
	for tier, w := range p.TrustWeights {
		if w < 0 {
			return fmt.Errorf("policy: trust_weights[%q] must be >= 0, got %v", tier, w)
		}
	}
	return nil
}

// QuorumWindowDuration returns the parsed quorum window, or a conservative
// default of 5m when unset. validate() has already ensured it parses.
func (p *Policy) QuorumWindowDuration() time.Duration {
	if p.QuorumWindow == "" {
		return 5 * time.Minute
	}
	d, _ := time.ParseDuration(p.QuorumWindow)
	return d
}

// MaxTTLDuration returns the parsed max TTL cap, or 0 (no cap) when unset.
func (p *Policy) MaxTTLDuration() time.Duration {
	if p.MaxTTL == "" {
		return 0
	}
	d, _ := time.ParseDuration(p.MaxTTL)
	return d
}

// AdapterName returns the enforcement adapter, defaulting to nftables.
func (p *Policy) AdapterName() string {
	if p.Adapter == "" {
		return DefaultAdapter
	}
	return p.Adapter
}

// WeightFor returns the quorum weight of a trust tier under this policy,
// falling back to DefaultTrustWeights and finally to the "standard" weight for
// an unknown tier (never zero, so a mislabeled-but-valid identity still
// contributes its baseline).
func (p *Policy) WeightFor(tier string) float64 {
	if w, ok := p.TrustWeights[tier]; ok {
		return w
	}
	if w, ok := DefaultTrustWeights[tier]; ok {
		return w
	}
	return DefaultTrustWeights["standard"]
}

// CanonicalBytes produces the deterministic SHA-256 the operator signs. It
// covers every semantic field and deliberately excludes SignedBy,
// OperatorKeyID, and Signature so the policy signs its own content and not its
// own signature. Field order and length-prefixing follow the same discipline
// as identity.CanonicalSignedContent to keep boundaries unambiguous.
func (p *Policy) CanonicalBytes() []byte {
	h := sha256.New()
	writeStr(h, p.ID)
	writeU64(h, uint64(p.Version))
	writeStr(h, p.Action)
	writeStr(h, p.Adapter)
	writeStr(h, p.DefaultMode)
	writeF64(h, p.MinConfidence)
	writeF64(h, p.RequireWeight)
	writeStr(h, p.QuorumWindow)
	writeStr(h, p.MaxTTL)
	writeBool(h, p.KernelTimeoutRequired)
	// protected_cidrs order is significant to the operator; hash as-authored.
	writeU64(h, uint64(len(p.ProtectedCIDRs)))
	for _, c := range p.ProtectedCIDRs {
		writeStr(h, c)
	}
	writeBool(h, p.ProtectSelfPlanes)
	writeBool(h, p.DenyIfTargetIsAdminEndpoint)
	writeBool(h, p.RollbackOnError)
	// trust_weights is a map; sort keys for determinism.
	keys := make([]string, 0, len(p.TrustWeights))
	for k := range p.TrustWeights {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	writeU64(h, uint64(len(keys)))
	for _, k := range keys {
		writeStr(h, k)
		writeF64(h, p.TrustWeights[k])
	}
	return h.Sum(nil)
}

// Verify checks the operator signature against the pinned operator public key.
// A policy that is not signed_by "operator", carries no signature, or fails
// verification is rejected — this is the "accept only if it verifies against a
// pinned operator root" rule. A nil/empty operator key is a hard error: a node
// with no pinned operator key cannot trust any policy.
func (p *Policy) Verify(operatorKey ed25519.PublicKey) error {
	if len(operatorKey) == 0 {
		return fmt.Errorf("policy %s: no operator key pinned; cannot trust policy", p.ID)
	}
	if p.SignedBy != "operator" {
		return fmt.Errorf("policy %s: must be signed_by operator, got %q", p.ID, p.SignedBy)
	}
	if p.Signature == "" {
		return fmt.Errorf("policy %s: missing signature", p.ID)
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return fmt.Errorf("policy %s: signature not valid base64: %w", p.ID, err)
	}
	if !ed25519.Verify(operatorKey, p.CanonicalBytes(), sig) {
		return fmt.Errorf("policy %s: operator signature does not verify", p.ID)
	}
	return nil
}

// SignDetached fills SignedBy/Signature using an external signing function
// (e.g. an identity.Ed25519Signer's Sign method), so operator tooling can sign
// a policy without ever exposing the raw private key bytes to this package.
func (p *Policy) SignDetached(sign func(msg []byte) ([]byte, error), keyID string) error {
	sig, err := sign(p.CanonicalBytes())
	if err != nil {
		return err
	}
	p.SignedBy = "operator"
	p.OperatorKeyID = keyID
	p.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Sign fills SignedBy/Signature by signing CanonicalBytes with the operator
// private key. This runs OFFLINE in operator tooling (frienctl policy sign) —
// a running node never holds the operator private key. keyID is recorded for
// operator bookkeeping only; verification uses the pinned key, not this field.
func (p *Policy) Sign(priv ed25519.PrivateKey, keyID string) {
	p.SignedBy = "operator"
	p.OperatorKeyID = keyID
	p.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, p.CanonicalBytes()))
}

// ── canonical-encoding helpers ──────────────────────────────────────────────

func writeStr(h interface{ Write([]byte) (int, error) }, s string) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	h.Write(l[:])
	h.Write([]byte(s))
}

func writeU64(h interface{ Write([]byte) (int, error) }, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

func writeF64(h interface{ Write([]byte) (int, error) }, v float64) {
	// Encode via a stable string form so 3.0 and 3 hash identically regardless
	// of how YAML parsed them.
	writeStr(h, fmt.Sprintf("%g", v))
}

func writeBool(h interface{ Write([]byte) (int, error) }, v bool) {
	if v {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
}
