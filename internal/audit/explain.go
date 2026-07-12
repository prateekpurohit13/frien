package audit

import (
	"time"

	"github.com/prateekpurohit13/frien/internal/policy"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Explanation answers, for one indicator, the five questions every frien action
// must be able to answer: who reported it (contributing identities), what
// policy approved it, what quorum was met, what would/did change, and where the
// audit trail is. It is a plain projection of a policy.Decision plus the
// enforcement/audit context the daemon has on hand, kept here so both the
// ExplainDecision RPC and the CLI render from one shape.
type Explanation struct {
	Indicator      string
	Decision       string // enforced | observe_only | denied_by_policy | no_record
	Reason         string
	Identities     []string
	MatchedWeight  float64
	RequiredWeight float64
	PolicyID       string
	PolicyVersion  int64
	Adapter        string
	ExpiresAt      time.Time
	RollbackToken  string
	AuditEntryID   string
}

// FromDecision assembles an Explanation from a policy decision and the extra
// context the daemon holds (the rollback token minted for an applied decision,
// and the audit entry recording it). rollbackToken and auditEntryID may be
// empty for observe/denied/no-record outcomes that produced neither.
func FromDecision(d policy.Decision, rollbackToken, auditEntryID string) Explanation {
	return Explanation{
		Indicator:      d.Indicator,
		Decision:       d.Outcome,
		Reason:         d.Reason,
		Identities:     append([]string(nil), d.Identities...),
		MatchedWeight:  d.MatchedWeight,
		RequiredWeight: d.RequiredWeight,
		PolicyID:       d.PolicyID,
		PolicyVersion:  d.PolicyVersion,
		Adapter:        d.Adapter,
		ExpiresAt:      d.ExpiresAt,
		RollbackToken:  rollbackToken,
		AuditEntryID:   auditEntryID,
	}
}

// ToProto renders the ExplainDecision admin response.
func (e Explanation) ToProto() *frienv1.ExplainDecisionResponse {
	resp := &frienv1.ExplainDecisionResponse{
		Indicator:              e.Indicator,
		Decision:               e.Decision,
		Reason:                 e.Reason,
		ContributingIdentities: append([]string(nil), e.Identities...),
		MatchedWeight:          e.MatchedWeight,
		RequiredWeight:         e.RequiredWeight,
		PolicyId:               e.PolicyID,
		PolicyVersion:          e.PolicyVersion,
		Adapter:                e.Adapter,
		RollbackToken:          e.RollbackToken,
		AuditEntryId:           e.AuditEntryID,
	}
	if !e.ExpiresAt.IsZero() {
		resp.ExpiresAt = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return resp
}
