package crdt

import (
	"google.golang.org/protobuf/proto"

	"github.com/prateekpurohit13/frien/internal/scope"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// AcceptFunc is the ingress scope gate: it reports whether an op pulled from a
// peer may enter local state. The daemon backs this with scope.Router.Accept.
type AcceptFunc func(env *frienv1.OperationEnvelope) bool

// EnvelopeScope returns the scope used for ingress acceptance. Threat records
// carry their scope; retractions ride the fleet (an author withdrawal is a
// harmless no-op on a node that never held the target); other ops are fleet.
func EnvelopeScope(env *frienv1.OperationEnvelope) scope.Scope {
	if env.GetOpType() == OpThreatRecord {
		var tr frienv1.ThreatRecord
		if proto.Unmarshal(env.GetPayload(), &tr) == nil {
			if sc, err := scope.Parse(tr.GetScope()); err == nil {
				return sc
			}
		}
	}
	return scope.Scope{Kind: scope.Fleet}
}

// MissingFrom returns the op_ids that src holds in scopeKey and dst does not.
// (Phase 4 will bound this below the latest common checkpoint; until checkpoints
// exist the whole scope is reconciled, and TTL expiry plus the absence of
// pruning mean there is nothing to resurrect.)
func MissingFrom(dst, src *OpSet, scopeKey string) []string {
	var out []string
	for _, id := range src.OpIDsInScope(scopeKey) {
		if !dst.Has(id) {
			out = append(out, id)
		}
	}
	return out
}

// Reconcile pulls every op that src holds in scopeKey and dst lacks (and that
// passes accept) into dst, returning the count pulled and any equivocation
// proofs surfaced. It is one direction of anti-entropy; the caller runs it both
// ways for full convergence.
func Reconcile(dst, src *OpSet, scopeKey string, accept AcceptFunc) (int, []*frienv1.MisbehaviorProof) {
	pulled := 0
	var proofs []*frienv1.MisbehaviorProof
	for _, id := range MissingFrom(dst, src, scopeKey) {
		env, ok := src.Get(id)
		if !ok {
			continue
		}
		if accept != nil && !accept(env) {
			continue
		}
		res, err := dst.Add(env)
		if err != nil {
			continue
		}
		if res.Added {
			pulled++
		}
		if res.Equivocation != nil {
			proofs = append(proofs, res.Equivocation)
		}
	}
	return pulled, proofs
}

// SyncScope reconciles one scope only when the per-scope roots differ, so an
// already-converged scope costs a single hash comparison and no op-id exchange.
func SyncScope(dst, src *OpSet, scopeKey string, accept AcceptFunc) (int, []*frienv1.MisbehaviorProof) {
	if dst.ScopeDigest(scopeKey).Root == src.ScopeDigest(scopeKey).Root {
		return 0, nil
	}
	return Reconcile(dst, src, scopeKey, accept)
}
