package crdt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

func payloadHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func threatEnv(t *testing.T, opID, nodeID string, seq uint64, expires string) *frienv1.OperationEnvelope {
	t.Helper()
	tr := &frienv1.ThreatRecord{Id: opID, Indicator: "203.0.113.44", ExpiresAt: expires}
	payload, err := proto.Marshal(tr)
	if err != nil {
		t.Fatalf("marshal threat: %v", err)
	}
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: OpThreatRecord, NodeId: nodeID, Seq: seq,
		PayloadHash: payloadHash(payload), Payload: payload,
	}
}

func retractionEnv(t *testing.T, opID, nodeID string, seq uint64, target string) *frienv1.OperationEnvelope {
	t.Helper()
	payload, err := proto.Marshal(&frienv1.Retraction{TargetOpId: target})
	if err != nil {
		t.Fatalf("marshal retraction: %v", err)
	}
	return &frienv1.OperationEnvelope{
		OpId: opID, OpType: OpRetraction, NodeId: nodeID, Seq: seq,
		PayloadHash: payloadHash(payload), Payload: payload,
	}
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func TestAddIdempotentOnReplay(t *testing.T) {
	s := NewOpSet()
	env := threatEnv(t, "op1", "node.a", 1, "")

	if res, _ := s.Add(env); !res.Added {
		t.Fatal("first add should register")
	}
	res, _ := s.Add(env)
	if !res.Duplicate || res.Added {
		t.Fatalf("replay should be duplicate no-op, got %+v", res)
	}
	if s.Len() != 1 {
		t.Fatalf("len = %d, want 1 after replay", s.Len())
	}
}

func TestExpiryByExpiresAt(t *testing.T) {
	s := NewOpSet()
	now := time.Unix(1_700_000_000, 0).UTC()

	live := threatEnv(t, "live", "node.a", 1, rfc3339(now.Add(time.Hour)))
	expired := threatEnv(t, "expired", "node.a", 2, rfc3339(now.Add(-time.Hour)))
	noExpiry := threatEnv(t, "forever", "node.a", 3, "")
	for _, e := range []*frienv1.OperationEnvelope{live, expired, noExpiry} {
		if _, err := s.Add(e); err != nil {
			t.Fatalf("add: %v", err)
		}
	}

	if !s.IsPresent("live", now) {
		t.Error("unexpired op should be present")
	}
	if s.IsPresent("expired", now) {
		t.Error("late-delivered expired op must never be present (no resurrection)")
	}
	if !s.IsPresent("forever", now) {
		t.Error("op with no expiry should be present")
	}
	if got := len(s.ActiveThreats(now)); got != 2 {
		t.Fatalf("active threats = %d, want 2", got)
	}
}

func TestRetractionAuthorOnlyAndBySeq(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	future := rfc3339(now.Add(time.Hour))

	t.Run("valid author retraction by higher seq", func(t *testing.T) {
		s := NewOpSet()
		s.Add(threatEnv(t, "t1", "node.a", 1, future))
		s.Add(retractionEnv(t, "r1", "node.a", 2, "t1"))
		if s.IsPresent("t1", now) {
			t.Error("op retracted by its author should not be present")
		}
	})

	t.Run("retraction by a different author is ignored", func(t *testing.T) {
		s := NewOpSet()
		s.Add(threatEnv(t, "t1", "node.a", 1, future))
		s.Add(retractionEnv(t, "r1", "node.b", 2, "t1"))
		if !s.IsPresent("t1", now) {
			t.Error("a non-author retraction must not remove the op")
		}
	})

	t.Run("retraction with lower seq is ignored", func(t *testing.T) {
		s := NewOpSet()
		s.Add(threatEnv(t, "t1", "node.a", 5, future))
		s.Add(retractionEnv(t, "r1", "node.a", 4, "t1"))
		if !s.IsPresent("t1", now) {
			t.Error("retraction must carry a strictly higher seq than its target")
		}
	})
}

func TestEquivocationPreservesEvidence(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "opA", "node.a", 7, ""))

	// Same author reuses seq 7 with a different op — equivocation.
	res, _ := s.Add(threatEnv(t, "opB", "node.a", 7, ""))
	if res.Equivocation == nil {
		t.Fatal("forking (node_id, seq) should produce an equivocation proof")
	}
	if res.Equivocation.GetOpA().GetOpId() != "opA" || res.Equivocation.GetOpB().GetOpId() != "opB" {
		t.Fatalf("proof should carry both envelopes, got %s/%s",
			res.Equivocation.GetOpA().GetOpId(), res.Equivocation.GetOpB().GetOpId())
	}
	// Both ops are retained — the union never discards evidence.
	if !s.Has("opA") || !s.Has("opB") {
		t.Fatal("both conflicting ops must remain in the set")
	}
}

func TestStampAttributionFillsIdAndAttribution(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "opA", "node.a", 7, ""))
	res, _ := s.Add(threatEnv(t, "opB", "node.a", 7, ""))

	before := time.Now()
	StampAttribution(res.Equivocation, "node.detector", before)

	if res.Equivocation.GetId() == "" {
		t.Fatal("StampAttribution should assign a proof id")
	}
	if res.Equivocation.GetDetectedBy() != "node.detector" {
		t.Fatalf("detected_by = %q, want node.detector", res.Equivocation.GetDetectedBy())
	}
	if res.Equivocation.GetDetectedAt() != before.UTC().Format(time.RFC3339) {
		t.Fatalf("detected_at = %q, want %q", res.Equivocation.GetDetectedAt(), before.UTC().Format(time.RFC3339))
	}
}

func TestStampAttributionNilIsNoOp(t *testing.T) {
	StampAttribution(nil, "node.a", time.Now()) // must not panic
}

func TestAddWithLimitCapsScope(t *testing.T) {
	s := NewOpSet()
	for i := 0; i < 3; i++ {
		env := threatEnv(t, fmt.Sprintf("op%d", i), "node.a", uint64(i+1), "")
		if res, err := s.AddWithLimit(env, 3); err != nil || !res.Added {
			t.Fatalf("op %d within cap should be admitted: res=%+v err=%v", i, res, err)
		}
	}
	if _, err := s.AddWithLimit(threatEnv(t, "op3", "node.a", 4, ""), 3); !errors.Is(err, ErrScopeFull) {
		t.Fatalf("over-cap op should return ErrScopeFull, got %v", err)
	}
	// A duplicate of an existing op is never rejected by the cap.
	if res, err := s.AddWithLimit(threatEnv(t, "op0", "node.a", 1, ""), 3); err != nil || !res.Duplicate {
		t.Fatalf("duplicate should stay an admitted no-op at cap: res=%+v err=%v", res, err)
	}
	if s.Len() != 3 {
		t.Fatalf("set should hold exactly the cap of 3, got %d", s.Len())
	}
}

func TestAddWithLimitConcurrentDoesNotOvershoot(t *testing.T) {
	s := NewOpSet()
	const capacity = 8
	const writers = 64

	envs := make([]*frienv1.OperationEnvelope, writers)
	for i := range envs {
		envs[i] = threatEnv(t, fmt.Sprintf("op%d", i), "node.a", uint64(i+1), "")
	}

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(env *frienv1.OperationEnvelope) {
			defer wg.Done()
			s.AddWithLimit(env, capacity)
		}(envs[i])
	}
	wg.Wait()

	if got := s.Len(); got != capacity {
		t.Fatalf("concurrent adds overshot the cap: got %d, want %d", got, capacity)
	}
}

func aboveSet(ids []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

func TestScopeStateComputesContiguousWatermark(t *testing.T) {
	s := NewOpSet()
	// node.a holds 1,2,3 contiguously then a gap to 5; node.b holds 1,2.
	for _, sq := range []uint64{1, 2, 3, 5} {
		s.Add(threatEnv(t, fmt.Sprintf("a%d", sq), "node.a", sq, ""))
	}
	for _, sq := range []uint64{1, 2} {
		s.Add(threatEnv(t, fmt.Sprintf("b%d", sq), "node.b", sq, ""))
	}

	haveSeqs, haveAbove := s.ScopeState("fleet")
	if haveSeqs["node.a"] != 3 {
		t.Fatalf("node.a watermark = %d, want 3 (stops at the gap before 5)", haveSeqs["node.a"])
	}
	if haveSeqs["node.b"] != 2 {
		t.Fatalf("node.b watermark = %d, want 2", haveSeqs["node.b"])
	}
	if len(haveAbove) != 1 || haveAbove[0] != "a5" {
		t.Fatalf("have_above should be exactly the above-watermark op a5, got %v", haveAbove)
	}
}

func TestMissingInRangeSkipsHeldAndFillsGap(t *testing.T) {
	responder := NewOpSet()
	for sq := uint64(1); sq <= 5; sq++ {
		responder.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}
	requester := NewOpSet()
	for _, sq := range []uint64{1, 2, 4, 5} { // missing seq 3
		requester.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}

	haveSeqs, haveAbove := requester.ScopeState("fleet")
	if haveSeqs["node.a"] != 2 {
		t.Fatalf("watermark should stop at the gap: got %d, want 2", haveSeqs["node.a"])
	}
	missing := responder.MissingInRange("fleet", haveSeqs, aboveSet(haveAbove), 0)
	if len(missing) != 1 || missing[0].GetSeq() != 3 {
		t.Fatalf("only the gap op (seq 3) should be sent, got %d ops", len(missing))
	}
}

func TestMissingInRangePropagatesEquivocationBelowWatermark(t *testing.T) {
	responder := NewOpSet()
	for sq := uint64(1); sq <= 3; sq++ {
		responder.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}
	// Equivocation: a second op at (node.a, 2).
	responder.Add(threatEnv(t, "op2-fork", "node.a", 2, ""))

	requester := NewOpSet()
	for sq := uint64(1); sq <= 3; sq++ { // has only one op at seq 2
		requester.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}

	haveSeqs, haveAbove := requester.ScopeState("fleet")
	if haveSeqs["node.a"] != 3 {
		t.Fatalf("requester watermark = %d, want 3", haveSeqs["node.a"])
	}
	missing := responder.MissingInRange("fleet", haveSeqs, aboveSet(haveAbove), 0)
	// The forked op sits below the watermark but must still be sent as evidence.
	// Its already-held sibling may ride along as an idempotent duplicate.
	found := false
	for _, env := range missing {
		if env.GetOpId() == "op2-fork" {
			found = true
		}
	}
	if !found {
		t.Fatalf("equivocation sibling below the watermark must be sent, got %d ops", len(missing))
	}
}

func TestRangeSyncConvergesUnderEquivocation(t *testing.T) {
	responder := NewOpSet()
	for sq := uint64(1); sq <= 4; sq++ {
		responder.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}
	responder.Add(threatEnv(t, "op2-fork", "node.a", 2, ""))
	requester := NewOpSet()

	for round := 0; round < 10; round++ {
		haveSeqs, haveAbove := requester.ScopeState("fleet")
		missing := responder.MissingInRange("fleet", haveSeqs, aboveSet(haveAbove), 2)
		if len(missing) == 0 {
			break
		}
		for _, env := range missing {
			requester.Add(env)
		}
	}
	if requester.CanonicalHash() != responder.CanonicalHash() {
		t.Fatalf("range sync with equivocation diverged: req=%d resp=%d ops", requester.Len(), responder.Len())
	}
}

func TestAddRejectsMalformed(t *testing.T) {
	s := NewOpSet()
	if _, err := s.Add(nil); err == nil {
		t.Error("nil envelope should error")
	}
	if _, err := s.Add(&frienv1.OperationEnvelope{NodeId: "n"}); err == nil {
		t.Error("missing op_id should error")
	}
	if _, err := s.Add(&frienv1.OperationEnvelope{OpId: "x"}); err == nil {
		t.Error("missing node_id should error")
	}
}

func TestCompactBelowRemovesOldOpsBoundedByCut(t *testing.T) {
	s := NewOpSet()
	for sq := uint64(1); sq <= 5; sq++ {
		s.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}
	removed := s.CompactBelow("fleet", map[string]uint64{"node.a": 3})
	if len(removed) != 3 {
		t.Fatalf("should compact seqs 1-3, got %d removed", len(removed))
	}
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2 (seqs 4,5 remain)", s.Len())
	}
	for _, sq := range []uint64{1, 2, 3} {
		if s.Has(fmt.Sprintf("op%d", sq)) {
			t.Fatalf("op at seq %d should have been compacted", sq)
		}
	}
	for _, sq := range []uint64{4, 5} {
		if !s.Has(fmt.Sprintf("op%d", sq)) {
			t.Fatalf("op at seq %d should still be present", sq)
		}
	}
	for i, want := range []string{"op1", "op2", "op3"} {
		if removed[i].GetOpId() != want {
			t.Fatalf("removed[%d] = %s, want %s (sorted by op_id)", i, removed[i].GetOpId(), want)
		}
	}
}

// TestCompactBelowIsScopedNotGlobal proves the fix for a real data-loss
// vector: a node's seq counter is global across every scope it publishes
// into (see LastOpIDInScope), so a cut computed from one scope's peer
// confirmations must never delete a *different* scope's ops from the same
// origin, even when their seqs fall in the same numeric range. Before
// CompactBelow took a scopeKey, a zone-confirmed cut would also have deleted
// that origin's interleaved fleet ops that no fleet peer had confirmed.
func TestCompactBelowIsScopedNotGlobal(t *testing.T) {
	s := NewOpSet()
	// Interleave: seq 1 fleet, seq 2 zone:eu, seq 3 fleet, seq 4 zone:eu.
	addScoped := func(id string, seq uint64, scopeKey string) {
		tr := &frienv1.ThreatRecord{Id: id, Indicator: "203.0.113.1", Scope: scopeKey}
		payload, err := proto.Marshal(tr)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		env := &frienv1.OperationEnvelope{
			OpId: id, OpType: OpThreatRecord, NodeId: "node.a", Seq: seq,
			PayloadHash: payloadHash(payload), Payload: payload,
		}
		if _, err := s.Add(env); err != nil {
			t.Fatalf("add %s: %v", id, err)
		}
	}
	addScoped("f1", 1, "fleet")
	addScoped("z1", 2, "zone:eu")
	addScoped("f2", 3, "fleet")
	addScoped("z2", 4, "zone:eu")

	// A cut of 4 for node.a, applied only to zone:eu, must leave both fleet
	// ops untouched even though their seqs (1, 3) are below the cut.
	removed := s.CompactBelow("zone:eu", map[string]uint64{"node.a": 4})
	if len(removed) != 2 || removed[0].GetOpId() != "z1" || removed[1].GetOpId() != "z2" {
		t.Fatalf("expected only z1,z2 removed, got %+v", removed)
	}
	if !s.Has("f1") || !s.Has("f2") {
		t.Fatal("fleet ops must survive a zone-scoped compaction cut even at lower seqs")
	}
	if s.Has("z1") || s.Has("z2") {
		t.Fatal("zone ops should have been compacted")
	}
}

func TestCompactBelowLeavesUnknownOriginsUntouched(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "a1", "node.a", 1, ""))
	s.Add(threatEnv(t, "b1", "node.b", 1, ""))
	// Only node.a has a known cut; node.b must be left alone entirely.
	s.CompactBelow("fleet", map[string]uint64{"node.a": 100})
	if s.Has("a1") {
		t.Fatal("node.a's op should be compacted")
	}
	if !s.Has("b1") {
		t.Fatal("node.b has no cut yet; its op must survive untouched")
	}
}

func TestCompactBelowPreservesEquivocationEvidence(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "opA", "node.a", 1, ""))
	s.Add(threatEnv(t, "opB", "node.a", 1, "")) // fork at (node.a, 1)

	s.CompactBelow("fleet", map[string]uint64{"node.a": 100})
	if !s.Has("opA") || !s.Has("opB") {
		t.Fatal("equivocation evidence must survive compaction even below the cut")
	}
}

func TestCompactBelowRemovesScopeIndexEntry(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "op1", "node.a", 1, ""))
	if len(s.OpIDsInScope("fleet")) != 1 {
		t.Fatal("op should be indexed under fleet before compaction")
	}
	s.CompactBelow("fleet", map[string]uint64{"node.a": 100})
	if len(s.OpIDsInScope("fleet")) != 0 {
		t.Fatal("scope index entry should be removed alongside the op")
	}
}

func TestCompactedReplayDoesNotResurrect(t *testing.T) {
	s := NewOpSet()
	env := threatEnv(t, "op1", "node.a", 1, "")
	s.Add(env)
	s.CompactBelow("fleet", map[string]uint64{"node.a": 100})
	if s.Has("op1") {
		t.Fatal("precondition: op1 should be compacted")
	}

	// A slow peer's anti-entropy later re-delivers the exact same envelope.
	res, err := s.Add(env)
	if err != nil {
		t.Fatalf("replay of a compacted op should not error: %v", err)
	}
	if !res.Duplicate || res.Added {
		t.Fatalf("replay should be treated as an idempotent duplicate, got %+v", res)
	}
	if s.Has("op1") {
		t.Fatal("a compacted op must not be resurrected by replay")
	}
}

func TestCompactedSeqStillDetectsLateEquivocation(t *testing.T) {
	s := NewOpSet()
	s.Add(threatEnv(t, "original", "node.a", 1, ""))
	s.CompactBelow("fleet", map[string]uint64{"node.a": 100})

	// A different op_id at the same (node_id, seq) arrives after the original
	// was compacted: this is still equivocation, and must still be flagged,
	// even though the original envelope is no longer available as evidence.
	res, err := s.Add(threatEnv(t, "forged", "node.a", 1, ""))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if res.Equivocation == nil {
		t.Fatal("a conflicting op at an already-compacted seq must still be detected as equivocation")
	}
	if res.Equivocation.GetOpA() != nil {
		t.Fatal("OpA should be nil: its evidence was already compacted")
	}
	if !s.Has("forged") {
		t.Fatal("the newly detected equivocating op should be admitted (and now protected from compaction)")
	}
}

func TestScopeStateWatermarkAdvancesPastCompactedRegion(t *testing.T) {
	s := NewOpSet()
	for sq := uint64(1); sq <= 3; sq++ {
		s.Add(threatEnv(t, fmt.Sprintf("op%d", sq), "node.a", sq, ""))
	}
	s.CompactBelow("fleet", map[string]uint64{"node.a": 3})

	haveSeqs, haveAbove := s.ScopeState("fleet")
	if haveSeqs["node.a"] != 3 {
		t.Fatalf("watermark should still read 3 after compaction, got %d", haveSeqs["node.a"])
	}
	if len(haveAbove) != 0 {
		t.Fatalf("nothing should be listed above the watermark right after full compaction, got %v", haveAbove)
	}

	// A new op continuing the sequence should extend the watermark further.
	s.Add(threatEnv(t, "op4", "node.a", 4, ""))
	haveSeqs, _ = s.ScopeState("fleet")
	if haveSeqs["node.a"] != 4 {
		t.Fatalf("watermark should advance to 4 across the compacted region, got %d", haveSeqs["node.a"])
	}
}
