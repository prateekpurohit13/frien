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
