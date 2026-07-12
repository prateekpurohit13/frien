package audit

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/prateekpurohit13/frien/internal/policy"
)

func testDB(t *testing.T) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(filepath.Join(t.TempDir(), "audit.db"), 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("open bbolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAppendAndChain(t *testing.T) {
	l, err := NewLog(testDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	e1, err := l.Append(Entry{Actor: "op", Action: ActionModeSet, Adapter: "nftables", Reason: "rollout"})
	if err != nil {
		t.Fatal(err)
	}
	if e1.Seq != 1 || e1.PrevHash != "" || e1.Hash == "" || e1.ID == "" {
		t.Fatalf("first entry wrong: %+v", e1)
	}
	e2, _ := l.Append(Entry{Actor: "op", Action: ActionRollback, Reason: "oops"})
	if e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("chain not linked: %+v", e2)
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("Verify on clean log: %v", err)
	}
}

func TestGetAndList(t *testing.T) {
	l, _ := NewLog(testDB(t), nil)
	e1, _ := l.Append(Entry{Actor: "op", Action: ActionModeSet})
	_, _ = l.Append(Entry{Actor: "op", Action: ActionBreakglass})

	got, ok, _ := l.Get(e1.ID)
	if !ok || got.ID != e1.ID {
		t.Fatalf("Get: ok=%v got=%+v", ok, got)
	}
	list, _ := l.List(0)
	if len(list) != 2 || list[0].Seq != 2 { // newest first
		t.Fatalf("List order wrong: %+v", list)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	db := testDB(t)
	l, _ := NewLog(db, nil)
	_, _ = l.Append(Entry{Actor: "op", Action: ActionModeSet, Reason: "original"})
	_, _ = l.Append(Entry{Actor: "op", Action: ActionRollback})

	// Tamper: overwrite seq-1's stored value with a changed reason but stale hash.
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketAudit))
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], 1)
		// Hand-craft a record whose Hash no longer matches its content.
		return b.Put(key[:], []byte(`{"id":"audit-x","seq":1,"time":"2020-01-01T00:00:00Z","actor":"op","action":"mode_set","reason":"TAMPERED","prev_hash":"","hash":"deadbeef"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(); err == nil {
		t.Fatal("Verify should detect a tampered record")
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	db := testDB(t)
	l, _ := NewLog(db, nil)
	_, _ = l.Append(Entry{Actor: "op", Action: ActionModeSet})
	_, _ = l.Append(Entry{Actor: "op", Action: ActionRollback})
	_, _ = l.Append(Entry{Actor: "op", Action: ActionBreakglass})

	// Delete the middle entry (seq 2), leaving a gap.
	err := db.Update(func(tx *bolt.Tx) error {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], 2)
		return tx.Bucket([]byte(bucketAudit)).Delete(key[:])
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Verify(); err == nil {
		t.Fatal("Verify should detect a deleted record (sequence gap / broken link)")
	}
}

func TestExplanationFromDecision(t *testing.T) {
	now := time.Now()
	d := policy.Decision{
		Indicator:      "203.0.113.7",
		Outcome:        policy.OutcomeEnforced,
		Reason:         "quorum met",
		Identities:     []string{"fpA", "fpB", "fpC"},
		MatchedWeight:  3.0,
		RequiredWeight: 3.0,
		Adapter:        "nftables",
		PolicyID:       "edge_block_v1",
		PolicyVersion:  7,
		ExpiresAt:      now.Add(time.Hour),
	}
	ex := FromDecision(d, "tok-1", "audit-abc")
	resp := ex.ToProto()
	if resp.GetDecision() != policy.OutcomeEnforced ||
		resp.GetRollbackToken() != "tok-1" ||
		resp.GetAuditEntryId() != "audit-abc" ||
		len(resp.GetContributingIdentities()) != 3 ||
		resp.GetPolicyVersion() != 7 ||
		resp.GetExpiresAt() == "" {
		t.Fatalf("explanation proto wrong: %+v", resp)
	}
}
