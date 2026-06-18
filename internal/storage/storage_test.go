package storage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

// ─── WAL: append + replay ──────────────────────────────────────────────────────

func TestWAL_AppendReplay(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	want := [][]byte{
		[]byte("first operation"),
		[]byte("second operation"),
		{}, // empty payload must round-trip
		[]byte("fourth"),
	}
	for _, p := range want {
		if err := w.Append(p); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen and replay — exercises cross-restart chain continuation.
	w2, err := OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()

	var got [][]byte
	if err := w2.Replay(func(p []byte) error {
		got = append(got, append([]byte(nil), p...))
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("replayed %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("record %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestWAL_AppendAfterReopen_ChainContinues(t *testing.T) {
	dir := t.TempDir()

	w, _ := OpenWAL(dir, true)
	_ = w.Append([]byte("a"))
	_ = w.Append([]byte("b"))
	_ = w.Close()

	w2, err := OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := w2.Append([]byte("c")); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	_ = w2.Close()

	w3, _ := OpenWAL(dir, true)
	defer w3.Close()
	var count int
	if err := w3.Replay(func(_ []byte) error { count++; return nil }); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 records across reopens, got %d", count)
	}
}

// ─── WAL: tamper-evidence ──────────────────────────────────────────────────────

func TestWAL_TamperedPayload_DetectedOnReopen(t *testing.T) {
	dir := t.TempDir()
	w, _ := OpenWAL(dir, true)
	_ = w.Append([]byte("sensitive-operation"))
	_ = w.Append([]byte("another-operation"))
	_ = w.Close()

	// Flip a byte inside the first record's payload region.
	path := filepath.Join(dir, walFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	// header(44) + first byte of payload
	data[headerSize] ^= 0xFF
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write tampered wal: %v", err)
	}

	if _, err := OpenWAL(dir, true); err == nil {
		t.Fatal("tampered payload must be detected on reopen")
	}
}

func TestWAL_TruncatedTail_RecoveredNotRejected(t *testing.T) {
	dir := t.TempDir()
	w, _ := OpenWAL(dir, true)
	_ = w.Append([]byte("complete-record"))
	_ = w.Append([]byte("this-tail-will-be-torn"))
	_ = w.Close()

	// Chop the last few bytes to simulate a crash mid-append.
	path := filepath.Join(dir, walFileName)
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, data[:len(data)-5], 0o600); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	w2, err := OpenWAL(dir, true)
	if err != nil {
		t.Fatalf("torn tail should recover, not fail: %v", err)
	}
	defer w2.Close()

	var count int
	if err := w2.Replay(func(_ []byte) error { count++; return nil }); err != nil {
		t.Fatalf("replay after torn tail: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 surviving complete record, got %d", count)
	}

	// The recovered WAL must still be appendable with an intact chain.
	if err := w2.Append([]byte("recovery-write")); err != nil {
		t.Fatalf("append after recovery: %v", err)
	}
}

func TestWAL_ReplayCallbackError_Propagates(t *testing.T) {
	dir := t.TempDir()
	w, _ := OpenWAL(dir, true)
	_ = w.Append([]byte("x"))
	defer w.Close()

	sentinel := fmt.Errorf("stop here")
	err := w.Replay(func(_ []byte) error { return sentinel })
	if err != sentinel {
		t.Fatalf("expected callback error to propagate, got %v", err)
	}
}

func TestWAL_Size(t *testing.T) {
	dir := t.TempDir()
	w, _ := OpenWAL(dir, false)
	defer w.Close()
	if w.Size() != 0 {
		t.Fatalf("fresh WAL size should be 0, got %d", w.Size())
	}
	payload := []byte("measure-me")
	_ = w.Append(payload)
	want := int64(headerSize + len(payload) + hashSize)
	if w.Size() != want {
		t.Fatalf("size after one append = %d, want %d", w.Size(), want)
	}
}

// ─── bbolt ─────────────────────────────────────────────────────────────────────

func TestBolt_OpenCreatesBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := openBolt(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	err = db.View(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if tx.Bucket([]byte(name)) == nil {
				return fmt.Errorf("bucket %q missing", name)
			}
		}
		// Schema version must be stamped on a fresh database.
		v := tx.Bucket([]byte(BucketMeta)).Get([]byte(metaKeySchemaVersion))
		if len(v) != 1 || v[0] != SchemaVersion {
			return fmt.Errorf("schema version not stamped, got %v", v)
		}
		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestBolt_RejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := openBolt(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Forge a schema version from a hypothetical future binary.
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(BucketMeta)).Put([]byte(metaKeySchemaVersion), []byte{SchemaVersion + 1})
	}); err != nil {
		t.Fatalf("forge: %v", err)
	}
	db.Close()

	if _, err := openBolt(path); err == nil {
		t.Fatal("opening a newer-schema database must fail, not silently proceed")
	}
}

// ─── Store lifecycle + snapshots ────────────────────────────────────────────────

func TestStore_OpenCloseReopen(t *testing.T) {
	base := t.TempDir()
	opts := Options{
		WALDir:      filepath.Join(base, "wal"),
		DBPath:      filepath.Join(base, "state.db"),
		SnapshotDir: filepath.Join(base, "snapshots"),
		WALSync:     true,
	}

	s, err := Open(opts, zerolog.Nop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.WAL.Append([]byte("op-1")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	s2, err := Open(opts, zerolog.Nop())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	var count int
	_ = s2.WAL.Replay(func(_ []byte) error { count++; return nil })
	if count != 1 {
		t.Fatalf("expected 1 record after reopen, got %d", count)
	}
}

func TestSnapshot_SaveLoadLatest(t *testing.T) {
	dir := t.TempDir()

	if snap, err := LoadLatestSnapshot(dir); err != nil || snap != nil {
		t.Fatalf("fresh dir: want (nil,nil), got (%v,%v)", snap, err)
	}

	first := &Snapshot{CheckpointID: "ckpt_1", StateHash: "h1", State: []byte("s1")}
	if _, err := SaveSnapshot(dir, first); err != nil {
		t.Fatalf("save first: %v", err)
	}
	second := &Snapshot{CheckpointID: "ckpt_2", StateHash: "h2", State: []byte("s2")}
	if _, err := SaveSnapshot(dir, second); err != nil {
		t.Fatalf("save second: %v", err)
	}

	got, err := LoadLatestSnapshot(dir)
	if err != nil {
		t.Fatalf("load latest: %v", err)
	}
	if got == nil || got.CheckpointID != "ckpt_2" {
		t.Fatalf("expected latest checkpoint ckpt_2, got %+v", got)
	}
	if !bytes.Equal(got.State, []byte("s2")) {
		t.Fatalf("state mismatch: %q", got.State)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Errorf("schema version not stamped: %d", got.SchemaVersion)
	}
}
