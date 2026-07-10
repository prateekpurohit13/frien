package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshot is a point-in-time materialization of node state, anchored to a
// checkpoint, used to bound restart recovery: on startup the node loads the
// latest snapshot and replays only the WAL records above it (docs/database.md
// §Startup Recovery). In Phase 1 there is no CRDT state yet, so State is empty,
// but the format and lifecycle are real and forward-compatible.
type Snapshot struct {
	SchemaVersion int       `json:"schema_version"`
	CheckpointID  string    `json:"checkpoint_id"` // anchor; empty before Phase 4 checkpoints exist
	StateHash     string    `json:"state_hash"`    // SHA-256 of State, for integrity checks
	CreatedAt     time.Time `json:"created_at"`
	State         []byte    `json:"state"` // opaque materialized state blob
}

const snapshotExt = ".snap"

// SaveSnapshot writes snap into dir atomically (temp file + rename) so a crash
// mid-write can never leave a partially-written snapshot that loads as valid.
// The filename is timestamp-ordered so LoadLatestSnapshot can pick the newest.
func SaveSnapshot(dir string, snap *Snapshot) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("snapshot: empty dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("snapshot: creating dir %s: %w", dir, err)
	}
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = SchemaVersion
	}
	if snap.CreatedAt.IsZero() {
		snap.CreatedAt = time.Now().UTC()
	}

	data, err := json.Marshal(snap)
	if err != nil {
		return "", fmt.Errorf("snapshot: marshal: %w", err)
	}

	name := fmt.Sprintf("%020d%s", snap.CreatedAt.UTC().UnixNano(), snapshotExt)
	final := filepath.Join(dir, name)

	tmp, err := os.CreateTemp(dir, "snapshot-*.tmp")
	if err != nil {
		return "", fmt.Errorf("snapshot: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("snapshot: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("snapshot: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("snapshot: close: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return "", fmt.Errorf("snapshot: rename: %w", err)
	}
	return final, nil
}

// LoadLatestSnapshot returns the newest snapshot in dir, or (nil, nil) if none
// exists yet (a fresh node). A corrupt latest snapshot is reported as an error so
// the caller can decide whether to fall back to a full WAL replay.
func LoadLatestSnapshot(dir string) (*Snapshot, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: reading dir %s: %w", dir, err)
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), snapshotExt) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sort.Strings(names) // timestamp-prefixed names sort chronologically
	latest := filepath.Join(dir, names[len(names)-1])

	data, err := os.ReadFile(latest)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading %s: %w", latest, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("snapshot: parsing %s: %w", latest, err)
	}
	return &snap, nil
}
