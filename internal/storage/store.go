package storage

import (
	"fmt"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

// Options configures a Store. It is intentionally a small, storage-local struct
// rather than the full config.Config, so the storage layer stays decoupled from
// the daemon's configuration schema and is trivial to construct in tests.
type Options struct {
	WALDir      string // directory holding the WAL segment
	DBPath      string // bbolt database file path
	SnapshotDir string // directory holding signed snapshots
	WALSync     bool   // fsync every WAL append (durability vs. throughput)
}

// Store bundles the three local persistence mechanisms (hash-linked WAL, bbolt
// metadata index, and snapshot directory) behind a single open/close lifecycle.
// No external database is ever required — a node starts, recovers, and serves
// using only local disk (a core non-negotiable from docs/FRIEN_ARCHITECTURE.md).
type Store struct {
	WAL         *WAL
	DB          *bolt.DB
	snapshotDir string
	log         zerolog.Logger
}

// Open initializes the WAL and bbolt database and verifies their integrity. If
// the WAL hash chain is corrupt, Open fails: continuing past tamper-evidence is
// an explicit operator decision, not a silent default.
func Open(opts Options, log zerolog.Logger) (*Store, error) {
	wal, err := OpenWAL(opts.WALDir, opts.WALSync)
	if err != nil {
		return nil, err
	}

	db, err := openBolt(opts.DBPath)
	if err != nil {
		_ = wal.Close()
		return nil, err
	}

	log.Info().
		Str("wal_path", wal.Path()).
		Int64("wal_size_bytes", wal.Size()).
		Str("db_path", opts.DBPath).
		Int("schema_version", SchemaVersion).
		Msg("storage opened")

	return &Store{
		WAL:         wal,
		DB:          db,
		snapshotDir: opts.SnapshotDir,
		log:         log,
	}, nil
}

// LoadLatestSnapshot returns the newest snapshot, or nil if the node is fresh.
func (s *Store) LoadLatestSnapshot() (*Snapshot, error) {
	return LoadLatestSnapshot(s.snapshotDir)
}

// SaveSnapshot persists snap into the configured snapshot directory.
func (s *Store) SaveSnapshot(snap *Snapshot) (string, error) {
	return SaveSnapshot(s.snapshotDir, snap)
}

// Close releases both the bbolt handle and the WAL file. Both are attempted even
// if the first fails, and the first error encountered is returned.
func (s *Store) Close() error {
	var firstErr error
	if s.DB != nil {
		if err := s.DB.Close(); err != nil {
			firstErr = fmt.Errorf("storage: closing bbolt: %w", err)
		}
	}
	if s.WAL != nil {
		if err := s.WAL.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("storage: closing wal: %w", err)
		}
	}
	return firstErr
}
