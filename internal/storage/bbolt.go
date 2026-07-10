package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bucket names for the bbolt metadata store. These mirror docs/database.md so the
// on-disk layout is documented in one place and referenced symbolically everywhere.
const (
	BucketPeers          = "peers"           // node_id            -> PeerState
	BucketThreats        = "threats"         // threat_id          -> ThreatRecord
	BucketDecisions      = "decisions"       // decision_id        -> EnforcementDecision
	BucketRollbackTokens = "rollback_tokens" // rollback_token    -> decision_id
	BucketRevocations    = "revocations"     // cert_fingerprint   -> RevocationRecord
	BucketPolicies       = "policies"        // policy_id:version  -> Policy
	BucketCheckpoints    = "checkpoints"     // checkpoint_id      -> Checkpoint
	BucketAudit          = "audit"           // audit_id           -> AuditEntry
	BucketOpDedup        = "op_dedup"        // op_id              -> "1" (replay window)
	BucketMeta           = "meta"            // schema_version, etc.
)

// allBuckets is the authoritative set created at open time. Adding a bucket here
// is the only change needed to provision it across fresh and existing databases.
var allBuckets = []string{
	BucketPeers,
	BucketThreats,
	BucketDecisions,
	BucketRollbackTokens,
	BucketRevocations,
	BucketPolicies,
	BucketCheckpoints,
	BucketAudit,
	BucketOpDedup,
	BucketMeta,
}

// SchemaVersion is the on-disk metadata format version. Bump it only when a
// migration is required (see docs/UPGRADE.md §Schema Migrations).
const SchemaVersion = 1

const metaKeySchemaVersion = "schema_version"

// MetaKeyHLC is the meta-bucket key under which the daemon persists the Hybrid
// Logical Clock so it cannot regress across a restart.
const MetaKeyHLC = "hlc"

// openBolt opens (creating if absent) the bbolt database at path, ensures every
// required bucket exists, and records/validates the schema version. A timeout
// guards against a stale lock from a previous process holding the file.
func openBolt(path string) (*bolt.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("bbolt: empty db path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("bbolt: creating dir for %s: %w", path, err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("bbolt: opening %s: %w", path, err)
	}

	if err := initBuckets(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func initBuckets(db *bolt.DB) error {
	return db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("bbolt: creating bucket %q: %w", name, err)
			}
		}

		meta := tx.Bucket([]byte(BucketMeta))
		existing := meta.Get([]byte(metaKeySchemaVersion))
		if existing == nil {
			// Fresh database: stamp the current schema version.
			return meta.Put([]byte(metaKeySchemaVersion), []byte{byte(SchemaVersion)})
		}
		if len(existing) != 1 || existing[0] > SchemaVersion {
			// A newer binary wrote this file; refuse to start rather than risk
			// interpreting an unknown layout (docs/UPGRADE.md emergency-downgrade rule).
			return fmt.Errorf("bbolt: on-disk schema version %v is newer than supported %d",
				existing, SchemaVersion)
		}
		// existing[0] < SchemaVersion would trigger migrations here in a future release.
		return nil
	})
}
