package enforcer

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// bucketRollbackTokens mirrors storage.BucketRollbackTokens. It is duplicated
// as a literal rather than imported so this package does not depend on
// internal/storage's schema surface — the Store hands us its *bolt.DB and we
// own this one bucket's layout.
const bucketRollbackTokens = "rollback_tokens"

// RollbackToken is the durable record of one applied mitigation. It is written
// before/at apply time and reconciled on restart so a crash mid-enforcement
// never leaves silent partial state: either the rule is confirmed still present
// (and left to its kernel timeout) or it is confirmed gone (and the token is
// closed out).
type RollbackToken struct {
	Token      string    `json:"token"`
	DecisionID string    `json:"decision_id"`
	Adapter    string    `json:"adapter"`
	Target     string    `json:"target"`
	Action     string    `json:"action"`
	AppliedAt  time.Time `json:"applied_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Applied    bool      `json:"applied"`
	RolledBack bool      `json:"rolled_back"`
}

// RollbackStore persists rollback tokens in bbolt. It is constructed over the
// shared storage.Store's *bolt.DB (whose Open already created the bucket).
type RollbackStore struct {
	db *bolt.DB
}

// NewRollbackStore wraps an already-open bbolt handle. It creates the bucket if
// missing so the store also works against a bare test DB.
func NewRollbackStore(db *bolt.DB) (*RollbackStore, error) {
	if db == nil {
		return nil, fmt.Errorf("enforcer: nil bbolt db")
	}
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketRollbackTokens))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("enforcer: creating rollback bucket: %w", err)
	}
	return &RollbackStore{db: db}, nil
}

// Put writes or overwrites a token record.
func (s *RollbackStore) Put(t RollbackToken) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("enforcer: marshaling token: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRollbackTokens)).Put([]byte(t.Token), b)
	})
}

// Get returns the token record, or (zero, false, nil) if absent.
func (s *RollbackStore) Get(token string) (RollbackToken, bool, error) {
	var out RollbackToken
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketRollbackTokens)).Get([]byte(token))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &out)
	})
	if err != nil {
		return RollbackToken{}, false, fmt.Errorf("enforcer: reading token %s: %w", token, err)
	}
	return out, found, nil
}

// MarkRolledBack flips RolledBack on a stored token. An absent token is not an
// error (the record may have been compacted or never persisted).
func (s *RollbackStore) MarkRolledBack(token string) error {
	t, ok, err := s.Get(token)
	if err != nil || !ok {
		return err
	}
	t.RolledBack = true
	return s.Put(t)
}

// Outstanding returns all tokens that were applied and not yet rolled back —
// the set that must be reconciled after a restart.
func (s *RollbackStore) Outstanding() ([]RollbackToken, error) {
	var out []RollbackToken
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketRollbackTokens)).ForEach(func(_, v []byte) error {
			var t RollbackToken
			if err := json.Unmarshal(v, &t); err != nil {
				return nil // skip an unreadable record rather than fail the whole scan
			}
			if t.Applied && !t.RolledBack {
				out = append(out, t)
			}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("enforcer: scanning tokens: %w", err)
	}
	return out, nil
}
