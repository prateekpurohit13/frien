// Package audit is frien's immutable, tamper-evident record of every
// enforcement-relevant action: promotions to enforce mode, rollbacks,
// breakglass invocations, policy loads, and the decisions themselves. Every
// action that could change what frien does to a host must answer "who, when,
// why, and what changed" — this package is where that answer is durably kept.
//
// Entries are hash-linked (each carries the previous entry's hash) so a
// deletion or edit anywhere in the chain is detectable by Verify, exactly like
// the WAL. The log lives in its own bbolt bucket keyed by a monotonic sequence,
// so ordering is stable and append-only.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

const bucketAudit = "audit"

// Action categories recorded in the log.
const (
	ActionModeSet    = "mode_set"
	ActionRollback   = "rollback"
	ActionBreakglass = "breakglass"
	ActionDecision   = "decision"
	ActionPolicyLoad = "policy_load"
)

// Entry is one immutable audit record. Hash and PrevHash form the tamper-
// evident chain; everything above them is the recorded fact. ID is a short,
// stable handle derived from the entry's own hash.
type Entry struct {
	ID       string            `json:"id"`
	Seq      uint64            `json:"seq"`
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor"`  // operator id / node id / "system"
	Action   string            `json:"action"` // one of the Action* constants
	Adapter  string            `json:"adapter,omitempty"`
	Target   string            `json:"target,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Outcome  string            `json:"outcome,omitempty"`
	PolicyID string            `json:"policy_id,omitempty"`
	Details  map[string]string `json:"details,omitempty"`
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Log is the append-only audit log over a bbolt bucket. It is constructed over
// the shared storage.Store's *bolt.DB.
type Log struct {
	db  *bolt.DB
	now func() time.Time
}

// NewLog wraps an open bbolt handle, creating the audit bucket if needed. now
// may be nil (time.Now).
func NewLog(db *bolt.DB, now func() time.Time) (*Log, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: nil bbolt db")
	}
	if now == nil {
		now = time.Now
	}
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketAudit))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("audit: creating bucket: %w", err)
	}
	return &Log{db: db, now: now}, nil
}

// Append writes a new entry, linking it to the current chain head, and returns
// the stored entry (with its assigned Seq, Time, PrevHash, Hash, and ID). The
// caller-supplied fields (Actor, Action, …) are recorded as given; Time is
// stamped here unless already set.
func (l *Log) Append(e Entry) (Entry, error) {
	if e.Action == "" {
		return Entry{}, fmt.Errorf("audit: entry missing action")
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketAudit))
		// Chain head = last key.
		c := b.Cursor()
		lastKey, lastVal := c.Last()
		var prevSeq uint64
		prevHash := ""
		if lastKey != nil {
			prevSeq = binary.BigEndian.Uint64(lastKey)
			var prev Entry
			if err := json.Unmarshal(lastVal, &prev); err == nil {
				prevHash = prev.Hash
			}
		}
		e.Seq = prevSeq + 1
		e.PrevHash = prevHash
		e.Hash = e.computeHash()
		e.ID = "audit-" + e.Hash[:16]

		val, err := json.Marshal(e)
		if err != nil {
			return err
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], e.Seq)
		return b.Put(key[:], val)
	})
	if err != nil {
		return Entry{}, fmt.Errorf("audit: appending: %w", err)
	}
	return e, nil
}

// Get returns the entry with the given audit ID, or (zero, false).
func (l *Log) Get(id string) (Entry, bool, error) {
	var out Entry
	found := false
	err := l.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketAudit)).ForEach(func(_, v []byte) error {
			if found {
				return nil
			}
			var e Entry
			if json.Unmarshal(v, &e) == nil && e.ID == id {
				out, found = e, true
			}
			return nil
		})
	})
	if err != nil {
		return Entry{}, false, err
	}
	return out, found, nil
}

// List returns the most recent `limit` entries, newest first. limit <= 0
// returns all.
func (l *Log) List(limit int) ([]Entry, error) {
	var all []Entry
	err := l.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketAudit)).ForEach(func(_, v []byte) error {
			var e Entry
			if json.Unmarshal(v, &e) == nil {
				all = append(all, e)
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Seq > all[j].Seq })
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

// Verify walks the whole chain in sequence order and confirms each entry's hash
// recomputes and links to its predecessor. It returns an error identifying the
// first broken link, so a tampered or deleted entry is caught.
func (l *Log) Verify() error {
	var entries []Entry
	err := l.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketAudit)).ForEach(func(_, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			entries = append(entries, e)
			return nil
		})
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Seq < entries[j].Seq })

	prevHash := ""
	var prevSeq uint64
	for i, e := range entries {
		if i > 0 && e.Seq != prevSeq+1 {
			return fmt.Errorf("audit: sequence gap at seq %d (prev %d): a record was deleted", e.Seq, prevSeq)
		}
		if e.PrevHash != prevHash {
			return fmt.Errorf("audit: broken chain at seq %d: prev_hash mismatch", e.Seq)
		}
		if e.computeHash() != e.Hash {
			return fmt.Errorf("audit: tampered record at seq %d: hash mismatch", e.Seq)
		}
		prevHash = e.Hash
		prevSeq = e.Seq
	}
	return nil
}

// computeHash hashes the entry's recorded fields plus PrevHash, excluding Hash
// and ID (which are derived from it). Map keys are sorted for determinism.
func (e Entry) computeHash() string {
	h := sha256.New()
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], e.Seq)
	h.Write(u64[:])
	writeField(h, e.Time.UTC().Format(time.RFC3339Nano))
	for _, s := range []string{e.Actor, e.Action, e.Adapter, e.Target, e.Reason, e.Outcome, e.PolicyID} {
		writeField(h, s)
	}
	keys := make([]string, 0, len(e.Details))
	for k := range e.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		writeField(h, k)
		writeField(h, e.Details[k])
	}
	writeField(h, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s)))
	h.Write(l[:])
	h.Write([]byte(s))
}
