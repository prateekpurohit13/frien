package storage

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// WAL is an append-only, hash-linked write-ahead log. Each record commits to the
// previous record's hash, so any truncation, reordering, or in-place modification
// of history is detectable on replay (tamper-evidence, per docs/database.md §WAL).
//
// On-disk record layout (matches docs/database.md):
//
//	[4  bytes] magic              — constant walMagic, frames every record
//	[8  bytes] payload length     — little-endian uint64, length of payload only
//	[32 bytes] prev hash          — self-hash of the preceding record (zero for the first)
//	[N  bytes] payload            — opaque caller bytes (a marshaled OperationEnvelope)
//	[32 bytes] self hash          — SHA-256(magic || length || prev hash || payload)
//
// The payload is opaque to the WAL: storage stays decoupled from the wire schema.
// Compaction (pruning below a checkpoint) is intentionally out of scope here and
// arrives in Phase 4; this type only guarantees durable, verifiable append + replay.
type WAL struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	sync     bool
	lastHash [hashSize]byte
	size     int64
}

const (
	walMagic    uint32 = 0x4652574C // "FRWL"
	hashSize           = sha256.Size
	headerSize         = 4 + 8 + hashSize // magic + length + prev hash
	walFileName        = "wal.log"

	// maxRecordPayload bounds a single replayed record so a corrupt length field
	// cannot drive an unbounded allocation. 64 MiB is well above any legitimate
	// envelope (transport.max_message_bytes caps at 16 MiB).
	maxRecordPayload = 64 * 1024 * 1024
)

// ErrCorruptWAL indicates the on-disk hash chain failed verification. The daemon
// must not silently continue past this: recovery is an explicit operator decision.
var ErrCorruptWAL = errors.New("wal: hash chain verification failed")

// OpenWAL opens (creating if absent) the WAL segment in dir and verifies the
// existing hash chain, leaving the file positioned for appends. The returned WAL
// holds the self-hash of the last valid record so the chain continues across restarts.
func OpenWAL(dir string, fsync bool) (*WAL, error) {
	if dir == "" {
		return nil, fmt.Errorf("wal: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("wal: creating dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, walFileName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wal: opening %s: %w", path, err)
	}

	w := &WAL{f: f, path: path, sync: fsync}
	if err := w.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// recover scans the whole file from the start, verifying the chain, and records
// the last good hash and the byte offset at which the next append begins. A record
// that is incompletely written (e.g. a crash mid-append) truncates the file back
// to the last complete record rather than failing — a torn tail is expected after
// a crash, whereas a hash mismatch within a complete record is genuine corruption.
func (w *WAL) recover() error {
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("wal: seek start: %w", err)
	}

	var prev [hashSize]byte
	var offset int64

	for {
		rec, n, err := readRecord(w.f, prev)
		if err == nil {
			prev = rec.selfHash
			offset += n
			continue
		}
		if errors.Is(err, io.EOF) {
			break // clean end of log
		}
		if errors.Is(err, errTornRecord) {
			// Trailing partial record from an interrupted append: discard it.
			if terr := w.f.Truncate(offset); terr != nil {
				return fmt.Errorf("wal: truncating torn tail: %w", terr)
			}
			break
		}
		return err // ErrCorruptWAL or an I/O error
	}

	if _, err := w.f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("wal: seek to append offset: %w", err)
	}
	w.lastHash = prev
	w.size = offset
	return nil
}

// Append writes payload as a new hash-linked record and (if configured) fsyncs it.
// It is safe for concurrent use; records are serialized.
func (w *WAL) Append(payload []byte) error {
	if len(payload) > maxRecordPayload {
		return fmt.Errorf("wal: payload %d bytes exceeds max %d", len(payload), maxRecordPayload)
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:4], walMagic)
	binary.LittleEndian.PutUint64(header[4:12], uint64(len(payload)))
	copy(header[12:], w.lastHash[:])

	h := sha256.New()
	h.Write(header)
	h.Write(payload)
	var self [hashSize]byte
	h.Sum(self[:0])

	// Single write of the fully-assembled record minimizes the torn-write window.
	record := make([]byte, 0, headerSize+len(payload)+hashSize)
	record = append(record, header...)
	record = append(record, payload...)
	record = append(record, self[:]...)

	if _, err := w.f.Write(record); err != nil {
		return fmt.Errorf("wal: write: %w", err)
	}
	if w.sync {
		if err := w.f.Sync(); err != nil {
			return fmt.Errorf("wal: fsync: %w", err)
		}
	}

	w.lastHash = self
	w.size += int64(len(record))
	return nil
}

// Replay invokes fn for every record in order, verifying the hash chain as it
// goes. A verification failure returns ErrCorruptWAL. If fn returns an error,
// replay stops and returns it.
func (w *WAL) Replay(fn func(payload []byte) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("wal: seek start: %w", err)
	}
	defer func() { _, _ = w.f.Seek(w.size, io.SeekStart) }()

	var prev [hashSize]byte
	for {
		rec, _, err := readRecord(w.f, prev)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			if errors.Is(err, errTornRecord) {
				return nil // tail already accounted for during recover()
			}
			return err
		}
		if cbErr := fn(rec.payload); cbErr != nil {
			return cbErr
		}
		prev = rec.selfHash
	}
}

// Size returns the current on-disk byte size of the WAL (for status reporting).
func (w *WAL) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// Path returns the WAL file path.
func (w *WAL) Path() string { return w.path }

// Close flushes and closes the underlying file.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

type walRecord struct {
	payload  []byte
	selfHash [hashSize]byte
}

// errTornRecord signals an incomplete trailing record (short read), distinct from
// ErrCorruptWAL which signals a complete-but-tampered record.
var errTornRecord = errors.New("wal: torn trailing record")

// readRecord reads and verifies one record, returning it plus the total bytes
// consumed. expectedPrev is the self-hash the record's prev-hash field must match.
func readRecord(r io.Reader, expectedPrev [hashSize]byte) (walRecord, int64, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return walRecord{}, 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return walRecord{}, 0, errTornRecord
		}
		return walRecord{}, 0, fmt.Errorf("wal: read header: %w", err)
	}

	if magic := binary.LittleEndian.Uint32(header[0:4]); magic != walMagic {
		return walRecord{}, 0, fmt.Errorf("%w: bad magic 0x%08x", ErrCorruptWAL, magic)
	}
	length := binary.LittleEndian.Uint64(header[4:12])
	if length > maxRecordPayload {
		return walRecord{}, 0, fmt.Errorf("%w: payload length %d exceeds max", ErrCorruptWAL, length)
	}

	var prev [hashSize]byte
	copy(prev[:], header[12:])
	if prev != expectedPrev {
		return walRecord{}, 0, fmt.Errorf("%w: prev-hash mismatch (chain broken)", ErrCorruptWAL)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return walRecord{}, 0, errTornRecord
		}
		return walRecord{}, 0, fmt.Errorf("wal: read payload: %w", err)
	}

	stored := make([]byte, hashSize)
	if _, err := io.ReadFull(r, stored); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return walRecord{}, 0, errTornRecord
		}
		return walRecord{}, 0, fmt.Errorf("wal: read self-hash: %w", err)
	}

	var self [hashSize]byte
	computeRecordHash(self[:0], header, payload)
	if !hashEqual(self[:], stored) {
		return walRecord{}, 0, fmt.Errorf("%w: self-hash mismatch (record altered)", ErrCorruptWAL)
	}

	total := int64(headerSize + len(payload) + hashSize)
	return walRecord{payload: payload, selfHash: self}, total, nil
}

func computeRecordHash(dst []byte, header, payload []byte) {
	var h hash.Hash = sha256.New()
	h.Write(header)
	h.Write(payload)
	h.Sum(dst)
}

// hashEqual is a length-checked byte comparison. The WAL is integrity-protected,
// not secret, so constant-time comparison is unnecessary here.
func hashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
