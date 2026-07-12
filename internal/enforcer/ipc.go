package enforcer

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"time"

	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// This file defines the local IPC between the unprivileged friend daemon and
// the privileged frien-enforcer helper. The two run as separate processes so a
// compromise of the large daemon does not hand an attacker CAP_NET_ADMIN: only
// the small enforcer holds it, and the enforcer owns rule lifetime and the
// dead-man's switch independently of the daemon.
//
// The wire format is deliberately minimal — length-prefixed JSON, one
// request/response per exchange over a Unix-domain socket — rather than gRPC:
// the privileged component's parsing surface should be as small as auditable.

// IPC request kinds.
const (
	KindHeartbeat = "heartbeat"
	KindApply     = "apply"
	KindRollback  = "rollback"
	KindFlush     = "flush"
	KindList      = "list"
	KindSetMode   = "set_mode"
	KindGetMode   = "get_mode"
)

// Request is a single command from the daemon to the enforcer.
type Request struct {
	Kind     string                       `json:"kind"`
	Decision *frienv1.EnforcementDecision `json:"decision,omitempty"` // KindApply
	Token    string                       `json:"token,omitempty"`    // KindRollback
	Adapter  string                       `json:"adapter,omitempty"`  // KindSetMode/GetMode
	Mode     string                       `json:"mode,omitempty"`     // KindSetMode
	Reason   string                       `json:"reason,omitempty"`   // KindFlush/Rollback
}

// Response is the enforcer's reply.
type Response struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Applied bool         `json:"applied,omitempty"` // KindApply
	Status  string       `json:"status,omitempty"`  // KindRollback outcome
	Count   int          `json:"count,omitempty"`   // KindFlush rules removed
	Mode    string       `json:"mode,omitempty"`    // KindGetMode / KindSetMode previous
	Rules   []ActiveRule `json:"rules,omitempty"`   // KindList
}

// maxFrameBytes bounds a single IPC frame so a corrupt or hostile length prefix
// cannot force an unbounded allocation in the privileged process.
const maxFrameBytes = 4 << 20 // 4 MiB

// writeFrame writes a length-prefixed JSON value.
func writeFrame(w io.Writer, v interface{}) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("enforcer ipc: frame too large (%d bytes)", len(payload))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// readFrame reads a length-prefixed JSON value into v.
func readFrame(r *bufio.Reader, v interface{}) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameBytes {
		return fmt.Errorf("enforcer ipc: incoming frame too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// dialTimeout is the default per-request timeout for the daemon-side client.
const dialTimeout = 5 * time.Second
