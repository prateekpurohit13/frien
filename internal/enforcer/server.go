package enforcer

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

// Server is the privileged frien-enforcer's IPC endpoint. It exposes the
// Enforcer over a Unix socket to the friend daemon and treats every request as
// an implicit heartbeat (re-arming the dead-man's switch), so a daemon that is
// actively driving enforcement inherently keeps the switch armed, and a daemon
// that has gone silent trips it.
type Server struct {
	e        *Enforcer
	dm       *Deadman // optional; beaten on every request and on explicit heartbeats
	log      zerolog.Logger
	socket   string
	listener net.Listener
}

// NewServer builds the IPC server around an Enforcer.
func NewServer(e *Enforcer, dm *Deadman, socketPath string, log zerolog.Logger) *Server {
	return &Server{e: e, dm: dm, log: log, socket: socketPath}
}

// Listen binds the Unix socket, removing a stale one first (the enforcer is the
// sole owner of this path, as with the admin socket).
func (s *Server) Listen() error {
	if s.socket == "" {
		return errors.New("enforcer: empty socket path")
	}
	if err := removeStaleSocket(s.socket); err != nil {
		return err
	}
	ln, err := net.Listen("unix", s.socket)
	if err != nil {
		return err
	}
	// Restrict to the owner: only the daemon's user should reach the privileged
	// helper.
	_ = os.Chmod(s.socket, 0o600)
	s.listener = ln
	return nil
}

// Serve accepts connections until ctx is cancelled. Each connection carries one
// request and one response.
func (s *Server) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down
			}
			s.log.Warn().Err(err).Msg("enforcer: accept error")
			continue
		}
		s.handle(conn)
	}
}

// Addr returns the bound socket path (useful in tests where the caller wants
// the resolved path).
func (s *Server) Addr() string { return s.socket }

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	var req Request
	if err := readFrame(bufio.NewReader(conn), &req); err != nil {
		_ = writeFrame(conn, Response{OK: false, Error: "bad request: " + err.Error()})
		return
	}

	// Every request is a liveness signal from the daemon.
	if s.dm != nil {
		s.dm.Beat()
	}

	resp := s.dispatch(req)
	if err := writeFrame(conn, resp); err != nil {
		s.log.Warn().Err(err).Str("kind", req.Kind).Msg("enforcer: writing response")
	}
}

func (s *Server) dispatch(req Request) Response {
	switch req.Kind {
	case KindHeartbeat:
		return Response{OK: true}

	case KindApply:
		applied, err := s.e.Apply(req.Decision)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Applied: applied}

	case KindRollback:
		status, err := s.e.Rollback(req.Token)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Status: status}

	case KindFlush:
		n := s.e.FlushAll(req.Reason)
		return Response{OK: true, Count: n}

	case KindList:
		rules, err := listAll(s.e)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Rules: rules}

	case KindSetMode:
		prev, err := s.e.SetMode(req.Adapter, req.Mode)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Mode: prev}

	case KindGetMode:
		return Response{OK: true, Mode: s.e.Mode(req.Adapter)}

	default:
		return Response{OK: false, Error: "unknown request kind: " + req.Kind}
	}
}

// removeStaleSocket deletes a leftover socket file from a previous run so
// Listen does not fail with "address already in use".
func removeStaleSocket(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Only remove socket files, never a regular file the operator may have put
	// there by mistake.
	if info.Mode()&os.ModeSocket == 0 && !strings.HasSuffix(path, ".sock") {
		return errors.New("enforcer: refusing to remove non-socket file at " + path)
	}
	return os.Remove(path)
}
