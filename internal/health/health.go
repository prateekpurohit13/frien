// Package health exposes Kubernetes-style liveness and readiness probes over a
// local HTTP endpoint. Liveness reports that the process is running; readiness
// reports that bootstrap has completed and the node can serve. Keeping the two
// distinct lets an orchestrator restart a hung process (liveness) without routing
// traffic to a node that is still initializing (readiness).
package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// Checker holds the readiness state. Liveness has no state: if the HTTP server
// can answer, the process is alive.
type Checker struct {
	ready atomic.Bool
}

// New returns a Checker that is not-ready until SetReady(true) is called.
func New() *Checker { return &Checker{} }

// SetReady flips the readiness state. The daemon calls SetReady(true) only after
// every subsystem has initialized, and SetReady(false) at the start of shutdown
// so load balancers drain the node before it stops.
func (c *Checker) SetReady(ready bool) { c.ready.Store(ready) }

// Ready reports the current readiness state.
func (c *Checker) Ready() bool { return c.ready.Load() }

// Handler returns an http.Handler serving:
//
//	GET /healthz — liveness;  always 200 while the server is up
//	GET /readyz  — readiness; 200 when ready, 503 otherwise
func (c *Checker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writePlain(w, http.StatusOK, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if c.Ready() {
			writePlain(w, http.StatusOK, "ready")
			return
		}
		writePlain(w, http.StatusServiceUnavailable, "not ready")
	})
	return mux
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

// Server is the health HTTP server bound to a local address.
type Server struct {
	checker *Checker
	http    *http.Server
	log     zerolog.Logger
}

// NewServer binds a listener on addr (e.g. "127.0.0.1:9110") and prepares to serve
// the probes. Binding happens here, before Start, so a bad address fails fast at
// bootstrap rather than asynchronously. The endpoint is intended to be local-only.
func NewServer(addr string, checker *Checker, log zerolog.Logger) (*Server, net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	s := &Server{
		checker: checker,
		log:     log,
		http: &http.Server{
			Handler:           checker.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
	return s, ln, nil
}

// Serve runs the HTTP server on ln until Shutdown is called. It is intended to be
// run in its own goroutine; a clean shutdown returns nil.
func (s *Server) Serve(ln net.Listener) {
	if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error().Err(err).Msg("health server stopped unexpectedly")
	}
}

// Shutdown gracefully stops the health server within ctx's deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}
