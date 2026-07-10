// Package grpc wires the local admin API: a gRPC server bound to a Unix socket by
// default (local-only, per the secure-by-default posture in docs/security.md), with
// optional mTLS-protected TCP. It owns the interceptor chain and server lifecycle.
package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	"github.com/prateekpurohit13/frien/internal/middleware"
	frienv1 "github.com/prateekpurohit13/frien/pkg/proto/v1"
)

// Options configures the admin gRPC server. Defaults come from config.AdminAPI.
type Options struct {
	SocketPath   string      // Unix socket path; primary, local-only admin surface
	SocketMode   os.FileMode // permission bits applied to the socket (e.g. 0o660)
	MaxRecvBytes int         // max inbound message size
	TCPListen    string      // optional "host:port"; requires TLS
	TLSCert      string      // PEM cert for the TCP listener
	TLSKey       string      // PEM key for the TCP listener
}

// Server is the admin gRPC server and its listeners.
type Server struct {
	grpc      *grpc.Server
	listeners []net.Listener
	socket    string
	log       zerolog.Logger
}

// NewServer builds the gRPC server with the interceptor chain and registers the
// admin service. Listeners are created here so that binding failures (a busy port,
// an unwritable socket directory) surface at bootstrap rather than asynchronously.
func NewServer(opts Options, admin *AdminService, log zerolog.Logger) (*Server, error) {
	if opts.SocketPath == "" && opts.TCPListen == "" {
		return nil, fmt.Errorf("grpc: no admin listener configured (socket or tcp required)")
	}

	serverOpts := []grpc.ServerOption{
		middleware.Chain(log),
	}
	if opts.MaxRecvBytes > 0 {
		serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(opts.MaxRecvBytes))
	}

	gs := grpc.NewServer(serverOpts...)
	frienv1.RegisterAdminServiceServer(gs, admin)

	s := &Server{grpc: gs, socket: opts.SocketPath, log: log}

	if opts.SocketPath != "" {
		ln, err := listenUnix(opts.SocketPath, opts.SocketMode)
		if err != nil {
			return nil, err
		}
		s.listeners = append(s.listeners, ln)
	}

	if opts.TCPListen != "" {
		ln, err := listenTLS(opts)
		if err != nil {
			s.closeListeners()
			return nil, err
		}
		s.listeners = append(s.listeners, ln)
	}

	return s, nil
}

// listenUnix creates a Unix-domain listener, clearing any stale socket left by a
// previous unclean shutdown, and tightens the socket permissions to local access.
func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	// Remove a stale socket only if it is in fact a socket — never clobber a
	// regular file that happens to share the path (avoids destroying real data).
	if fi, err := os.Stat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("grpc: admin socket path %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("grpc: removing stale socket %s: %w", path, err)
		}
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("grpc: listening on unix socket %s: %w", path, err)
	}
	if mode == 0 {
		mode = 0o660
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("grpc: chmod socket %s: %w", path, err)
	}
	return ln, nil
}

// listenTLS creates a TCP listener wrapped in mTLS-capable TLS credentials. TLS is
// mandatory for the TCP surface; an unencrypted admin port is never allowed.
func listenTLS(opts Options) (net.Listener, error) {
	if opts.TLSCert == "" || opts.TLSKey == "" {
		return nil, fmt.Errorf("grpc: tcp_listen requires tls_cert and tls_key")
	}
	cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("grpc: loading admin TLS keypair: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := net.Listen("tcp", opts.TCPListen)
	if err != nil {
		return nil, fmt.Errorf("grpc: listening on %s: %w", opts.TCPListen, err)
	}
	return tls.NewListener(ln, tlsCfg), nil
}

// Start begins serving on all listeners. It is non-blocking: each listener runs in
// its own goroutine. A listener returning grpc.ErrServerStopped during shutdown is
// expected and not logged as an error.
func (s *Server) Start() {
	for _, ln := range s.listeners {
		ln := ln
		s.log.Info().Str("addr", ln.Addr().String()).Str("network", ln.Addr().Network()).Msg("admin api listening")
		go func() {
			if err := s.grpc.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				s.log.Error().Err(err).Str("addr", ln.Addr().String()).Msg("admin api serve stopped")
			}
		}()
	}
}

// Stop gracefully drains in-flight RPCs, falling back to a hard stop if ctx expires
// before the drain completes. The Unix socket file is removed afterward.
func (s *Server) Stop(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		s.log.Warn().Msg("admin api graceful stop timed out; forcing stop")
		s.grpc.Stop()
	}

	if s.socket != "" {
		if err := os.Remove(s.socket); err != nil && !os.IsNotExist(err) {
			s.log.Warn().Err(err).Str("socket", s.socket).Msg("removing admin socket")
		}
	}
}

func (s *Server) closeListeners() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
}
