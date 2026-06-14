package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prateekpurohit13/frien/internal/config"
	"github.com/prateekpurohit13/frien/internal/logger"
	"github.com/prateekpurohit13/frien/internal/version"
)

func main() {
	configPath := flag.String("config", "", "path to config file (default: /etc/frien/config.yaml or ./frien.yaml)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("friend %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		os.Exit(0)
	}

	// ── 1. Load and validate configuration ───────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}

	// ── 2. Initialize logger ─────────────────────────────────────────────────
	log := logger.Init(cfg.Observability.LogLevel, cfg.Observability.LogFormat)
	log.Info().
		Str("node_id", cfg.Node.ID).
		Str("zone", cfg.Node.Zone).
		Str("role", cfg.Node.Role).
		Str("version", version.SoftwareVersion).
		Uint32("proto_version", version.ProtoVersion).
		Msg("friend daemon starting")

	// ── 3. Set up root context with cancellation ──────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── 4. (Placeholder) Initialize storage ──────────────────────────────────
	// TODO(phase1): init WAL and bbolt
	log.Info().Str("wal_dir", cfg.Storage.WALDir).Msg("storage: init placeholder")

	// ── 5. (Placeholder) Initialize node identity ─────────────────────────────
	// TODO(phase1): load cert, check expiry, schedule renewal
	log.Info().Str("cert_path", cfg.Identity.CertPath).Msg("identity: init placeholder")

	// ── 6. (Placeholder) Initialize gRPC server ───────────────────────────────
	// TODO(phase1): set up gRPC with interceptor chain, register AdminService
	log.Info().Str("socket", cfg.AdminAPI.Socket).Msg("admin api: init placeholder")

	// ── 7. Wait for shutdown signal ───────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case <-ctx.Done():
		log.Info().Msg("context cancelled")
	}

	// ── 8. Graceful shutdown ──────────────────────────────────────────────────
	log.Info().Msg("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// TODO(phase1): stop gRPC server, drain WAL, close bbolt
	_ = shutdownCtx

	log.Info().Msg("friend daemon stopped")
}
