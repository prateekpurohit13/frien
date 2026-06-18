// Command friend is the main frien daemon: an unprivileged process that runs the
// mesh, policy, storage, local admin API, detectors, and observability. It never
// owns firewall-rule lifetime (that is the separate frien-enforcer).
//
// This file is bootstrap only — it loads config, wires subsystems in dependency
// order, and manages startup/shutdown. All behavior lives in internal packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prateekpurohit13/frien/internal/config"
	admingrpc "github.com/prateekpurohit13/frien/internal/grpc"
	"github.com/prateekpurohit13/frien/internal/health"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/logger"
	"github.com/prateekpurohit13/frien/internal/oplog"
	"github.com/prateekpurohit13/frien/internal/storage"
	"github.com/prateekpurohit13/frien/internal/version"
)

func main() {
	configPath := flag.String("config", "", "path to config file (default: /etc/frien/config.yaml or ./frien.yaml)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("friend %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		return
	}

	if err := run(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

// run performs the full daemon lifecycle and returns the first fatal error. It
// blocks until a shutdown signal is received, then tears subsystems down in
// reverse dependency order. Returning (rather than calling os.Exit) keeps cleanup
// deferred and testable.
func run(configPath string) error {
	startTime := time.Now()

	// ── 1. Load and validate configuration ───────────────────────────────────
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// ── 2. Initialize logger ─────────────────────────────────────────────────
	log := logger.Init(cfg.Observability.LogLevel, cfg.Observability.LogFormat)
	log.Info().
		Str("node_id", cfg.Node.ID).
		Str("zone", cfg.Node.Zone).
		Str("role", cfg.Node.Role).
		Str("enforce_mode", cfg.Policy.EnforceMode).
		Str("version", version.SoftwareVersion).
		Uint32("proto_version", version.ProtoVersion).
		Msg("friend daemon starting")

	// ── 3. Open local storage (WAL + bbolt + snapshots) ───────────────────────
	store, err := storage.Open(storage.Options{
		WALDir:      cfg.Storage.WALDir,
		DBPath:      cfg.Storage.DBPath,
		SnapshotDir: cfg.Storage.SnapshotDir,
		WALSync:     cfg.Storage.WALSync,
	}, log)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			log.Error().Err(cerr).Msg("closing storage")
		}
	}()

	// ── 4. Load node identity and check certificate validity ──────────────────
	id, err := identity.Load(identity.LoadOptions{
		CertPath:       cfg.Identity.CertPath,
		KeyPath:        cfg.Identity.KeyPath,
		ExpectedNodeID: cfg.Node.ID,
	})
	if err != nil {
		return err
	}
	if id.IsExpired() {
		// A node with an expired certificate cannot authenticate to peers; refuse
		// to start rather than join the mesh with an invalid identity.
		return fmt.Errorf("node certificate is expired (not_after=%s)", id.NotAfter().UTC().Format(time.RFC3339))
	}
	if threshold, perr := time.ParseDuration(cfg.Identity.RenewalThreshold); perr == nil && id.NeedsRenewal(threshold) {
		log.Warn().
			Str("cert_not_after", id.NotAfter().UTC().Format(time.RFC3339)).
			Str("renewal_threshold", cfg.Identity.RenewalThreshold).
			Msg("node certificate is near expiry; renewal needed (auto-renewal arrives with CA integration)")
	}
	log.Info().
		Str("cert_fingerprint", id.Fingerprint).
		Str("cert_not_after", id.NotAfter().UTC().Format(time.RFC3339)).
		Str("key_id", id.Signer().PublicKeyID()).
		Msg("identity loaded")

	// ── 5. Recover the operation log and record this node's start ──────────────
	ops := oplog.New(store.WAL, id)
	recovered, err := ops.Recover()
	if err != nil {
		// A verification failure here means on-disk history is corrupt or tampered.
		// Recovery past that is an explicit operator decision, not a silent default.
		return fmt.Errorf("operation log recovery failed: %w", err)
	}
	log.Info().
		Int("records_recovered", recovered.Records).
		Uint64("last_seq", recovered.LastSeq).
		Int64("wal_size_bytes", store.WAL.Size()).
		Msg("operation log recovered")

	if _, err := ops.AppendLifecycle("start"); err != nil {
		return fmt.Errorf("recording node start: %w", err)
	}

	// ── 6. Start health probes (liveness/readiness) ───────────────────────────
	checker := health.New()
	healthSrv, healthLn, err := health.NewServer(cfg.Observability.HealthBind, checker, log)
	if err != nil {
		return fmt.Errorf("starting health server: %w", err)
	}
	go healthSrv.Serve(healthLn)

	// ── 7. Start the local admin gRPC API ─────────────────────────────────────
	statusSrc := newStatusSource(cfg, id, store, startTime)
	admin := admingrpc.NewAdminService(statusSrc, cfg.AdminAPI.ReadOnly, log)
	adminSrv, err := admingrpc.NewServer(admingrpc.Options{
		SocketPath:   cfg.AdminAPI.Socket,
		SocketMode:   0o660,
		MaxRecvBytes: cfg.AdminAPI.MaxRecvMessageBytes,
		TCPListen:    cfg.AdminAPI.TCPListen,
		TLSCert:      cfg.AdminAPI.TLSCert,
		TLSKey:       cfg.AdminAPI.TLSKey,
	}, admin, log)
	if err != nil {
		return fmt.Errorf("starting admin api: %w", err)
	}
	adminSrv.Start()

	// ── 8. Ready to serve ──────────────────────────────────────────────────────
	checker.SetReady(true)
	log.Info().Msg("friend daemon ready")

	// ── 9. Wait for a shutdown signal ──────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("shutdown signal received")

	// ── 10. Graceful shutdown (reverse dependency order) ───────────────────────
	checker.SetReady(false) // drain: orchestrators stop routing here first
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	adminSrv.Stop(shutdownCtx)
	if herr := healthSrv.Shutdown(shutdownCtx); herr != nil && !errors.Is(herr, context.Canceled) {
		log.Warn().Err(herr).Msg("health server shutdown")
	}
	if _, err := ops.AppendLifecycle("stop"); err != nil {
		log.Warn().Err(err).Msg("recording node stop")
	}

	log.Info().Msg("friend daemon stopped")
	return nil
}

// newStatusSource builds the live status closure the admin API reports. It reads
// from the daemon's subsystems on each call so values like WAL size stay current.
func newStatusSource(cfg *config.Config, id *identity.Identity, store *storage.Store, startTime time.Time) admingrpc.StatusSource {
	return admingrpc.StatusFunc(func() admingrpc.StatusInfo {
		return admingrpc.StatusInfo{
			NodeID:       cfg.Node.ID,
			EnforceMode:  cfg.Policy.EnforceMode,
			PeerCount:    0, // membership (peer count) arrives in Phase 2
			CertExpiry:   id.NotAfter(),
			WALSizeBytes: store.WAL.Size(),
			StartedAt:    startTime,
		}
	})
}
