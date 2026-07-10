// Command friend is the main frien daemon: an unprivileged process that runs the
// mesh, policy, storage, local admin API, detectors, and observability. It never
// owns firewall-rule lifetime (that is the separate frien-enforcer).
//
// This file is bootstrap only — it loads config, wires subsystems in dependency
// order, and manages startup/shutdown. All behavior lives in internal packages.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/config"
	"github.com/prateekpurohit13/frien/internal/crdt"
	"github.com/prateekpurohit13/frien/internal/gossip"
	admingrpc "github.com/prateekpurohit13/frien/internal/grpc"
	"github.com/prateekpurohit13/frien/internal/health"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/logger"
	"github.com/prateekpurohit13/frien/internal/membership"
	"github.com/prateekpurohit13/frien/internal/oplog"
	"github.com/prateekpurohit13/frien/internal/scope"
	"github.com/prateekpurohit13/frien/internal/storage"
	"github.com/prateekpurohit13/frien/internal/transport"
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

	// ── 5b. Bring up the peer mesh (transport + membership + CRDT state) ───────
	meshCtx, meshCancel := context.WithCancel(context.Background())
	defer meshCancel()
	mesh, clock, err := buildMesh(meshCtx, cfg, id, store, log)
	if err != nil {
		return fmt.Errorf("starting mesh: %w", err)
	}
	go persistHLCLoop(meshCtx, store, clock, log)

	// ── 6. Start health probes (liveness/readiness) ───────────────────────────
	checker := health.New()
	healthSrv, healthLn, err := health.NewServer(cfg.Observability.HealthBind, checker, log)
	if err != nil {
		return fmt.Errorf("starting health server: %w", err)
	}
	go healthSrv.Serve(healthLn)

	// ── 7. Start the local admin gRPC API ─────────────────────────────────────
	statusSrc := newStatusSource(cfg, id, store, mesh, startTime)
	admin := admingrpc.NewAdminService(statusSrc, cfg.AdminAPI.ReadOnly, log)
	admin.SetPeerSource(peerAdapter{mesh})
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
	meshCancel() // stop probes, gossip, and the listener
	if herr := healthSrv.Shutdown(shutdownCtx); herr != nil && !errors.Is(herr, context.Canceled) {
		log.Warn().Err(herr).Msg("health server shutdown")
	}
	if perr := persistHLC(store, clock); perr != nil {
		log.Warn().Err(perr).Msg("persisting HLC on shutdown")
	}
	if _, err := ops.AppendLifecycle("stop"); err != nil {
		log.Warn().Err(err).Msg("recording node stop")
	}

	log.Info().Msg("friend daemon stopped")
	return nil
}

// buildMesh constructs and starts the peer mesh: the QUIC transport, the Hybrid
// Logical Clock (seeded from persisted state so it never regresses), the CRDT op
// set, the scope router, and the gossip engine. It returns the running engine and
// the clock (for periodic persistence).
func buildMesh(ctx context.Context, cfg *config.Config, id *identity.Identity, store *storage.Store, log zerolog.Logger) (*gossip.Engine, *crdt.Clock, error) {
	caPool, err := identity.LoadCACertPool(cfg.Identity.CACertPath)
	if err != nil {
		return nil, nil, err
	}

	skew := parseDuration(cfg.Transport.ClockSkewWindow, 10*time.Second)
	tr, err := transport.New(id, caPool, transport.Config{
		BindAddr:        net.JoinHostPort(cfg.Transport.PeerBind, strconv.Itoa(cfg.Transport.PeerPort)),
		MaxMessageBytes: cfg.Transport.MaxMessageBytes,
		DialTimeout:     parseDuration(cfg.Transport.DialTimeout, 5*time.Second),
		IdleTimeout:     parseDuration(cfg.Transport.SessionIdleTimeout, 30*time.Second),
		KEM:             kemMode(cfg.Identity.PQCKem),
	}, nil, log)
	if err != nil {
		return nil, nil, err
	}

	clockOpts := []crdt.ClockOption{crdt.WithMaxDrift(skew)}
	if raw, gerr := store.MetaGet(storage.MetaKeyHLC); gerr == nil && len(raw) > 0 {
		if ts, perr := crdt.ParseTimestamp(string(raw)); perr == nil {
			clockOpts = append(clockOpts, crdt.WithInitial(ts))
		}
	}
	clock := crdt.NewClock(cfg.Node.ID, clockOpts...)

	seeds := make([]string, 0, len(cfg.Seeds))
	for _, s := range cfg.Seeds {
		seeds = append(seeds, s.Address)
	}

	var operatorKey ed25519.PublicKey
	if cfg.Identity.OperatorRootCert != "" {
		operatorKey, err = identity.LoadOperatorPublicKey(cfg.Identity.OperatorRootCert)
		if err != nil {
			return nil, nil, err
		}
	}

	eng := gossip.New(gossip.Config{
		NodeID:            cfg.Node.ID,
		Zone:              cfg.Node.Zone,
		LocalAddr:         net.JoinHostPort(advertiseHost(cfg.Transport.PeerBind), strconv.Itoa(cfg.Transport.PeerPort)),
		Seeds:             seeds,
		SubscribedScopes:  []string{"fleet", "zone:" + cfg.Node.Zone},
		SkewWindow:        skew,
		ProbeInterval:     parseDuration(cfg.Membership.ProbeInterval, time.Second),
		ProbeTimeout:      parseDuration(cfg.Membership.ProbeTimeout, 500*time.Millisecond),
		SuspectMultiplier: cfg.Membership.SuspectMultiplier,
		IndirectProbes:    cfg.Membership.MaxGossipNodes,
		OperatorPublicKey: operatorKey,
	}, id, clock, crdt.NewOpSet(), scope.NewRouter(cfg.Node.Zone), tr, log)

	if err := eng.Start(ctx); err != nil {
		return nil, nil, err
	}
	log.Info().Str("peer_bind", cfg.Transport.PeerBind).Int("peer_port", cfg.Transport.PeerPort).Msg("peer mesh started")
	return eng, clock, nil
}

// peerAdapter exposes the gossip engine's roster to the admin ListPeers RPC.
type peerAdapter struct{ eng *gossip.Engine }

func (p peerAdapter) Peers() []admingrpc.PeerInfo {
	members := p.eng.Peers()
	out := make([]admingrpc.PeerInfo, 0, len(members))
	for _, m := range members {
		out = append(out, admingrpc.PeerInfo{
			NodeID:    m.NodeID,
			Status:    m.State.String(),
			Addresses: m.Addresses,
			LastSeen:  m.StateChange,
		})
	}
	return out
}

// persistHLCLoop periodically saves the Hybrid Logical Clock so a restart resumes
// without the clock regressing.
func persistHLCLoop(ctx context.Context, store *storage.Store, clock *crdt.Clock, log zerolog.Logger) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := persistHLC(store, clock); err != nil {
				log.Warn().Err(err).Msg("persisting HLC")
			}
		}
	}
}

func persistHLC(store *storage.Store, clock *crdt.Clock) error {
	return store.MetaPut(storage.MetaKeyHLC, []byte(clock.Snapshot().String()))
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return fallback
}

func kemMode(s string) transport.KEMMode {
	if s == "classical" {
		return transport.KEMClassical
	}
	return transport.KEMHybridPQC
}

// advertiseHost picks the address peers should dial back. A wildcard bind is not
// dialable, so in that (single-host dev) case we advertise loopback; multi-host
// deployments set transport.peer_bind to the node's reachable address.
func advertiseHost(bind string) string {
	if bind == "" || bind == "0.0.0.0" || bind == "::" {
		return "127.0.0.1"
	}
	return bind
}

// newStatusSource builds the live status closure the admin API reports. It reads
// from the daemon's subsystems on each call so values like WAL size stay current.
func newStatusSource(cfg *config.Config, id *identity.Identity, store *storage.Store, mesh *gossip.Engine, startTime time.Time) admingrpc.StatusSource {
	return admingrpc.StatusFunc(func() admingrpc.StatusInfo {
		return admingrpc.StatusInfo{
			NodeID:       cfg.Node.ID,
			EnforceMode:  cfg.Policy.EnforceMode,
			PeerCount:    livePeerCount(mesh),
			CertExpiry:   id.NotAfter(),
			WALSizeBytes: store.WAL.Size(),
			StartedAt:    startTime,
		}
	})
}

// livePeerCount counts peers currently considered alive (excluding this node).
func livePeerCount(mesh *gossip.Engine) int64 {
	var n int64
	for _, m := range mesh.Peers() {
		if m.State == membership.StateAlive {
			n++
		}
	}
	return n
}
