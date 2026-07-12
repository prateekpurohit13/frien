// Command frien-enforcer is frien's small, privileged enforcement helper. It is
// the ONLY component that holds CAP_NET_ADMIN: the large friend daemon runs
// unprivileged and forwards already-policy-approved decisions here over a local
// Unix socket. Keeping enforcement in a separate, minimal process means a
// compromise of the daemon does not directly grant firewall control, and this
// process independently owns rule lifetime — kernel-native timeouts plus a
// dead-man's switch that flushes frien's rules if the daemon stops heartbeating.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/prateekpurohit13/frien/internal/config"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/logger"
	"github.com/prateekpurohit13/frien/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("frien-enforcer %s (proto v%d)\n", version.SoftwareVersion, version.ProtoVersion)
		return
	}
	configPath := ""
	if len(os.Args) > 2 && os.Args[1] == "--config" {
		configPath = os.Args[2]
	}
	if err := run(configPath); err != nil {
		fmt.Fprintln(os.Stderr, "frien-enforcer:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	log := logger.Init(cfg.Observability.LogLevel, cfg.Observability.LogFormat).With().Str("component", "frien-enforcer").Logger()

	socket := cfg.Enforcement.EnforcerSocket
	if socket == "" {
		return fmt.Errorf("enforcement.enforcer_socket must be set to run the separate enforcer process")
	}

	// The enforcer owns its own rollback-token store — it, not the daemon, is the
	// authority on what rules exist and must survive a daemon crash.
	dbPath := filepath.Join(filepath.Dir(cfg.Storage.DBPath), "enforcer.db")
	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return fmt.Errorf("opening enforcer db %s: %w", dbPath, err)
	}
	defer db.Close()

	rb, err := enforcer.NewRollbackStore(db)
	if err != nil {
		return err
	}
	e := enforcer.New(rb, nil, log)

	// Select the firewall backend. A real nftables backend requires Linux and
	// CAP_NET_ADMIN; elsewhere we fall back to the self-expiring in-memory
	// backend so the process still runs (observe/dry-run).
	var adapter enforcer.Adapter
	if cfg.Enforcement.NFTables.Enabled {
		a, aerr := enforcer.NewNFTablesAdapter(enforcer.NFTablesOptions{
			Table:      cfg.Enforcement.NFTables.Table,
			ChainInput: cfg.Enforcement.NFTables.ChainInput,
		}, log)
		if aerr != nil {
			log.Warn().Err(aerr).Msg("nftables adapter unavailable; using in-memory backend")
			adapter = enforcer.NewMemAdapter("nftables", nil)
		} else {
			adapter = a
		}
	} else {
		adapter = enforcer.NewMemAdapter("nftables", nil)
	}
	// Start in observe mode; the daemon promotes via SetMode over the socket. A
	// freshly (re)started enforcer never enforces until told to.
	e.Register(adapter, enforcer.ModeObserve)

	if closed, rerr := e.Reconcile(); rerr != nil {
		log.Warn().Err(rerr).Msg("reconcile error on start")
	} else if closed > 0 {
		log.Info().Int("tokens_closed", closed).Msg("reconciled stale rollback tokens on start")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Dead-man's switch: if the daemon stops heartbeating (every IPC request is
	// a heartbeat), flush frien-managed rules. Cleanup fails open.
	dm := enforcer.NewDeadman(parseDeadman(cfg.Enforcement.NFTables.DeadmanSwitchTimeout), func() {
		e.FlushAll("dead-man's switch: no daemon heartbeat")
	}, log)
	go dm.Run(ctx)

	srv := enforcer.NewServer(e, dm, socket, log)
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("binding enforcer socket %s: %w", socket, err)
	}
	log.Info().Str("socket", socket).Str("adapter", adapter.Name()).
		Bool("linux", runtime.GOOS == "linux").Msg("frien-enforcer ready")

	go srv.Serve(ctx)
	<-ctx.Done()
	log.Info().Msg("frien-enforcer shutting down")
	return nil
}

func parseDeadman(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return 30 * time.Second
}
