package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/rs/zerolog"

	"github.com/prateekpurohit13/frien/internal/audit"
	"github.com/prateekpurohit13/frien/internal/config"
	"github.com/prateekpurohit13/frien/internal/coordinator"
	"github.com/prateekpurohit13/frien/internal/enforcer"
	"github.com/prateekpurohit13/frien/internal/gossip"
	"github.com/prateekpurohit13/frien/internal/identity"
	"github.com/prateekpurohit13/frien/internal/policy"
	"github.com/prateekpurohit13/frien/internal/storage"
)

// enforcementDeps is what run() needs to serve the Phase 5 admin RPCs.
type enforcementDeps struct {
	coord    *coordinator.Coordinator
	client   enforcer.Client
	auditLog *audit.Log
	adapters []string
}

// buildEnforcement wires the policy/enforcement subsystem: the enforcement
// client (a separate privileged frien-enforcer over its socket when configured,
// else an in-process enforcer), the audit log, the decision coordinator, the
// active operator-signed policy (verified before it is trusted), and the
// heartbeat + sweep loops. Enforcement stays observe-only until the operator
// both promotes an adapter and a verified policy is loaded — the fail-safe
// default.
func buildEnforcement(ctx context.Context, cfg *config.Config, id *identity.Identity, store *storage.Store, mesh *gossip.Engine, log zerolog.Logger) (*enforcementDeps, error) {
	auditLog, err := audit.NewLog(store.DB, nil)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}

	client, err := buildEnforcementClient(ctx, cfg, store, log)
	if err != nil {
		return nil, err
	}

	resolver := &meshResolver{mesh: mesh}
	coord := coordinator.New(coordinator.Deps{
		NodeID:    cfg.Node.ID,
		Client:    client,
		Audit:     auditLog,
		State:     mesh,
		Publisher: mesh,
		Trust:     resolver,
		Partition: resolver,
		Log:       log,
	})

	if err := loadActivePolicy(cfg, coord, log); err != nil {
		return nil, err
	}

	// Heartbeat the (possibly remote) enforcer so its dead-man's switch stays
	// armed, and periodically re-evaluate present threats so a standing threat
	// that has since gathered quorum gets enforced.
	go heartbeatLoop(ctx, client, parseDuration(cfg.Enforcement.HeartbeatInterval, 10*time.Second), log)
	go sweepLoop(ctx, coord, parseDuration(cfg.Enforcement.SweepInterval, 15*time.Second), log)

	return &enforcementDeps{coord: coord, client: client, auditLog: auditLog, adapters: []string{"nftables"}}, nil
}

// buildEnforcementClient returns a socket client to a separate frien-enforcer
// when one is configured, else an in-process enforcer. The in-process path
// selects a real nftables backend on Linux (when enabled) and otherwise a
// self-expiring in-memory backend suitable for observe/dry-run.
func buildEnforcementClient(ctx context.Context, cfg *config.Config, store *storage.Store, log zerolog.Logger) (enforcer.Client, error) {
	if sock := cfg.Enforcement.EnforcerSocket; sock != "" {
		log.Info().Str("socket", sock).Msg("enforcement: using separate privileged frien-enforcer")
		return enforcer.NewSocketClient(sock), nil
	}

	rb, err := enforcer.NewRollbackStore(store.DB)
	if err != nil {
		return nil, err
	}
	e := enforcer.New(rb, nil, log)
	e.SetRateLimit(cfg.Policy.MaxNewRulesPerMinute)

	var adapter enforcer.Adapter
	if cfg.Enforcement.NFTables.Enabled {
		a, aerr := enforcer.NewNFTablesAdapter(enforcer.NFTablesOptions{
			Table:        cfg.Enforcement.NFTables.Table,
			ChainInput:   cfg.Enforcement.NFTables.ChainInput,
			ChainForward: cfg.Enforcement.NFTables.ChainForward,
			DenyAction:   cfg.Enforcement.NFTables.DenyAction,
		}, log)
		if aerr != nil {
			log.Warn().Err(aerr).Msg("enforcement: nftables adapter unavailable; using in-memory observe/dry-run backend")
			adapter = enforcer.NewMemAdapter("nftables", nil)
		} else {
			adapter = a
		}
	} else {
		adapter = enforcer.NewMemAdapter("nftables", nil)
	}
	e.Register(adapter, cfg.Policy.EnforceMode)

	dm := enforcer.NewDeadman(parseDuration(cfg.Enforcement.NFTables.DeadmanSwitchTimeout, 30*time.Second), func() {
		e.FlushAll("in-process dead-man's switch")
	}, log)
	go dm.Run(ctx)

	if closed, rerr := e.Reconcile(); rerr != nil {
		log.Warn().Err(rerr).Msg("enforcement: rollback-token reconcile error")
	} else if closed > 0 {
		log.Info().Int("tokens_closed", closed).Msg("enforcement: reconciled stale rollback tokens on start")
	}
	log.Info().Str("adapter", adapter.Name()).Str("mode", cfg.Policy.EnforceMode).
		Bool("linux", runtime.GOOS == "linux").Msg("enforcement: in-process enforcer ready")
	return enforcer.NewInProcClient(e, dm), nil
}

// loadActivePolicy loads and verifies the operator-signed policy file (if
// configured) and installs it. A configured-but-unverifiable policy is a fatal
// startup error — frien never trusts an unsigned or forged policy. No policy
// file means the node computes/explains nothing enforceable (pure observe).
func loadActivePolicy(cfg *config.Config, coord *coordinator.Coordinator, log zerolog.Logger) error {
	if cfg.Policy.PolicyFile == "" {
		log.Warn().Msg("enforcement: no policy_file configured; node will not enforce (observe/intelligence only)")
		return nil
	}
	p, err := policy.Load(cfg.Policy.PolicyFile)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}
	var operatorKey ed25519.PublicKey
	if cfg.Identity.OperatorRootCert != "" {
		operatorKey, err = identity.LoadOperatorPublicKey(cfg.Identity.OperatorRootCert)
		if err != nil {
			return fmt.Errorf("loading operator key for policy verification: %w", err)
		}
	}
	if err := p.Verify(operatorKey); err != nil {
		return fmt.Errorf("policy signature verification failed (refusing to trust it): %w", err)
	}

	protected, err := policy.FromPolicy(p)
	if err != nil {
		return fmt.Errorf("building protected set: %w", err)
	}
	if p.ProtectSelfPlanes {
		addSelfPlanes(protected, cfg)
	}
	if cfg.Policy.DenyTargetingAdminEndpoint {
		protected.SetAdminEndpoint(cfg.Observability.MetricsBind)
	}
	coord.SetPolicy(p, protected)
	log.Info().Str("policy", p.ID).Int64("version", p.Version).Msg("enforcement: active policy loaded and verified")
	return nil
}

// addSelfPlanes registers frien's own control/management addresses as protected
// so a policy can never lock frien out of its own planes.
func addSelfPlanes(ps *policy.ProtectedSet, cfg *config.Config) {
	ps.AddSelfPlane(net.JoinHostPort(advertiseHost(cfg.Transport.PeerBind), strconv.Itoa(cfg.Transport.PeerPort)), "mesh peer address")
	ps.AddSelfPlane(cfg.Observability.MetricsBind, "metrics endpoint")
	ps.AddSelfPlane(cfg.Observability.HealthBind, "health endpoint")
	if cfg.AdminAPI.TCPListen != "" {
		ps.AddSelfPlane(cfg.AdminAPI.TCPListen, "admin API")
	}
}

func heartbeatLoop(ctx context.Context, client enforcer.Client, interval time.Duration, log zerolog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := client.Heartbeat(); err != nil {
				log.Warn().Err(err).Msg("enforcement: heartbeat to enforcer failed")
			}
		}
	}
}

func sweepLoop(ctx context.Context, coord *coordinator.Coordinator, interval time.Duration, log zerolog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			coord.Sweep()
		}
	}
}

// meshResolver backs the coordinator's TrustResolver and PartitionResolver over
// the live mesh. Trust tiers come from each node's CA-signed certificate (learned
// at the mTLS handshake, seeded from this node's own cert for self), so quorum
// weighting is Sybil-resistant: a node cannot claim a higher tier than its
// certificate was issued with.
type meshResolver struct {
	mesh *gossip.Engine
}

func (r *meshResolver) TrustTier(nodeID, _ string) string {
	return r.mesh.TrustTier(nodeID)
}

func (r *meshResolver) Excluded(nodeID, _ string) bool { return r.mesh.IsNodeExcluded(nodeID) }

func (r *meshResolver) Partition() policy.PartitionState {
	live, known := r.mesh.PartitionView()
	return policy.PartitionState{LiveDistinct: live, KnownDistinct: known}
}
