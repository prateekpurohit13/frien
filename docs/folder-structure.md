# frien — Folder Structure

## Root Layout

```
frien/
├── cmd/
│   ├── friend/                   # Main daemon binary
│   │   └── main.go
│   ├── frienctl/                 # Operator CLI binary
│   │   └── main.go
│   └── frien-enforcer/           # Privileged enforcer helper binary
│       └── main.go
│
├── internal/                     # Private packages (not importable externally)
│   ├── admission/                # Op-creation budgets, coalescing, storm shedding
│   ├── api/                      # Local admin gRPC service registration
│   ├── audit/                    # Audit log writer + explain data
│   ├── checkpoint/               # DAG/WAL compaction + signed checkpoint logic
│   ├── config/                   # Config loading, parsing, validation
│   ├── controlplane/             # Operator-signed policy + trust-tier distribution
│   ├── crdt/                     # op-id-keyed grow-only set (union), LWW-Register, G-Counter, HLC
│   ├── detector/                 # Detector interface + built-in detectors
│   ├── enforcer/                 # Adapter interfaces, self-expiry, dead-man switch
│   ├── errors/                   # Centralized error definitions + gRPC status mapping
│   ├── grpc/                     # gRPC server setup, interceptor chain registration
│   ├── harden/                   # Self-hardening checks and profiles
│   ├── health/                   # Readiness + liveness handlers
│   ├── logger/                   # Structured logger initialization
│   ├── membership/               # SWIM membership protocol
│   ├── middleware/               # gRPC interceptors (auth, RBAC, rate-limit, audit)
│   ├── policy/                   # Trust evaluation + partition-safe quorum engine
│   ├── revocation/               # Short-lived cert lifecycle + signed revocation CRDT
│   ├── scope/                    # Zone/interest-based replication router
│   ├── storage/                  # WAL, bbolt indexes, snapshot/checkpoint files
│   ├── transport/                # QUIC listener/dialer, mTLS peer sessions
│   ├── validation/               # Request message validators
│   ├── verify/                   # Signature verify, Merkle DAG, equivocation detection
│   └── version/                  # Protocol version constants + negotiation
│
├── pkg/                          # Importable shared packages
│   ├── proto/                    # Generated protobuf Go code + version constants
│   └── sdk/                      # Detector and enforcement adapter SDK (third-party use)
│
├── proto/
│   └── v1/
│       └── frien.proto           # All gRPC + message definitions
│
├── specs/
│   └── frien.tla                 # TLA+ spec: membership, quorum, quarantine, revocation
│
├── deploy/
│   ├── docker/
│   │   ├── Dockerfile.friend
│   │   ├── Dockerfile.enforcer
│   │   └── docker-compose.yaml
│   ├── kubernetes/
│   │   ├── daemonset.yaml
│   │   ├── rbac.yaml
│   │   ├── networkpolicy.yaml
│   │   └── configmap.yaml
│   └── systemd/
│       ├── friend.service
│       └── frien-enforcer.service
│
├── dashboards/
│   └── grafana.json              # Grafana dashboard for mesh health + observability
│
├── tests/
│   ├── integration/              # Multi-node join, gossip, sync, enforce tests
│   ├── chaos/                    # Restart, partition, rejoin, convergence tests
│   ├── adversarial/              # Malformed messages, replay, equivocation tests
│   ├── simulation/               # Deterministic seeded discrete-event simulation
│   └── jepsen/                   # Partition + consistency tests (Clojure/Jepsen)
│
├── migrations/                   # bbolt schema migrations (if needed)
├── scripts/                      # Build, release, demo, cluster-setup scripts
│
├── docs/
│   ├── FRIEN_ARCHITECTURE.md     # Canonical architecture document
│   ├── architecture.md           # Architecture summary
│   ├── workflow.md               # Event lifecycle and workflows
│   ├── api-manual.md             # gRPC API reference
│   ├── task-checklist.md         # Implementation progress checklist
│   ├── folder-structure.md       # This file
│   ├── configuration.md          # All config variables
│   ├── security.md               # Security model and controls
│   ├── database.md               # Data model + storage schema
│   ├── testing.md                # Testing strategy and requirements
│   ├── deployment.md             # Deployment guide
│   ├── error-handling.md         # Error handling patterns
│   ├── grpc-contracts.md         # gRPC contract versioning and evolution
│   ├── PROTOCOL.md               # Wire protocol versioning + negotiation
│   ├── THREAT_MODEL.md           # Threat model and attacker scenarios
│   ├── ENFORCEMENT_SAFETY.md     # Observe→enforce, breakglass, self-lockout
│   ├── COMPLIANCE.md             # Feature → compliance control mappings
│   └── UPGRADE.md                # Mixed-version migration guide
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── .gitignore
```

---

## Package Responsibilities

### `cmd/friend/main.go`
Bootstrap only. Calls into `internal/` packages in order:
1. Load config
2. Initialize logger
3. Initialize storage (WAL + bbolt)
4. Initialize node identity + cert
5. Initialize CRDT engine
6. Initialize membership
7. Initialize transport (QUIC)
8. Initialize admission control
9. Initialize policy engine
10. Initialize detectors
11. Initialize enforcer
12. Register gRPC services
13. Start server
14. Block on shutdown signal
15. Graceful shutdown

### `internal/config`
- Parse and validate config file + environment overrides
- Fail fast on missing required fields
- Expose typed `Config` struct to other packages
- No business logic

### `internal/grpc`
- Set up gRPC server with interceptor chain
- Register `AdminService` implementation
- Expose `api.go` for service registration (separate from handlers)

### `internal/storage`
- WAL: append-only, hash-linked, checkpoint-aware compaction
- bbolt: indexed metadata (rollback tokens, peer state, revocation set snapshots)
- Signed snapshot + checkpoint files

### `internal/crdt`
- Grow-only set of immutable signed ops keyed by op_id; union merge; TTL/retraction/quorum as deterministic projections
- Delta propagation + per-scope anti-entropy backstop (idempotent union self-heals dropped deltas)
- HLC implementation (persisted, drift-clamped)
- Scope/zone-aware replication state

### `internal/verify`
- Signature verification against node cert
- Merkle DAG parent validation
- Replay detection (op_id + origin_node_id dedup)
- Equivocation detection and proof construction

---

## Naming Conventions

- Packages: lowercase, single word where possible (`crdt`, `verify`, `policy`, `admission`)
- Files: `snake_case.go`
- Types: `PascalCase`
- Interfaces: descriptive noun (`Detector`, `Adapter`, `Repository`)
- Test files: `foo_test.go` co-located with the package
- Integration tests: in `tests/integration/`
- Mock types: only at package boundary, not for internal use
