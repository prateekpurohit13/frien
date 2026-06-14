# frien — Deployment Guide

## Deployment Modes

| Mode | Enforcement | Use Case |
|------|-------------|---------|
| Linux host (EC2/bare metal) | nftables | General Linux fleet |
| Kubernetes DaemonSet (EKS) | NetworkPolicy / Cilium | Cloud-native workloads |
| Observe-only (any) | None | Visibility and intelligence only |
| Development (single node) | None | Local testing |

---

## Linux Host Deployment

### Prerequisites

- Linux with nftables (kernel ≥ 4.10)
- Go 1.26+ (for building from source)
- Private CA for node certificate issuance
- KMS or HSM access for operator signing keys

### File Paths

| Path | Purpose | Permissions |
|------|---------|-------------|
| `/etc/frien/config.yaml` | Configuration | `root:root 0640` |
| `/etc/frien/keys/node.crt` | Node cert | `root:frien 0640` |
| `/etc/frien/keys/node.key` | Node private key | `root:frien 0600` |
| `/etc/frien/ca.crt` | CA certificate | `root:root 0644` |
| `/etc/frien/operator-root.crt` | Operator root cert | `root:root 0644` |
| `/etc/frien/policy.yaml` | Signed policy | `root:frien 0640` |
| `/var/lib/frien/` | WAL, bbolt, snapshots | `frien:frien 0700` |
| `/run/frien/admin.sock` | Admin API socket | `frien:frien 0660` |

### Installation Steps

```bash
# 1. Create frien user (non-root, no login shell)
useradd --system --no-create-home --shell /usr/sbin/nologin frien

# 2. Create directories
mkdir -p /etc/frien/keys /var/lib/frien /run/frien
chown -R root:frien /etc/frien
chmod 750 /etc/frien
chmod 700 /etc/frien/keys
chown -R frien:frien /var/lib/frien /run/frien

# 3. Install binaries
install -m 755 -o root -g root ./build/friend /usr/local/bin/friend
install -m 755 -o root -g root ./build/frienctl /usr/local/bin/frienctl
install -m 750 -o root -g frien-enforcer ./build/frien-enforcer /usr/local/bin/frien-enforcer

# 4. Issue and install node certificate
# (use your CA tooling; cert CN must match node.id in config)
install -m 640 -o root -g frien ./node.crt /etc/frien/keys/node.crt
install -m 600 -o root -g frien ./node.key /etc/frien/keys/node.key

# 5. Install config
install -m 640 -o root -g frien ./config.yaml /etc/frien/config.yaml

# 6. Install and start systemd units
install -m 644 ./deploy/systemd/friend.service /etc/systemd/system/
install -m 644 ./deploy/systemd/frien-enforcer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable friend frien-enforcer
systemctl start frien-enforcer friend

# 7. Verify health
frienctl status
```

### Systemd Unit (friend daemon)

```ini
# /etc/systemd/system/friend.service
[Unit]
Description=frien security mesh daemon
After=network-online.target
Wants=network-online.target
Requires=frien-enforcer.service
After=frien-enforcer.service

[Service]
Type=simple
User=frien
Group=frien
ExecStart=/usr/local/bin/friend --config /etc/frien/config.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=/var/lib/frien /run/frien
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
```

---

## Kubernetes (EKS) Deployment

### Architecture

- `friend` daemon: DaemonSet, non-root container, read-only root filesystem, no capabilities
- `frien-enforcer`: separate container in the same pod or separate DaemonSet with minimal capabilities
- NetworkPolicy: default-deny; allow only peer UDP, DNS, metrics, required API calls
- RBAC: minimal; only what the adapter needs

### Quick Start

```bash
# Apply Kubernetes manifests
kubectl apply -f deploy/kubernetes/

# Verify DaemonSet is healthy
kubectl -n frien get ds frien-node
kubectl -n frien get pods
```

### Key Constraints

- Main container runs as UID 65534 (nobody); `runAsNonRoot: true`
- `readOnlyRootFilesystem: true` on main container
- `allowPrivilegeEscalation: false` on main container
- Drop ALL capabilities on main container (`capabilities.drop: [ALL]`)
- Enforcer container: only `CAP_NET_ADMIN` if host nftables enforcement is required; prefer Kubernetes NetworkPolicy or Cilium adapter where possible
- Use IRSA (IAM Roles for Service Accounts) for AWS API access

---

## Observe-Only Deployment (any environment)

No changes to existing firewall configuration. frien runs purely as a security intelligence layer.

```yaml
# config.yaml
policy:
  enforce_mode: observe  # default; safe to omit

enforcement:
  nftables:
    enabled: false
  kubernetes:
    enabled: false
```

Nodes publish signed threat records, verify provenance, evaluate policy, and surface decisions via `frienctl explain` and the dashboard — but apply no rules.

---

## Ports and Network Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 7443 | UDP | peer → peer | QUIC mesh gossip |
| 9443 | TCP (optional) | local only | Admin API (TLS) |
| 9109 | TCP | local or monitoring CIDR | Prometheus metrics |
| 9110 | TCP | local | Health checks |

- Peer UDP should be restricted to known peer CIDRs via security group or host firewall
- Admin TCP must be local or VPN/bastion-only
- No port should be exposed to the public internet

---

## Upgrade Procedure

See [UPGRADE.md](UPGRADE.md) for the full mixed-version migration guide.

Quick reference:

1. Check `frienctl cluster versions` for current protocol versions in the mesh
2. Deploy new binary to one node
3. Verify version negotiation succeeds with existing peers (check logs + metrics)
4. Roll forward node by node
5. Once all nodes run the new version, update policy and config if needed
6. Run upgrade smoke tests

---

## Hardening Post-Install

```bash
# Check current hardening posture
frienctl harden status

# Detailed check against a profile
frienctl harden doctor --profile server

# Apply recommended hardening (requires review first; never auto-applies)
frienctl harden apply --profile server --dry-run
frienctl harden apply --profile server --confirm
```

---

## Backup and Restore

```bash
# Backup: copy signed snapshot + latest checkpoint + config
cp /var/lib/frien/snapshots/latest.snap /backup/frien-$(date +%Y%m%d).snap
cp /var/lib/frien/state.db /backup/frien-$(date +%Y%m%d).db
cp /etc/frien/config.yaml /backup/

# Restore:
# 1. Install new node with same node.id and a fresh cert
# 2. Copy snapshot and db to /var/lib/frien/
# 3. Start daemon; it will replay WAL from the checkpoint
```

Node identity (cert + key) should not be backed up and restored — issue a new cert on restore. Only state and config need restoring.
