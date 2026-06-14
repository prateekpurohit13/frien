# frien — Enforcement Safety

## Core Principle

**Observe before enforce.** A node never applies a firewall rule until an operator explicitly promotes it from `observe` mode to `enforce` mode for a specific adapter. This is not a configuration option that defaults to unsafe — it is the architectural default.

---

## Enforcement Modes

| Mode | Behavior |
|------|---------|
| `observe` | Decisions are computed, audited, logged, and shown via `explain`. No rule is applied to any adapter. |
| `enforce` | Policy-approved decisions with quorum are applied to the specified adapter with kernel-native TTL. |

Each adapter has its own mode. A node can be in `enforce` for `nftables` and `observe` for `cilium` simultaneously.

### Promoting to Enforce

```bash
frienctl mode set enforce \
  --adapter nftables \
  --confirm \
  --reason "rollout phase 2 — operator reviewed logs"
```

This command:
1. Requires `operator` RBAC role
2. Writes an immutable audit log entry with operator identity, reason, and timestamp
3. Transitions only the specified adapter to enforce mode
4. Does not retroactively apply any pending observe-mode decisions

### Demoting to Observe

```bash
frienctl mode set observe --adapter nftables --reason "pausing enforcement for maintenance"
```

This does not flush existing active rules. Use `rollback` or `breakglass` to remove rules.

---

## Fail-Safe Mechanisms

### 1. Kernel-Native Rule Expiry

All nftables rules created by frien carry an explicit kernel `timeout` matching the decision's `kernel_timeout` field. When the timeout expires, the kernel removes the rule automatically — even if the frien daemon and enforcer processes are both dead.

This means: **frien cannot leak permanent firewall rules.**

### 2. Enforcer Dead-Man's Switch

The `frien-enforcer` process monitors heartbeats from the `friend` daemon. If no heartbeat is received within `enforcement.nftables.deadman_switch_timeout` (default 30s):

1. Enforcer flushes all frien-managed rules from frien's own nftables chains
2. Logs the cleanup at WARN level
3. Increments the `frien_deadman_triggered_total` metric

The dead-man switch removes rules from **frien's chains only** — never from the host baseline firewall configuration.

### 3. Protected CIDR List

The following addresses cannot be blocked by frien policy (enforced at policy evaluation time, before the enforcer is called):

```
127.0.0.0/8      (loopback)
10.0.0.0/8       (RFC1918)
172.16.0.0/12    (RFC1918)
192.168.0.0/16   (RFC1918)
169.254.0.0/16   (link-local, incl. cloud metadata 169.254.169.254)
::1/128           (IPv6 loopback)
fc00::/7          (IPv6 unique local)
fe80::/10         (IPv6 link-local)
```

IPv6 protected CIDRs are required. An IPv4-only protected list is a configuration error.

### 4. Self-Plane Protection

At startup, frien dynamically adds to the protected set:
- The node's own mesh peer address(es) (UDP port 7443)
- The admin API socket address
- The metrics endpoint address
- The node's management/SSH path (if configured)

This prevents a policy from ever blocking frien's own control, admin, or management access.

### 5. Partition-Safe Quorum

A node in a minority partition — one that cannot observe the required weight from distinct trusted identities — **must not** take fleet-scoped enforcement. It falls back to intelligence-only for all fleet-scoped decisions.

Local-scope decisions on directly-observed local evidence are still permitted under policy.

### 6. Durable Rollback Tokens

Every EnforcementDecision carries a `rollback_token`. Rollback tokens are persisted in the WAL and reconciled on restart. If the daemon crashes mid-enforcement:

1. On restart: open bbolt `rollback_tokens` bucket
2. For each token where `applied=true` and `rolled_back=false`: verify whether the kernel rule is still active; reapply or roll back as appropriate
3. Log the reconciliation result

This ensures no partial-enforcement state persists silently across a crash.

---

## Breakglass (Self-Lockout Recovery)

If frien has locked out the operator's own access, the breakglass command provides a local emergency exit:

```bash
frienctl --local breakglass \
  --flush-enforcement \
  --force-observe \
  --reason "self-lockout recovery — urgent"
```

**Behavior:**
- `--local` bypasses mesh communication (works even if mesh is partitioned)
- Sends command directly to the local admin socket
- `--flush-enforcement`: removes ALL frien-managed rules from all adapters immediately
- `--force-observe`: sets all adapters to observe mode
- Writes audit log entry if the daemon is running; writes to local file if not

**This command does not require mesh connectivity to execute.** It communicates only with the local socket or, if the daemon is not running, directly with the enforcer via its own socket.

### When to Use Breakglass

- Self-lockout: frien blocked the operator's SSH or management access
- Emergency: frien is taking actions the operator did not intend and must be stopped immediately
- Maintenance: need to flush all enforcement before a planned system change

### Breakglass Protections

- Requires `breakglass` or `admin` RBAC role
- Requires explicit `--flush-enforcement` and `--force-observe` flags (no accidental invocation)
- Rate-limited (2/min) to prevent automated abuse
- All invocations are audit-logged (both to local file and to daemon if available)

---

## Policy Dry-Run

Before activating a new policy in enforce mode, test it:

```bash
# Simulate a threat record against a policy
frienctl policy test \
  --file /etc/frien/policy-candidate.yaml \
  --record /tmp/sample-threat.json

# Output shows:
# - would_enforce / observe_only / denied
# - reason
# - matched_weight vs required_weight
# - protected targets identified
```

---

## Enforcement Checklist

Before a node is promoted to enforce mode, verify:

- [ ] Policy has been reviewed and signed by operator
- [ ] Policy has been tested with `frienctl policy test` against representative threat samples
- [ ] Protected CIDRs include all management and infrastructure addresses
- [ ] `protect_self_planes: true` is set
- [ ] `kernel_timeout_required: true` is set in policy
- [ ] Breakglass access is available and tested on this node
- [ ] `frienctl harden doctor` shows no self-lockout risk
- [ ] Audit log is being collected and is accessible
- [ ] Rollback tokens are durable (WAL sync enabled or confirmed)
- [ ] Dead-man switch timeout is configured and tested
