# frien — Upgrade Guide

## Upgrade Safety Principle

frien supports mixed-version clusters during rolling upgrades. Nodes running different software versions must interoperate safely. **No upgrade should require a full cluster restart.**

---

## Version Types

| Version | Where | Meaning |
|---------|-------|---------|
| Software version | Binary, release tag | Feature/fix release (semver: vMAJOR.MINOR.PATCH) |
| Proto version | `OperationEnvelope.proto_version` | Wire protocol compatibility level |
| Schema version | bbolt bucket metadata | On-disk format version |

A software upgrade does **not** always change the proto version. Proto version changes only when wire semantics change.

---

## Rolling Upgrade Procedure

### Pre-Upgrade

```bash
# Check current versions across the cluster
frienctl cluster versions

# Verify the new version is compatible
frienctl upgrade check --target v0.2.0

# Read the release notes for the target version
# Check docs/UPGRADE.md in the new release for migration notes
```

### Upgrade Steps

1. Deploy new binary to one node (the canary)
2. Verify the canary node starts and connects to peers
3. Check that version negotiation succeeds: `frienctl peers | grep proto_version`
4. Monitor for errors in logs and metrics (`frien_peer_negotiate_failure_total` should be 0)
5. If canary is healthy for ≥10 minutes, roll to remaining nodes one at a time
6. After all nodes are on the new version, run upgrade smoke tests
7. If any node fails to upgrade, roll it back to the previous binary (state is compatible)

### Post-Upgrade

```bash
# Verify all peers are on the new version
frienctl cluster versions

# Run smoke tests
make test-smoke

# Update policy if the new version adds policy fields
# (update the policy file and have the operator re-sign and distribute)
```

---

## Schema Migrations

If a new version changes the on-disk bbolt schema:

1. The daemon detects the schema version at startup (stored in a `schema_version` bucket)
2. Runs idempotent migration steps in order
3. Updates the schema version
4. Proceeds with normal startup

Migration is automatic and logged. If migration fails, the daemon exits with a clear error — it never starts on a partially-migrated schema.

Rollback: the N-1 software version must be able to read the on-disk format produced by the previous schema migration. This is tested in upgrade CI.

---

## Breaking Changes

Breaking changes in the wire protocol require a new `proto_version`. The procedure:

1. Bump `proto_version` constant in `internal/version/version.go`
2. Add new version to `NegotiateRequest.supported_versions`
3. Implement handling for both versions in the peer session layer
4. Document the change in this file under a new version section
5. Keep support for N-1 version for at least one full release cycle
6. Remove old version only after all documented deployments have upgraded

---

## Version Compatibility Matrix

| New Version | Can Interoperate With | Notes |
|-------------|----------------------|-------|
| v0.1.x | v0.1.x only | Initial release; no upgrade path yet |

_(This table will be updated with each release.)_

---

## Emergency Downgrade

If the new version has a critical bug:

```bash
# Stop the daemon
systemctl stop friend

# Restore previous binary
cp /usr/local/bin/friend.prev /usr/local/bin/friend

# Restart
systemctl start friend
```

The WAL and bbolt state from the new version is compatible with the previous version (N-1 guarantee). The previous version will read and replay the state correctly.

If the new version ran a schema migration, and the previous version cannot read the new schema, the previous version will exit with a clear error. In this case, restore from the pre-upgrade backup.
