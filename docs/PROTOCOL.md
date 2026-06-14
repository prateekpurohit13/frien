# frien — Protocol Versioning

## Wire Protocol Version

Every `OperationEnvelope` carries a `proto_version` field (uint32). This is the wire protocol version, not the software version.

Current version: **1**

---

## Version Negotiation

At session handshake, peers exchange `NegotiateRequest` and `NegotiateResponse`:

```
A → B: NegotiateRequest { supported_versions: [1, 2] }
B → A: NegotiateResponse { negotiated_version: 1 }
```

Rules:
- The negotiated version is the highest version both peers support
- If no common version exists, the session is rejected
- The negotiated version applies for the lifetime of that session
- Mixed-version clusters are a supported, first-class state during rolling upgrades

---

## Current Protocol Version: v1

### Objects

All objects defined in `proto/v1/frien.proto`. See [grpc-contracts.md](grpc-contracts.md) for schema.

### Clock skew window

Operations whose origin HLC implies skew beyond `transport.clock_skew_window` (default 10s) are rejected. NTP is recommended as a soft dependency.

### Message size limit

Max `transport.max_message_bytes` (default 1MB per message). Peers announce their limit in `GossipMessage.max_message_bytes_hint`.

### Signature algorithm — Hybrid PQC Model

v1 supports a **hybrid signature scheme** where both a classical and a post-quantum signature may appear in the same `OperationEnvelope`. Both signatures cover the same canonical content.

**Canonical signed content** (same bytes used by both algorithms):
```
SHA-256(
  writeField(proto_version) +   // 4-byte big-endian length + value
  writeField(op_id)         +
  writeField(op_type)       +
  writeField(node_id)       +
  writeField(hlc)           +
  writeField(seq)           +
  writeField(parents[0])    +   // each parent as separate field
  writeField(...)           +
  writeField(payload_hash)  +
  writeField(signed_by)
)
```

Length-prefix encoding prevents boundary-ambiguity attacks.

**Classical signature** (fields 11–12, always present):
- Algorithm: ed25519 (RFC 8032)
- Length: 64 bytes
- `key_id`: hex fingerprint of ed25519 public key from mTLS cert

**PQC signature** (fields 13–15, present when sender supports PQC):
- Algorithm: ML-DSA-65 (FIPS 204, `pqc_algorithm = "ml-dsa-65"`)
- Length: 3309 bytes
- `pqc_key_id`: hex fingerprint of ML-DSA-65 public key
- Implemented via `github.com/cloudflare/circl v1.6.3`; migration to Go stdlib planned when native ML-DSA ships

**Receiver verification order** (hard rules, no exceptions):
1. `pqc_algorithm == "ml-dsa-65"` AND PQC public key known → verify ML-DSA-65. Pass → accept. Fail → reject (no fallback to classical, even if classical sig is valid).
2. `pqc_algorithm` set to an unrecognized value → reject. Never silently ignore an unknown PQC field.
3. No PQC fields → verify ed25519 only.

**TLS key exchange** (session layer, not envelope):
- Default: `tls.X25519MLKEM768` (hybrid X25519 + ML-KEM-768, FIPS 203, Go 1.23+)
- Configurable: `"classical"` for X25519 only
- Protects sessions against harvest-now-decrypt-later attacks

---

## Deprecation Process

1. Add new version constants and object schemas
2. Document changes in this file under the new version section
3. Both versions are supported simultaneously for at least one full release cycle
4. Announce deprecation of old version in release notes
5. Remove old version support only after all nodes in documented deployments have upgraded

Breaking changes (field removal, type change, semantic change) require a new `proto_version`. Additive changes (new optional fields) do not.

---

## Schema Migration

Explicit schema migrations are required for data stored in WAL and bbolt when a new version changes the on-disk format:

1. Migration is idempotent
2. Migration runs at startup, before accepting traffic
3. Rollback: a downgrade must be possible at the WAL/snapshot level for N-1 version
4. Migration steps are documented here under the relevant version section

### v1 → v2 (example template, not yet needed)

_No migration defined. This section is a template for future use._

---

## PROTOCOL.md Change Log

| Date | Change | Proto Version |
|------|--------|--------------|
| 2026-06-14 | Initial protocol definition | 1 |
