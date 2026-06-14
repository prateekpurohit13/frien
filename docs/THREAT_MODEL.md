# frien — Threat Model

## Scope

This document describes the security threats frien is designed to detect, resist, and mitigate. It also defines what frien explicitly does not protect against.

---

## Assets

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| Node private key | Critical | Attacker can sign data-plane messages as this node |
| Operator signing key | Critical | Attacker can issue arbitrary policies and revocations |
| WAL / local state | High | Attacker can alter history; detected via hash chain |
| Admin API socket | High | Attacker can query state, issue threats, change enforce mode |
| Policy file | High | Modified policy can suppress enforcement or target wrong indicators |
| frien binary | High | Compromised binary can bypass all protections |
| frien network traffic | Medium | Gossip is authenticated via mTLS; content is signed |

---

## Attacker Categories

### External Network Attacker

**Capabilities:**
- Can observe QUIC UDP traffic on the peer port
- Can send crafted UDP packets to the peer port
- Cannot forge valid mTLS sessions (no valid cert)
- Cannot impersonate a node without that node's private key

**mitigations:**
- mTLS required for all peer sessions; no anonymous peer connections
- QUIC provides transport-layer encryption
- Message signing detects tampering even if TLS is stripped at a proxy
- Port restriction to known peer CIDRs via security group/host firewall

---

### Compromised Node

**Capabilities:**
- Can sign and send arbitrary data-plane messages with valid node cert
- Can gossip crafted `ThreatRecord` objects to peers
- Can attempt to target high-value addresses (loopback, peer addresses)
- Can attempt equivocation (conflicting signed operations)
- Cannot sign control-plane objects (operator key required)

**Mitigations:**
- Protected CIDR list prevents blocking of loopback, RFC1918, link-local, frien planes
- Quorum requirement: single compromised node cannot alone satisfy quorum
- Trust-tier weighting: compromised `standard` node needs multiple confederates
- Equivocation detection: conflicting sequence → misbehavior proof → quarantine → revocation proposal
- Short-lived certs: compromise blast radius bounded by cert lifetime
- Revocation: operator can revoke compromised node's cert mesh-wide

**What a compromised node CAN do:**
- Publish threat records that propagate (but cannot satisfy quorum alone)
- Consume admission budget on receiving peers (rate-limited)
- Learn zone-scoped state it subscribes to (scoping limits blast radius)

---

### Malicious Peer / Sybil Attack

**Capabilities:**
- May control many peer identities
- May flood the network with crafted messages
- May attempt to manufacture quorum via collusion

**Mitigations:**
- Quorum keyed by distinct CA-issued certificate fingerprints: Sybil resistance = CA issuance discipline
- Admission control limits message creation rate per node
- Per-peer rate limits at transport layer
- Trust-tier weighting: attacker must control many `trusted` identities, not just `standard` ones
- Clock-skew window: replayed old messages rejected

---

### Compromised Operator Key

**Capabilities:**
- Can issue arbitrary policies (including permissive or malicious)
- Can revoke legitimate nodes
- Can issue trust-tier upgrades to attacker-controlled nodes

**Mitigations:**
- Operator keys must be KMS/HSM-backed in production (never on-node)
- Audit trail of all control-plane objects with operator key ID and signature
- Revocation of the operator key itself requires CA root rotation (documented procedure)
- Policy versioning is monotonic: a node never downgrades to a lower version for the same policy ID (limits replayed old policies)

---

### Supply-Chain Attacker

**Capabilities:**
- May compromise a dependency to inject malicious code
- May modify the frien binary in distribution

**Mitigations:**
- `govulncheck` on every CI build; fails on known critical CVEs
- `grype` image scanning
- `syft` SBOM generation
- `cosign` signed releases and container images
- Reproducible builds targeted
- Minimal dependency surface: core mesh has no required external services

---

### Malicious Admin API Caller

**Capabilities:**
- If the caller has socket access, can issue admin commands up to their RBAC role
- Cannot call methods above their assigned role

**Mitigations:**
- Unix socket permissions restrict who can connect (OS-enforced)
- RBAC enforced by gRPC interceptor before any handler executes
- All mutating calls produce immutable audit log entries
- Read-only mode can be enforced at API layer
- `Breakglass` requires `breakglass` or `admin` role + confirmation code

---

## Out of Scope

| Threat | Why Out of Scope |
|--------|-----------------|
| Physical access to node hardware | Hardware security is the operator's responsibility |
| Compromise of the CA private key itself | CA key management is out of scope; use HSM/KMS |
| Kernel exploits allowing privilege escalation | OS hardening is the operator's responsibility; systemd sandboxing is recommended |
| Side-channel attacks on crypto | Standard Go crypto is used; timing attacks on signatures are out of scope for v1 |
| Correctness of detector logic | Detectors are pluggable; false positives are addressed by quorum, not by detector auditing |

---

## Self-Lockout Risk

The most dangerous operational failure is a node blocking its own management access.

**Mitigated by:**
1. Protected self-planes: frien dynamically adds its own mesh/admin/metrics/management addresses to the protected set
2. Protected CIDR defaults include all RFC1918, loopback, link-local, and cloud metadata addresses
3. Breakglass command (`frienctl --local breakglass`) is local-only and works without mesh connectivity
4. `frienctl harden doctor` checks for self-lockout risk in the current config and firewall state
5. Observe-only default: no rules applied until operator explicitly promotes to enforce

---

## Security Properties Claimed

| Property | Claim |
|----------|-------|
| Authenticity | Every operation is signed by a CA-issued cert; unsigned operations are rejected |
| Integrity | Merkle DAG and WAL hash chain detect tampering with history |
| Accountability | Equivocation is detected and produces a portable proof; all control-plane actions are auditable |
| Provenance | `frienctl explain` can always show who reported, what evidence, which policy approved, what quorum was met |
| Non-escalation | Data-plane objects cannot grant enforcement authority; only operator-signed control-plane objects can |
| Fail-safe enforcement | Minority partition cannot take fleet-scoped enforcement action |
| Bounded state | DAG and WAL are compacted via signed checkpoints; no structure grows without bound |

**Not claimed:**
- Byzantine fault tolerance (we are accountable, not BFT)
- Consensus (frien uses gossip + CRDT + eventual consistency, not consensus)
- Protection against a malicious majority of the peer set (quorum is a defense against small coalitions, not a majority-Byzantine defense)
