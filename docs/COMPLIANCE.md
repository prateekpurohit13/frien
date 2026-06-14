# frien — Compliance Mapping

## Overview

This document maps frien features to common compliance control frameworks. It is intended to help operators identify which controls frien contributes to and where additional compensating controls may be needed.

frien does not guarantee compliance with any framework by itself. It provides technical controls that may satisfy or contribute to specific requirements when deployed and configured appropriately.

---

## SOC 2 Type II

| Control | CC Ref | frien Contribution |
|---------|--------|-------------------|
| Audit logging of security events | CC7.2, CC7.3 | Tamper-evident, hash-linked audit log; every admin action audited |
| Detection and response to security threats | CC7.1 | Pluggable detectors, signed threat records, policy-gated enforcement |
| Change management for security controls | CC8.1 | Policy versioning (monotonic, operator-signed); rollback tokens; audit trail |
| Access control to infrastructure | CC6.1 | RBAC on admin API; Unix socket ownership; no anonymous access |
| Monitoring of security events | CC7.2 | Prometheus metrics, OTel traces, structured logs with request IDs |
| Incident response | CC7.3 | `frienctl explain` for full decision provenance; misbehavior proofs; quarantine |
| Logical access restrictions | CC6.2 | Least privilege: daemon non-root; enforcer minimal capability; RBAC roles |

---

## PCI DSS v4

| Requirement | frien Contribution |
|------------|-------------------|
| 10.x — Audit logs | Tamper-evident audit log with hash-linked entries; `frienctl explain` for every action |
| 1.3 — Network access controls | nftables adapter enforces approved block decisions; protected CIDR list prevents blocking of required traffic |
| 6.3 — Security vulnerabilities | `govulncheck`, `grype`, SBOM in CI; signed releases |
| 12.10 — Incident response | Evidence-backed threat records with full provenance; rollback and breakglass |

---

## NIST SP 800-53 (Moderate Baseline)

| Control | frien Contribution |
|---------|-------------------|
| AC-2 Account Management | RBAC roles; no default/anonymous accounts; audit of role changes |
| AC-3 Access Enforcement | gRPC RBAC interceptor; Unix socket ownership |
| AC-6 Least Privilege | Daemon non-root; enforcer minimal capability; operator keys in KMS/HSM |
| AU-2 Audit Events | All admin actions, enforcement decisions, policy changes, revocations logged |
| AU-9 Protection of Audit Information | Audit log is hash-linked; write-once (append-only) |
| AU-12 Audit Record Generation | Structured JSON logs with timestamp, caller, method, result, request ID |
| CA-7 Continuous Monitoring | Prometheus metrics, OTel; fleet SLO checks |
| CM-3 Configuration Change Control | Policy versioning; operator-signed; rollback capability |
| IA-3 Device Identification | mTLS with CA-issued short-lived certificates; node ID in cert CN |
| IA-5 Authenticator Management | Short-lived cert auto-renewal; revocation set |
| SC-5 Denial-of-Service Protection | Admission control (token-bucket, coalescing, shedding); per-peer rate limits |
| SC-8 Transmission Confidentiality | QUIC + mTLS for peer traffic; TLS for admin API (optional) |
| SI-3 Malicious Code Protection | Tamper-evident operation history; equivocation detection |
| SI-4 Information System Monitoring | Pluggable detectors; structured logging; OTel traces |

---

## CIS Benchmarks

| Control Area | frien Contribution |
|-------------|-------------------|
| Network access | Least-privilege port exposure; local-only admin API; peer-CIDR restriction |
| Audit logging | Structured tamper-evident logs; every admin action audited |
| User accounts | Non-root daemon; RBAC; no default passwords |
| Software updates | Signed releases; SBOM; vuln scanning in CI |

---

## Notes and Gaps

The following compliance areas require additional controls outside frien:

- **Key management**: operator signing keys and CA keys require KMS/HSM management outside frien's scope
- **Penetration testing**: frien does not perform active penetration testing; external testing is required
- **Data classification**: frien does not classify data in threat records; operators must classify what indicators are captured
- **Physical security**: host physical security is outside frien's scope
- **Multi-tenancy**: frien v1 does not provide tenant isolation; this is a noted gap for commercial expansion
- **Long-term audit archive**: frien's local audit log is bounded by compaction; long-term archive requires S3-compatible object storage (optional adapter)
