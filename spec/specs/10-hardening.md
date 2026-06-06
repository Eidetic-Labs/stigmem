---
spec_id: Spec-10-Hardening
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 22.1, 22.2, 22.4, and 22.6
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-06-Capability-Tokens >= 0.1.0-alpha.0
  - Spec-09-Audit-Log >= 0.1.0-alpha.0
---

# Spec-10-Hardening

`Spec-10-Hardening` defines baseline operational hardening requirements:
transport security, key rotation posture, rate limits and quotas, and container
runtime baseline.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for supported hardening
expectations. Replay windows are owned by `Spec-11-Replay-Protection`; audit
record shape is owned by `Spec-09-Audit-Log`.

## Federation Transport

Federation deployments SHOULD use mutually authenticated TLS. When mTLS is
enabled, nodes MUST validate peer certificates against the configured trust
policy and MUST reject peers whose certificate identity does not match the
registered peer relationship.

Development deployments MAY use non-mTLS transport only when clearly configured
as non-production.

## Key Rotation

Federation and manifest signing keys SHOULD support rotation without downtime.
Rotation procedures MUST preserve a dual-trust period long enough for peers to
refresh manifests and reject stale keys. Rotation events SHOULD be auditable and
published through configured transparency-log evidence when available.

## Quotas And Rate Limits

Nodes SHOULD enforce per-principal quotas for write-heavy and security-sensitive
operations, including fact asserts, federation ingestion, token issuance, and
admin exports.

Rate-limit responses SHOULD be explicit and machine-readable. Implementations
SHOULD avoid revealing sensitive state in rate-limit errors.

## Container Baseline

Production container images SHOULD:

- run as a non-root user,
- minimize installed packages,
- use a read-only root filesystem where practical,
- declare health checks,
- publish SBOM/provenance evidence when supported by the release process,
- avoid embedding runtime secrets in image layers.

## Configuration Boundaries

Operators MAY relax some hardening settings in local development. Production
deployment templates SHOULD prefer the stricter setting and require explicit
operator action to weaken it.

## Out Of Scope

This spec does not define replay nonce windows, CID integrity, vulnerability
reporting policy, or external infrastructure such as hosted transparency logs.
