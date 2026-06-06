---
spec_id: Spec-10-Hardening
version: 0.1.0-alpha.0
status: Draft
audience: Spec
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

<p className="stigmem-meta"><span>2 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Baseline operational hardening requirements: transport security,
key rotation posture, rate limits and quotas, and container runtime
baseline.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for supported
hardening expectations. Replay windows are owned by
`Spec-11-Replay-Protection`; audit record shape is owned by
`Spec-09-Audit-Log`.

## Federation transport

Federation deployments SHOULD use mutually authenticated TLS. When
mTLS is enabled, nodes MUST validate peer certificates against the
configured trust policy and MUST reject peers whose certificate
identity does not match the registered peer relationship.

Development deployments MAY use non-mTLS transport only when
clearly configured as non-production.

## Key rotation

Federation and manifest signing keys SHOULD support rotation
without downtime. Rotation procedures MUST preserve a dual-trust
period long enough for peers to refresh manifests and reject stale
keys. Rotation events SHOULD be auditable and published through
configured transparency-log evidence when available.

## Quotas and rate limits

Nodes SHOULD enforce per-principal quotas for write-heavy and
security-sensitive operations, including fact asserts, federation
ingestion, token issuance, and admin exports.

Rate-limit responses SHOULD be explicit and machine-readable.
Implementations SHOULD avoid revealing sensitive state in
rate-limit errors.

## Container baseline

Production container images SHOULD:

<div className="stigmem-grid">

<div><h4>Run as non-root</h4><p>A non-root user with minimal privileges.</p></div>
<div><h4>Minimize installed packages</h4><p>Avoid shells and build tooling in the production layer.</p></div>
<div><h4>Read-only root filesystem</h4><p>Where practical.</p></div>
<div><h4>Declare health checks</h4></div>
<div><h4>Publish SBOM / provenance evidence</h4><p>When supported by the release process.</p></div>
<div><h4>Avoid embedded secrets</h4><p>No runtime secrets in image layers.</p></div>

</div>

## Configuration boundaries

<div className="stigmem-keypoint">

**Production deployment templates SHOULD prefer the stricter setting.**

Operators MAY relax some hardening settings in local development.
Production templates SHOULD prefer the stricter setting and require
explicit operator action to weaken it.

</div>

## Out of scope

This spec does not define replay nonce windows, CID integrity,
vulnerability reporting policy, or external infrastructure such as
hosted transparency logs.
