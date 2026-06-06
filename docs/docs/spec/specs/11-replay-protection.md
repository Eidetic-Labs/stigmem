---
spec_id: Spec-11-Replay-Protection
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 22.5 replay-protection material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-06-Capability-Tokens >= 0.1.0-alpha.0
---

# Spec-11-Replay-Protection

<p className="stigmem-meta"><span>2 min read</span><span>Spec contributor</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Nonce, timestamp, and bounded replay-window requirements for signed
federation and capability-token operations.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for replay
protection. It intentionally keeps token shape in
`Spec-06-Capability-Tokens` and HLC clock skew policy in
`Spec-12-HLC-Bounded-Skew`.

## Requirements

<div className="stigmem-fields">

<div>
<dt>Requirement</dt>
<dt><span className="stigmem-fields__type">Spec</span></dt>
<dd>Constraint</dd>
</div>

<div>
<dt>Nonce</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Unique for the <code>(issuer, subject, operation, window)</code> tuple. Implementations SHOULD use at least 128 bits of randomness or equivalent collision resistance.</dd>
</div>

<div>
<dt>Timestamp</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Issuance timestamp on every protected request. Receivers MUST reject requests outside the accepted replay window.</dd>
</div>

<div>
<dt>Replay window</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Receivers MUST remember accepted nonces until the replay window elapses. A second request with the same nonce inside that window MUST be rejected even if the signature is valid.</dd>
</div>

</div>

The default window SHOULD be short enough to limit replay value and
long enough to tolerate normal network latency and bounded clock
skew.

## Failure behavior

Replay failures MUST deny the operation and SHOULD emit an audit
event. Error responses SHOULD not reveal whether a valid request
with the same nonce was previously accepted beyond the minimum
needed for debugging authorized clients.

## Storage

<div className="stigmem-keypoint">

**Production deployments SHOULD use restart-resilient nonce storage.**

In-memory storage MAY be used for single-node development
deployments. Production deployments SHOULD use storage with
process-restart resilience when the protected operation can be
retried after restart.

</div>

## Out of scope

This spec does not define capability-token schema, federation peer
admission, or HLC bounded-skew rejection thresholds.
