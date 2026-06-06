---
spec_id: Spec-11-Replay-Protection
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 22.5 replay-protection material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-06-Capability-Tokens >= 0.1.0-alpha.0
---

# Spec-11-Replay-Protection

`Spec-11-Replay-Protection` defines nonce, timestamp, and bounded replay-window
requirements for signed federation and capability-token operations.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for replay protection. It
intentionally keeps token shape in `Spec-06-Capability-Tokens` and HLC clock
skew policy in `Spec-12-HLC-Bounded-Skew`.

## Nonce Requirement

Requests protected by replay defense MUST carry a nonce. The nonce MUST be
unique for the `(issuer, subject, operation, window)` tuple. Implementations
SHOULD use at least 128 bits of randomness or an equivalently collision-resistant
identifier.

## Timestamp Requirement

Protected requests MUST carry an issuance timestamp. Receivers MUST reject
requests whose timestamp is outside the accepted replay window.

## Replay Window

Receivers MUST remember accepted nonces until the replay window elapses. A
second request with the same nonce inside that window MUST be rejected even if
the signature is valid.

The default window SHOULD be short enough to limit replay value and long enough
to tolerate normal network latency and bounded clock skew.

## Failure Behavior

Replay failures MUST deny the operation and SHOULD emit an audit event. Error
responses SHOULD not reveal whether a valid request with the same nonce was
previously accepted beyond the minimum needed for debugging authorized clients.

## Storage

Nonce storage MAY be in-memory for single-node development deployments.
Production deployments SHOULD use storage with process-restart resilience when
the protected operation can be retried after restart.

## Out Of Scope

This spec does not define capability-token schema, federation peer admission,
or HLC bounded-skew rejection thresholds.
