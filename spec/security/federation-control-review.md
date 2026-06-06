# Federation Hardening Control Review

**Roadmap slice:** future hardened-core federation hardening
**Issue:** #418  
**Reviewed on:** 2026-05-16  
**Status:** Current review record for the v0.9.0a1/v0.9.0a2 hardening line

This review records the implementation evidence, test evidence,
version-introduced notes, and accept/patch/replace decision for the controls
called out in the federation-hardening worksheet. It is intentionally a
review record, not a rewrite PR. Follow-up implementation issues are created
for every `patch` decision.

## Decision Summary

| Control | Risk linkage | Version introduced | Decision | Follow-up |
|---|---|---|---|---|
| TLS termination | R-01 | 0.9.0a1 | Accept as shipped control evidence | None |
| mTLS client certificate enforcement | R-01 | 0.9.0a1 | Patch default/insecure-mode posture | Required |
| Rate limiting middleware | R-02, R-12 | 0.9.0a1 | Patch production warning for explicit kill switch | Required |
| Audit event helpers | R-09, R-10 | 0.9.0a1 | Accept as shipped control evidence | None |
| Capability-token validation | R-14 | 0.9.0a1 | Accept as shipped control evidence | None |
| Key rotation | R-03, R-10 | 0.9.0a1 | Accept as shipped control evidence | None |
| Quota buckets migration | R-02, R-12 | 0.9.0a1 | Accept as shipped control evidence | None |

`Accept as shipped control evidence` means the current implementation and tests
are sufficient for the corresponding security evidence registry entry. `Patch`
means the control exists, but a narrow follow-up is needed to satisfy the
roadmap's desired production posture or operator ergonomics.

## TLS Termination

**Implementation evidence**

- `node/src/stigmem_node/tls.py` builds server and client SSL contexts with
  `ssl.TLSVersion.TLSv1_3` as the minimum protocol version.
- The server context sets `ssl.CERT_REQUIRED`.
- The client context also presents the node certificate and verifies peers
  against the configured CA bundle.
- `node/src/stigmem_node/main.py` serves with the configured TLS cert/key/CA
  when `settings.mtls_enabled` is true.

**Test evidence**

- `node/tests/federation/test_mtls.py` covers TLS 1.3-only contexts, client certificate
  rejection, certificate reload behavior, plaintext federation route rejection
  when mTLS is configured, and required CA-bundle validation.

**Decision**

Accept as shipped control evidence for R-01. The TLS context implementation is
sound when mTLS is configured.

## mTLS Client Certificate Enforcement

**Implementation evidence**

- `node/src/stigmem_node/tls.py` requires client certificates in the server SSL
  context.
- `node/src/stigmem_node/routes/federation/common.py` verifies peer
  certificate SAN values against expected peer `entity_uri` when
  `settings.mtls_enabled` is true.
- `node/src/stigmem_node/main.py` rejects plaintext `/v1/federation/*`
  requests with HTTP 421 when mTLS is configured.

**Test evidence**

- `node/tests/federation/test_mtls.py` covers wrong-CA client rejection, URI SAN matching,
  plaintext rejection when mTLS is configured, missing peer cert handling, and
  pull behavior when SAN/entity binding fails.

**Decision**

Patch. The configured mTLS path is covered, but the hardened-core roadmap asks for
mTLS to be the default federation posture and for insecure federation mode to
require an explicit `STIGMEM_FEDERATION_INSECURE=1` acknowledgement with a loud
startup warning. That is a production-posture patch, not a reason to rewrite
the TLS primitives.

## Rate Limiting Middleware

**Implementation evidence**

- `node/src/stigmem_node/rate_limit.py` maps public routes to quota dimensions
  and uses token buckets persisted in `quota_buckets`.
- Quotas are keyed by `entity_uri`, `tenant_id`, and dimension.
- `quota_breach` audit events are emitted on denied requests.

**Test evidence**

- `node/tests/observability/test_quota.py` covers write/read burst behavior, 429 response
  shape, `Retry-After`, read/write bucket independence, unauthenticated bypass,
  federation endpoint bypass, and `quota_breach` audit emission.

**Decision**

Patch. The token-bucket implementation and tests satisfy the R-02/R-12 control
evidence. The remaining roadmap gap is an operator warning when both
`STIGMEM_RATE_LIMIT_WRITE_PER_HOUR=0` and
`STIGMEM_RATE_LIMIT_READ_PER_HOUR=0` disable enforcement. That warning should
be explicit because the kill switch re-opens the rate-limit risk in production.

## Audit Event Helpers

**Implementation evidence**

- `node/src/stigmem_node/audit_event.py` centralizes audit emission into
  `fact_audit_log`.
- `emit()` writes before returning to the caller and increments the audit
  Prometheus counter after a successful insert.
- `emit_nofail()` logs failures instead of silently dropping them.
- `node/src/stigmem_node/routes/admin_audit.py` exposes the admin audit query
  surface.

**Test evidence**

- `node/tests/routes/test_admin_audit.py` covers authentication/authorization, fact
  write visibility, principal and event filters, pagination, time range
  filters, and response shape.
- `node/tests/observability/test_audit_enriched.py` covers enriched audit metadata.
- `node/tests/observability/test_quota.py` covers `quota_breach` audit emission.
- `node/tests/identity/test_capability_tokens.py` covers capability issue and
  revoke audit entries.

**Decision**

Accept as shipped control evidence for R-09 and R-10. Operational log
monitoring remains an operator responsibility, but the persistence and admin
query surfaces are implemented and tested.

## Capability-Token Validation

**Implementation evidence**

- `node/src/stigmem_node/identity/capability.py` verifies token JSON shape,
  token version, JCS signing body, Ed25519 signature, expiry, revocation state,
  manifest validity, and dual-trust rotation windows.
- The verification path raises `CapabilityTokenError` for structural or
  cryptographic failures.

**Test evidence**

- `node/tests/identity/test_capability_tokens.py` covers token issue/verify,
  invalid body cases, replay nonce constraints, revocation, TTL limits, and
  audit events.
- `node/tests/identity/test_federation_push.py` covers federation push
  behavior that depends on capability validation.
- `node/tests/federation/test_phase12_key_rotation.py` covers capability-token behavior
  across key rotation and dual-trust windows.

**Decision**

Accept as shipped control evidence for R-14. Broader prompt-injection
capability redesign remains tracked separately by ADR-003/R-05/R-15 and is not
part of this federation-control review.

## Key Rotation

**Implementation evidence**

- `node/src/stigmem_node/identity/key_rotation.py` generates new Ed25519 key
  material, signs rotation events with the retiring key, builds a new manifest,
  enforces a minimum 90-day dual-trust window, and writes transparency-log
  entries for rotation evidence.
- `node/src/stigmem_node/auth.py` enforces API-key expiry and max-age for
  authenticated callers.

**Test evidence**

- `node/tests/federation/test_phase12_key_rotation.py` covers key-id generation, rotation
  event signing, dry-run behavior, dual-trust validation, expired rotation
  windows, malformed rotation timestamps, and in-flight token acceptance during
  key rotation.
- `node/tests/auth/test_argon2_auth.py` covers API-key verification behavior and
  legacy-hash rehashing.

**Decision**

Accept as shipped control evidence for R-03 and R-10. The v1.0.0 GA retirement
of legacy SHA-256 verification remains tracked separately as the [ADR-007](../../docs/adr/archive/007-argon2id.md)
retirement item.

## Quota Buckets Migration

**Implementation evidence**

- `node/migrations/022_quota_buckets.sql` creates `quota_buckets` keyed by
  `(entity_uri, tenant_id, dimension)` and adds `fact_audit_log.seq` for
  audit ordering.
- `node/src/stigmem_node/rate_limit.py` lazily creates and updates bucket rows
  under `BEGIN IMMEDIATE`.

**Test evidence**

- `node/tests/observability/test_quota.py` exercises quota state creation, independent
  dimensions, retry behavior, bypass paths, and audit evidence on breaches.
- `node/tests/routes/test_admin_audit.py` exercises the `seq`-ordered audit export
  surface that depends on migration 022.

**Decision**

Accept as shipped control evidence for R-02 and R-12. No migration rewrite is
needed for this review.

## Follow-Up Issues

This review requires two follow-up implementation issues:

1. [#419](https://github.com/eidetic-labs/stigmem/issues/419): Federation mTLS should become the default production posture, and insecure
   federation should require `STIGMEM_FEDERATION_INSECURE=1` plus a startup
   warning.
2. [#420](https://github.com/eidetic-labs/stigmem/issues/420): Rate-limit kill-switch mode should emit a loud startup warning when both
   read and write rate limits are set to zero.

Both follow-ups are narrow patches. They should update public docs and
Internal-Comms when implemented.
