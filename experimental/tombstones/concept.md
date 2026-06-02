---
title: Right to Be Forgotten (RTBF)
sidebar_label: RTBF Tombstones
audience: Integrator
---

# Right to Be Forgotten (RTBF)

**Audience:** Node operators handling GDPR Art. 17 / CCPA 1798.105 erasure requests.

:::caution Experimental source package

RTBF tombstones are not part of the v0.9.0a1 default install and are not a supported compliance surface. The source package lives under `experimental/tombstones/` and only becomes active when `stigmem-plugin-tombstones` is explicitly registered/configured. Default installs mount tombstone admin and federation route contracts but keep them access-gated, and do not apply tombstone filters.

Signed package publication, launch evidence, and operator-ready artifact verification are deferred to the all-plugins launch lane. Treat the API and CLI examples below as the target plugin-loaded workflow, not default-install behavior.

:::

## Overview

The experimental tombstone design models erasure via **tombstones** rather than physical deletion. A tombstone marks
an entity URI (and optionally a specific scope) as erased. Once tombstoned:

- Facts for the entity are excluded from all query and recall results.
- Subscription deliveries for the entity are suppressed.
- Federation peers receive the tombstone and apply it locally.
- The underlying rows remain in the database for audit and legal-hold purposes.

The full protocol is defined in `Spec-X2-RTBF-Tombstones`.

---

## Target workflow: creating a tombstone

### Via CLI

```bash
stigmem fact tombstone --entity-uri "user:alice@example.com" --reason "GDPR Art. 17 request"
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--entity-uri` | (required) | Entity URI to tombstone |
| `--scope` | `*` | Scope pattern — `*` covers all scopes, or provide a specific scope |
| `--reason` | `null` | Human-readable reason (stored but not included in signature) |
| `--legal-hold` | `false` | Preserve facts for admin `as_of` queries (spec section 24) |

### Via API

```http
POST /v1/tombstones
Authorization: Bearer <admin-key>
Content-Type: application/json

{
  "entity_uri": "user:alice@example.com",
  "scope": "*",
  "reason": "GDPR Art. 17 request",
  "legal_hold": false
}
```

Response (201 Created):

```json
{
  "id": "tomb_a1b2c3d4-...",
  "entity_uri": "user:alice@example.com",
  "scope": "*",
  "signed_by": "stigmem://your-node/admin",
  "key_id": "sha256hexofkey...",
  "signature": "base64url-ed25519-sig",
  "created_at": "2026-05-04T12:00:00+00:00",
  "legal_hold": false
}
```

The tombstone is cryptographically signed with the node's Ed25519 federation key. The `key_id`
field is the SHA-256 hex digest of the signing public key (spec section 23.2.1 rev 14 F-8).

---

## Checking tombstone status

```http
GET /v1/tombstones/{entity_uri_encoded}
Authorization: Bearer <admin-key>
```

Returns active tombstones and any revocations for the entity.

---

## Revoking a tombstone

Revocation reinstates facts without deleting the tombstone audit trail:

```http
POST /v1/tombstones/{tombstone_id}/revoke
Authorization: Bearer <admin-key>
Content-Type: application/json

{
  "reason": "Erasure request withdrawn by data subject"
}
```

After revocation, facts for the entity reappear in query results on the next cache refresh
(within 60 seconds).

---

## Scope patterns

| Pattern | Effect |
|---------|--------|
| `*` | Tombstones the entity across all scopes |
| `project:acme` | Only tombstones facts in the `project:acme` scope |

A wildcard tombstone (`*`) suppresses facts regardless of their individual scope.
A scoped tombstone only suppresses facts whose scope matches exactly.

---

## Legal hold

When `legal_hold: true`:

- Facts are still excluded from normal queries and recall.
- Admin callers using the `as_of` time-travel API (spec section 24) can still retrieve the facts.
- Tombstone notices are returned in query metadata to signal the hold exists.

Use legal hold when retention is required for litigation or regulatory investigation while
still honouring the erasure request for normal access paths.

---

## Federation propagation

Federation propagation is part of the target plugin-loaded design. It is not active in default installs, and operators should not rely on it for production RTBF compliance until the feature passes the ADR-008 gates.

Tombstones propagate automatically to federation peers:

1. **Outbound push:** On creation, the node immediately pushes the tombstone to all active peers
   via `POST /v1/federation/tombstones/ingest`.
2. **Inbound poll:** Peers periodically poll `GET /v1/federation/tombstones?since=<cursor>` during
   their federation pull loop.
3. **Signature verification:** Receiving nodes verify the Ed25519 signature against the issuing
   node's org manifest before applying the tombstone locally.

### Capability token

The federation tombstone poll route requires a `tombstone:read` capability token when
`trust_mode` is not `off`. Peers obtain this token during the standard federation handshake.

---

## Recall-time filtering

The tombstone filter operates with a 60-second in-process LRU cache (spec section 23.3.3 rule 4).
After creating or revoking a tombstone, the cache is invalidated immediately on the local node.
Remote peers will pick up changes within their pull interval plus the cache TTL.

Query pagination totals are computed post-filter to prevent oracle leakage of tombstoned
entity existence (spec section 23.3.3 rule 3).

---

## Signing details

Tombstones are signed using JCS (RFC 8785) canonical JSON serialization with the `signature`
and `reason` fields excluded from the signing body. The Ed25519 signature is base64url-encoded.

To verify a tombstone manually:

1. Reconstruct the signing body: all fields of the tombstone record except `signature` and `reason`.
2. Canonicalize with JCS (RFC 8785).
3. Verify the Ed25519 signature against the public key identified by `key_id`.

---

## Operations checklist

- [ ] Ensure federation keys are generated (`STIGMEM_FEDERATION_PUBKEY` / `STIGMEM_FEDERATION_PRIVKEY`)
- [ ] Verify admin API key has `write` and `federate` permissions
- [ ] Confirm federation peers are registered and active
- [ ] Test tombstone creation in a staging environment before production
- [ ] Monitor audit logs for `tombstone_created` and `tombstone_propagated` events
- [ ] Document your organization's RTBF SLA (typical: 72 hours per GDPR)

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Facts still appear after tombstone | Cache TTL (up to 60s) | Wait for cache expiry or restart the node |
| Federation peer doesn't apply tombstone | Signature verification failed | Check that the issuing node's org manifest is resolvable by the peer |
| 401 on tombstone creation | Missing admin permissions | Ensure API key has `write` + `federate` scopes |
| Tombstone not propagating | No active peers | Check `GET /v1/federation/peers` for peer status |
| Revocation has no effect | Double-revoke returns 409 | Tombstone was already revoked; check status endpoint |
