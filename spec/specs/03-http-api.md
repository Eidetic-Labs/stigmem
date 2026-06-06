---
spec_id: Spec-03-HTTP-API
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 5 API surface material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
---

# Spec-03-HTTP-API

`Spec-03-HTTP-API` defines the JSON-over-HTTP contract for the supported
reference-node surface. It owns route shape, status-code families, pagination
shape, and endpoint grouping. Domain semantics for each route remain owned by
their component specs.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for the supported HTTP API
surface. It intentionally keeps detailed semantics in the owning specs:
fact-model rules in `Spec-01-Fact-Model`, scope and garden ACL in
`Spec-02-Scopes-and-ACL`, federation trust in `Spec-05-Federation-Trust`,
capability tokens in `Spec-06-Capability-Tokens`, and quarantine moderation in
`Spec-08-Quarantine-Garden`.

Legacy version labels from archived sources are normalized to the current
`v0.9.0a1` protocol line. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## API Style

All supported operations are JSON-over-HTTP. Clients do not need a Stigmem SDK
to participate; any HTTP client that can send JSON bodies and bearer tokens can
use the API.

Responses MUST use JSON unless the endpoint is explicitly documented as empty
(`204 No Content`). Error responses SHOULD include a stable machine-readable
detail string or code. Endpoints that return collections SHOULD use cursor
pagination when the result set can grow without a small fixed bound.

## Authentication

Authenticated routes use:

```http
Authorization: Bearer <token-or-api-key>
```

This spec defines the placement of credentials only. API-key identity,
capability-token verification, peer-token validation, and admin/federate
permission semantics are owned by their component specs.

## Discovery

```http
GET /.well-known/stigmem
```

The discovery document advertises the node id, node URL, authentication mode,
supported namespaces, protocol/spec pointer, and any advertised federation
endpoints. Federation-enabled nodes MUST include the public federation key and
federation endpoint paths needed for peer discovery.

## Fact Operations

### Assert Fact

```http
POST /v1/facts
```

Asserts one immutable fact. The request body carries the fact tuple fields owned
by `Spec-01-Fact-Model`; the node stamps server-owned fields such as `id`,
`timestamp`, and `hlc`.

Success: `201 Created` with the created fact record.

### Query Facts

```http
GET /v1/facts
```

Queries facts by fact dimensions such as `entity`, `relation`, `source`,
`scope`, `min_confidence`, expiry/contradiction inclusion flags, cursor, and
limit. Query-time normalization and ACL filtering must occur before results are
returned.

Success: `200 OK` with `facts`, `total`, and `cursor` fields.

### Get Fact

```http
GET /v1/facts/{id}
```

Returns a single fact by id when the caller can read it. Garden-tagged facts
must pass garden ACL before being returned.

Success: `200 OK`; missing facts return `404 Not Found`; unauthorized garden
access returns `403 Forbidden`.

### Retract Fact

Retraction uses the normal fact assertion route by asserting a new fact for the
same `(entity, relation, scope)` with `confidence=0.0`. There is no destructive
delete route for facts.

## Conflict Operations

```http
GET /v1/conflicts
POST /v1/conflicts/{conflict_id}/resolve
```

Conflict routes expose contradictions detected between facts and allow an
authorized caller to record a resolution. Resolutions are additive: original
facts remain immutable, and the resolution itself is recorded as fact data.

## Federation Routes

```http
POST /v1/federation/peers
GET /v1/federation/peers
GET /v1/federation/facts
POST /v1/federation/facts/push
PUT /v1/federation/manifest
GET /v1/federation/manifest/{entity_uri_encoded}
POST /v1/federation/capability-tokens
POST /v1/federation/capability-tokens/{token_id}/revoke
```

The HTTP API owns these route shapes. Federation peer declaration semantics,
manifest verification, replication scope checks, capability-token signing, and
revocation behavior are owned by `Spec-04`, `Spec-05`, and `Spec-06`.

Push replication is optional. Nodes that do not support push SHOULD return
`405 Method Not Allowed` for the push route or omit the push route from
discovery.

## Garden Routes

```http
POST /v1/gardens
GET /v1/gardens
GET /v1/gardens/{garden_slug_or_id}
DELETE /v1/gardens/{garden_slug_or_id}
GET /v1/gardens/{garden_slug_or_id}/members
POST /v1/gardens/{garden_slug_or_id}/members
PATCH /v1/gardens/{garden_slug_or_id}/members/{entity_uri}
DELETE /v1/gardens/{garden_slug_or_id}/members/{entity_uri}
POST /v1/gardens/{quarantine_garden_id}/promote
POST /v1/gardens/{quarantine_garden_id}/reject
```

Basic garden CRUD and membership routes serve `Spec-02-Scopes-and-ACL`.
Quarantine promote/reject routes serve `Spec-08-Quarantine-Garden`.

## Lint And Higher-Order Operations

```http
POST /v1/lint
POST /v1/synthesis
```

The lint route is part of the supported HTTP surface; lint behavior, checks,
filters, findings, and async job semantics are owned by
`Spec-20-Lint-Semantics`. Synthesis remains deferred/experimental per the
experimental synthesis spec and SHOULD NOT be treated as stable solely because
the route appeared in archived source material.

## Route Ownership

| Route family | HTTP shape owner | Semantic owner |
|---|---|---|
| Discovery | `Spec-03-HTTP-API` | Owning advertised component |
| Fact assert/query/get | `Spec-03-HTTP-API` | `Spec-01-Fact-Model`, `Spec-02-Scopes-and-ACL` |
| Conflicts | `Spec-03-HTTP-API` | Fact semantics component assignment TBD |
| Federation peers/facts | `Spec-03-HTTP-API` | `Spec-05-Federation-Trust` |
| Manifests | `Spec-03-HTTP-API` | `Spec-04-Manifests` |
| Capability tokens | `Spec-03-HTTP-API` | `Spec-06-Capability-Tokens` |
| Gardens | `Spec-03-HTTP-API` | `Spec-02-Scopes-and-ACL` |
| Quarantine moderation | `Spec-03-HTTP-API` | `Spec-08-Quarantine-Garden` |
| Lint | `Spec-03-HTTP-API` | `Spec-20-Lint-Semantics` |

## Out Of Scope

This spec does not define the internal database schema, SDK behavior, UI
behavior, plugin hook contracts, or component-specific validation rules.
