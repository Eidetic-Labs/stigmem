---
spec_id: Spec-03-HTTP-API
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 5 API surface material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
---

# Spec-03-HTTP-API

<p className="stigmem-meta"><span>5 min read</span><span>Spec contributor · SDK author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The JSON-over-HTTP contract for the supported reference-node
surface: route shape, status-code families, pagination shape, and
endpoint grouping. Domain semantics for each route remain owned by
their component specs.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for the supported
HTTP API surface. It intentionally keeps detailed semantics in the
owning specs: fact-model rules in `Spec-01-Fact-Model`, scope and
garden ACL in `Spec-02-Scopes-and-ACL`, federation trust in
`Spec-05-Federation-Trust`, capability tokens in
`Spec-06-Capability-Tokens`, and quarantine moderation in
`Spec-08-Quarantine-Garden`.

Legacy version labels from archived sources are normalized to the
current `v0.9.0a1` protocol line.

## API style

<div className="stigmem-keypoint">

**All supported operations are JSON-over-HTTP.**

Clients do not need a Stigmem SDK to participate; any HTTP client
that can send JSON bodies and bearer tokens can use the API.

</div>

<div className="stigmem-grid">

<div><h4>JSON-only responses</h4><p>Unless the endpoint is explicitly documented as <code>204 No Content</code>.</p></div>
<div><h4>Stable error codes</h4><p>Error responses SHOULD include a stable machine-readable detail string or code.</p></div>
<div><h4>Cursor pagination</h4><p>Endpoints that return collections SHOULD use cursor pagination when the result set can grow without a small fixed bound.</p></div>

</div>

## Authentication

Authenticated routes use:

```http
Authorization: Bearer <token-or-api-key>
```

This spec defines the placement of credentials only. API-key
identity, capability-token verification, peer-token validation, and
admin/federate permission semantics are owned by their component
specs.

## Discovery

```http
GET /.well-known/stigmem
```

The discovery document advertises the node id, node URL,
authentication mode, supported namespaces, protocol/spec pointer,
and any advertised federation endpoints. Federation-enabled nodes
MUST include the public federation key and federation endpoint
paths needed for peer discovery.

## Fact operations

<div className="stigmem-fields">

<div>
<dt>Operation</dt>
<dt><span className="stigmem-fields__type">Route</span></dt>
<dd>Behavior</dd>
</div>

<div>
<dt>Assert fact</dt>
<dt><span className="stigmem-fields__type"><code>POST /v1/facts</code></span></dt>
<dd>Asserts one immutable fact. The request body carries the fact tuple fields owned by <code>Spec-01-Fact-Model</code>; the node stamps server-owned fields such as <code>id</code>, <code>timestamp</code>, and <code>hlc</code>. Success: <code>201 Created</code>.</dd>
</div>

<div>
<dt>Query facts</dt>
<dt><span className="stigmem-fields__type"><code>GET /v1/facts</code></span></dt>
<dd>Queries by <code>entity</code>, <code>relation</code>, <code>source</code>, <code>scope</code>, <code>min_confidence</code>, expiry/contradiction inclusion flags, cursor, and limit. Query-time normalization and ACL filtering must occur before results are returned. Success: <code>200 OK</code> with <code>facts</code>, <code>total</code>, and <code>cursor</code> fields.</dd>
</div>

<div>
<dt>Get fact</dt>
<dt><span className="stigmem-fields__type"><code>GET /v1/facts/&#123;id&#125;</code></span></dt>
<dd>Returns a single fact by id when the caller can read it. Garden-tagged facts must pass garden ACL. <code>200 OK</code>; missing → <code>404</code>; unauthorized garden access → <code>403</code>.</dd>
</div>

<div>
<dt>Retract</dt>
<dt><span className="stigmem-fields__type">via assert</span></dt>
<dd>Assert a new fact for the same <code>(entity, relation, scope)</code> with <code>confidence=0.0</code>. There is no destructive delete route for facts.</dd>
</div>

</div>

## Conflict operations

```http
GET /v1/conflicts
POST /v1/conflicts/{conflict_id}/resolve
```

<div className="stigmem-keypoint">

**Resolutions are additive.**

Original facts remain immutable, and the resolution itself is
recorded as fact data.

</div>

## Federation routes

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

The HTTP API owns these route shapes. Federation peer declaration
semantics, manifest verification, replication scope checks,
capability-token signing, and revocation behavior are owned by
`Spec-04`, `Spec-05`, and `Spec-06`.

Push replication is optional. Nodes that do not support push SHOULD
return `405 Method Not Allowed` for the push route or omit the push
route from discovery.

## Garden routes

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

## Lint and higher-order operations

```http
POST /v1/lint
POST /v1/synthesis
```

The lint route is part of the supported HTTP surface; lint behavior,
checks, filters, findings, and async job semantics are owned by
`Spec-20-Lint-Semantics`. Synthesis remains deferred/experimental
per the experimental synthesis spec and SHOULD NOT be treated as
stable solely because the route appeared in archived source material.

## Route ownership

<div className="stigmem-fields">

<div>
<dt>Route family</dt>
<dt><span className="stigmem-fields__type">HTTP shape</span></dt>
<dd>Semantic owner</dd>
</div>

<div>
<dt>Discovery</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd>Owning advertised component.</dd>
</div>

<div>
<dt>Fact assert/query/get</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-01-Fact-Model</code>, <code>Spec-02-Scopes-and-ACL</code>.</dd>
</div>

<div>
<dt>Conflicts</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd>Fact semantics component assignment TBD.</dd>
</div>

<div>
<dt>Federation peers/facts</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-05-Federation-Trust</code>.</dd>
</div>

<div>
<dt>Manifests</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-04-Manifests</code>.</dd>
</div>

<div>
<dt>Capability tokens</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-06-Capability-Tokens</code>.</dd>
</div>

<div>
<dt>Gardens</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-02-Scopes-and-ACL</code>.</dd>
</div>

<div>
<dt>Quarantine moderation</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-08-Quarantine-Garden</code>.</dd>
</div>

<div>
<dt>Lint</dt>
<dt><span className="stigmem-fields__type">Spec-03</span></dt>
<dd><code>Spec-20-Lint-Semantics</code>.</dd>
</div>

</div>

## Out of scope

This spec does not define the internal database schema, SDK
behavior, UI behavior, plugin hook contracts, or component-specific
validation rules.
