---
spec_id: Spec-02-Scopes-and-ACL
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 3.4 and 17 basic scope/ACL material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-02-Scopes-and-ACL

`Spec-02-Scopes-and-ACL` defines the supported visibility boundary for facts:
coarse `FactScope` enforcement plus the basic Memory Garden ACL layer retained
in the `v0.9.0a1` protocol line.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for scope enforcement and basic
Memory Garden ACL behavior. It intentionally does **not** include API-key
credential shape, peer-token signing, federation replication rules, quarantine
garden moderation, advanced Memory Garden ACL behavior, or HTTP route details.
Those belong to their own component or experimental specs.

Legacy section labels from archived sources are normalized to the current
`v0.9.0a1` protocol line. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Source Map

| Source material | Extracted here | Notes |
|---|---|---|
| `spec/archive/evolution/stigmem-spec-v0.8-draft.md` section 3.4 | Scope enforcement | The old stub pointed at section 3.5, but section 3.5 is identity/auth. |
| `spec/archive/evolution/stigmem-spec-v1.0.md` section 17 | Basic Memory Garden ACL | Quarantine and advanced ACL behavior are excluded. |
| `node/src/stigmem_node/garden_acl.py` and `node/tests/routes/test_gardens.py` | Implementation evidence | Confirms garden membership roles, read/write gates, hidden global-query behavior, and scope mismatch rejection. |

## Scope Enforcement

Scope is enforced at read and write time. Cross-scope queries are additive: a
caller may query across the scopes it is authorized to read, but authorization
must be evaluated per scope before any fact is returned.

The supported coarse scopes are defined by `FactScope` in
[`Spec-01-Fact-Model`](01-fact-model.md):

```text
local | team | company | public
```

Facts without a garden use scope-only access control. Facts with a `garden_id`
must also pass the Memory Garden ACL rules in this spec.

## Federation Boundary

Federation scope enforcement is defined in the federation-trust component, but
this spec owns the basic invariant:

- Nodes MUST NOT replicate facts whose `scope` is not permitted by the active
  peer relationship.
- Nodes MUST reject inbound facts whose `scope` exceeds what the peer is
  authorized to write.
- Scope enforcement is evaluated per hop in multi-node topologies.

The detailed peer declaration, token, and re-federation rules live in
`Spec-05-Federation-Trust`.

## Memory Garden Primitive

The coarse scope model is intentionally small. A Memory Garden adds a named,
ACL-controlled partition inside a scope, for cases where a subset of principals
needs shared access without exposing those facts to every reader of the broader
scope.

A garden is represented by a `Garden` record and a set of `GardenMember` records:

```text
Garden {
  id:          UUID
  garden_id:   URI
  slug:        string
  name:        string
  scope:       FactScope
  description: string?
  created_by:  URI
  created_at:  ISO 8601 UTC
}

GardenRole = "admin" | "writer" | "reader"

GardenMember {
  garden_id:  UUID
  entity_uri: URI
  role:       GardenRole
  added_by:   URI
  added_at:   ISO 8601 UTC
}
```

`garden_id` URIs use this shape:

```text
stigmem://{node_authority}/garden/{slug}
```

The slug is lowercased and validated on creation. A garden's `scope` is fixed at
creation time. All facts tagged with that garden MUST use the same scope.

## Write Access

Garden ACL is checked in addition to normal scope enforcement.

| Condition | Result |
|---|---|
| `garden_id` is absent | Use normal scope enforcement only; fact is not garden-tagged. |
| `garden_id` is present and caller is `admin` or `writer` | Allow the write if the fact scope matches the garden scope. |
| `garden_id` is present and caller is `reader` | Reject with HTTP 403. |
| `garden_id` is present and caller is not a member | Reject with HTTP 403. |
| `garden_id` is present and fact `scope` differs from garden `scope` | Reject with HTTP 422. |
| `garden_id` is present and garden is not found | Reject with HTTP 404. |

Writers and admins retract garden-tagged facts through the normal immutable
retraction pattern: assert a new fact for the same `(entity, relation, scope)`
with `confidence=0.0` and the same garden boundary.

## Read Access

A garden-tagged fact is returned only when the caller:

1. Passes normal scope enforcement.
2. Holds at least `reader` role in the garden.

When a caller queries by explicit `garden_id`, non-members receive HTTP 403.
When a caller performs a broader query without a `garden_id` filter,
garden-tagged facts from gardens the caller cannot read MUST be excluded from
the result set. This prevents garden enumeration through global queries.

Single-fact reads MUST enforce the same ACL. A caller who can guess or obtain a
fact id MUST NOT be able to bypass garden membership checks.

## Admin Operations

| Operation | Required role |
|---|---|
| Create garden | Any principal with node write permission. Creator becomes `admin`. |
| List accessible gardens | Any valid API key; non-admin callers see only gardens where they are members. |
| Read garden metadata | `reader`, `writer`, or `admin`; node admins may read all gardens. |
| Read member roster | `reader`, `writer`, or `admin`. |
| Add member | `admin`. |
| Change member role | `admin`. |
| Remove member | `admin`; removing the final admin is forbidden. |
| Delete garden | `admin`. |

Deleting a basic garden removes the garden container. It MUST NOT delete the
facts that were tagged with that garden.

## Relationship To Scope

Gardens and scopes are layered controls:

```text
Scope:   local | team | company | public
Garden:  named subset of principals within one scope
```

A garden's scope declares the coarse visibility tier of all facts in the garden.
Garden ACL can only narrow access relative to the scope; it cannot broaden it.

Examples:

- A `company`-scoped garden fact is not visible to every company-scope reader;
  the caller must also be a garden member.
- A `public`-scoped garden fact remains garden-controlled. Implementations MUST
  NOT use `public` scope alone as authorization to expose garden-tagged facts.
- Facts without `garden_id` are unaffected by garden ACL and continue to use
  scope-only enforcement.

## Reserved Garden Namespace

The `garden:` relation prefix is reserved for garden membership metadata. The
node writes membership metadata automatically when callers manage gardens.
System-authored garden membership facts use `source="system:stigmem"` so
attestation and provenance checks can distinguish operator-managed membership
from agent-authored assertions.

## Out Of Scope

This spec does not define:

- Garden CRUD endpoint paths or request/response shapes; those belong in
  `Spec-03-HTTP-API`.
- Federation peer declarations, peer tokens, and re-federation rules; those
  belong in `Spec-05-Federation-Trust`.
- Capability token grants; those belong in `Spec-06-Capability-Tokens`.
- Quarantine garden moderation roles and promote/reject behavior; those belong
  in `Spec-08-Quarantine-Garden`.
- Advanced Memory Garden ACL behavior; that remains experimental in
  `Spec-X5-Memory-Garden-Advanced-ACL`.
