---
spec_id: Spec-02-Scopes-and-ACL
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 3.4 and 17 basic scope/ACL material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-02-Scopes-and-ACL

<p className="stigmem-meta"><span>5 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The supported visibility boundary for facts: coarse `FactScope`
enforcement plus the basic Memory Garden ACL layer retained in the
`v0.9.0a1` protocol line.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for scope
enforcement and basic Memory Garden ACL behavior. It intentionally
does **not** include API-key credential shape, peer-token signing,
federation replication rules, quarantine garden moderation, advanced
Memory Garden ACL behavior, or HTTP route details. Those belong to
their own component or experimental specs.

Legacy section labels from archived sources are normalized to the
current `v0.9.0a1` protocol line. Historical wording remains
available in `spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Source map

<div className="stigmem-fields">

<div>
<dt>Source material</dt>
<dt><span className="stigmem-fields__type">Extracted</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>stigmem-spec-v0.8-draft.md</code> §3.4</dt>
<dt><span className="stigmem-fields__type">scope enforcement</span></dt>
<dd>The old stub pointed at section 3.5, but section 3.5 is identity/auth.</dd>
</div>

<div>
<dt><code>stigmem-spec-v1.0.md</code> §17</dt>
<dt><span className="stigmem-fields__type">basic Memory Garden ACL</span></dt>
<dd>Quarantine and advanced ACL behavior are excluded.</dd>
</div>

<div>
<dt><code>garden_acl.py</code> + <code>test_gardens.py</code></dt>
<dt><span className="stigmem-fields__type">implementation evidence</span></dt>
<dd>Confirms garden membership roles, read/write gates, hidden global-query behavior, and scope mismatch rejection.</dd>
</div>

</div>

## Scope enforcement

<div className="stigmem-keypoint">

**Scope is enforced at read and write time.**

Cross-scope queries are additive: a caller may query across the
scopes it is authorized to read, but authorization must be evaluated
per scope before any fact is returned.

</div>

The supported coarse scopes are defined by `FactScope` in
[`Spec-01-Fact-Model`](fact-model):

```text
local | team | company | public
```

Facts without a garden use scope-only access control. Facts with a
`garden_id` must also pass the Memory Garden ACL rules in this spec.

## Federation boundary

Federation scope enforcement is defined in the federation-trust
component, but this spec owns the basic invariant:

<div className="stigmem-grid">

<div><h4>No over-scope replication</h4><p>Nodes MUST NOT replicate facts whose <code>scope</code> is not permitted by the active peer relationship.</p></div>
<div><h4>Reject over-scope inbound</h4><p>Nodes MUST reject inbound facts whose <code>scope</code> exceeds what the peer is authorized to write.</p></div>
<div><h4>Per-hop evaluation</h4><p>Scope enforcement is evaluated per hop in multi-node topologies.</p></div>

</div>

The detailed peer declaration, token, and re-federation rules live
in `Spec-05-Federation-Trust`.

## Memory Garden primitive

The coarse scope model is intentionally small. A Memory Garden adds
a named, ACL-controlled partition inside a scope, for cases where a
subset of principals needs shared access without exposing those
facts to every reader of the broader scope.

A garden is represented by a `Garden` record and a set of
`GardenMember` records:

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

<div className="stigmem-keypoint">

**A garden's `scope` is fixed at creation time. All facts tagged with that garden MUST use the same scope.**

</div>

## Write access

Garden ACL is checked in addition to normal scope enforcement.

<div className="stigmem-fields">

<div>
<dt>Condition</dt>
<dt><span className="stigmem-fields__type">Result</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>garden_id</code> absent</dt>
<dt><span className="stigmem-fields__type">scope-only</span></dt>
<dd>Use normal scope enforcement only; fact is not garden-tagged.</dd>
</div>

<div>
<dt>caller is <code>admin</code>/<code>writer</code></dt>
<dt><span className="stigmem-fields__type">allowed</span></dt>
<dd>Allow the write if the fact scope matches the garden scope.</dd>
</div>

<div>
<dt>caller is <code>reader</code></dt>
<dt><span className="stigmem-fields__type">HTTP 403</span></dt>
<dd>Forbidden.</dd>
</div>

<div>
<dt>caller is non-member</dt>
<dt><span className="stigmem-fields__type">HTTP 403</span></dt>
<dd>Forbidden.</dd>
</div>

<div>
<dt>fact scope ≠ garden scope</dt>
<dt><span className="stigmem-fields__type">HTTP 422</span></dt>
<dd>Unprocessable entity.</dd>
</div>

<div>
<dt>garden not found</dt>
<dt><span className="stigmem-fields__type">HTTP 404</span></dt>
<dd>Not found.</dd>
</div>

</div>

Writers and admins retract garden-tagged facts through the normal
immutable retraction pattern: assert a new fact for the same
`(entity, relation, scope)` with `confidence=0.0` and the same
garden boundary.

## Read access

A garden-tagged fact is returned only when the caller:

<ol className="stigmem-steps">
<li>Passes normal scope enforcement.</li>
<li>Holds at least <code>reader</code> role in the garden.</li>
</ol>

<div className="stigmem-keypoint">

**Garden enumeration through global queries MUST be prevented.**

When a caller queries by explicit `garden_id`, non-members receive
HTTP 403. When a caller performs a broader query without a
`garden_id` filter, garden-tagged facts from gardens the caller
cannot read MUST be excluded from the result set. Single-fact reads
MUST enforce the same ACL: a caller who can guess or obtain a fact
id MUST NOT be able to bypass garden membership checks.

</div>

## Admin operations

<div className="stigmem-fields">

<div>
<dt>Operation</dt>
<dt><span className="stigmem-fields__type">Required role</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Create garden</dt>
<dt><span className="stigmem-fields__type">node write perm</span></dt>
<dd>Any principal with node write permission. Creator becomes <code>admin</code>.</dd>
</div>

<div>
<dt>List accessible gardens</dt>
<dt><span className="stigmem-fields__type">any valid API key</span></dt>
<dd>Non-admin callers see only gardens where they are members.</dd>
</div>

<div>
<dt>Read garden metadata</dt>
<dt><span className="stigmem-fields__type">reader / writer / admin</span></dt>
<dd>Node admins may read all gardens.</dd>
</div>

<div>
<dt>Read member roster</dt>
<dt><span className="stigmem-fields__type">reader / writer / admin</span></dt>
<dd>—</dd>
</div>

<div>
<dt>Add / remove / change role</dt>
<dt><span className="stigmem-fields__type">admin</span></dt>
<dd>Removing the final admin is forbidden.</dd>
</div>

<div>
<dt>Delete garden</dt>
<dt><span className="stigmem-fields__type">admin</span></dt>
<dd>—</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Deleting a basic garden removes the garden container. It MUST NOT delete the facts that were tagged with that garden.**

</div>

## Relationship to scope

Gardens and scopes are layered controls:

```text
Scope:   local | team | company | public
Garden:  named subset of principals within one scope
```

A garden's scope declares the coarse visibility tier of all facts in
the garden. Garden ACL can only narrow access relative to the scope;
it cannot broaden it.

<div className="stigmem-grid">

<div><h4>Company-scoped garden fact</h4><p>Not visible to every company-scope reader; the caller must also be a garden member.</p></div>
<div><h4>Public-scoped garden fact</h4><p>Remains garden-controlled. Implementations MUST NOT use <code>public</code> scope alone as authorization to expose garden-tagged facts.</p></div>
<div><h4>Untagged facts</h4><p>Facts without <code>garden_id</code> are unaffected by garden ACL and continue to use scope-only enforcement.</p></div>

</div>

## Reserved garden namespace

The `garden:` relation prefix is reserved for garden membership
metadata. The node writes membership metadata automatically when
callers manage gardens. System-authored garden membership facts use
`source="system:stigmem"` so attestation and provenance checks can
distinguish operator-managed membership from agent-authored
assertions.

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Garden CRUD route shape</h4><p>Belongs in <code>Spec-03-HTTP-API</code>.</p></div>
<div><h4>Peer declarations / tokens</h4><p>Belong in <code>Spec-05-Federation-Trust</code>.</p></div>
<div><h4>Capability token grants</h4><p>Belong in <code>Spec-06-Capability-Tokens</code>.</p></div>
<div><h4>Quarantine moderation</h4><p>Belongs in <code>Spec-08-Quarantine-Garden</code>.</p></div>
<div><h4>Advanced Memory Garden ACL</h4><p>Experimental: <code>Spec-X5-Memory-Garden-Advanced-ACL</code>.</p></div>

</div>
