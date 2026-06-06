---
spec_id: Spec-01-Fact-Model
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 2 fact-model material
depends_on: []
---

# Spec-01-Fact-Model

<p className="stigmem-meta"><span>5 min read</span><span>Spec contributor · SDK author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The atomic fact record, typed values, scopes, reification pattern,
Hybrid Logical Clock field, and entity URI normalization rules used
by the `v0.9.0a1` protocol line.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for the fact model
component. It intentionally does **not** include HTTP routes, schema
migrations, adapter ABI, lint semantics, or CID behavior; those
belong in their own component specs.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Atomic fact shape

<div className="stigmem-keypoint">

**Every piece of knowledge in Stigmem is an atomic fact.**

A fact is immutable once written. Updates are expressed as new
facts. The latest fact for a given `(entity, relation, scope)`
triple wins unless contradiction policy applies in the fact-semantics
spec.

</div>

```text
(entity, relation, value, source, timestamp, hlc, confidence, scope)
```

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Type</span></dt>
<dd>Description</dd>
</div>

<div>
<dt><code>entity</code></dt>
<dt><span className="stigmem-fields__type">URI</span></dt>
<dd>What this fact is about. Formal: <code>stigmem://company.example/user/alice</code>. Informal forms such as <code>user:alice</code> are deprecated. Stored in canonical normalized form.</dd>
</div>

<div>
<dt><code>relation</code></dt>
<dt><span className="stigmem-fields__type">string</span></dt>
<dd>Namespaced predicate. Examples: <code>memory:role</code>, <code>roadmap:status</code>, <code>preference:timezone</code>.</dd>
</div>

<div>
<dt><code>value</code></dt>
<dt><span className="stigmem-fields__type">FactValue</span></dt>
<dd>The asserted typed value.</dd>
</div>

<div>
<dt><code>source</code></dt>
<dt><span className="stigmem-fields__type">URI</span></dt>
<dd>Who asserted the fact. Examples: <code>stigmem://company.example/agent/assistant</code>, <code>stigmem://company.example/user/alice</code>. Stored in canonical normalized form.</dd>
</div>

<div>
<dt><code>timestamp</code></dt>
<dt><span className="stigmem-fields__type">ISO 8601 UTC</span></dt>
<dd>Wall-clock time when the fact was asserted. Set by the node at write time; clients may suggest.</dd>
</div>

<div>
<dt><code>hlc</code></dt>
<dt><span className="stigmem-fields__type">HLC string</span></dt>
<dd>Hybrid Logical Clock timestamp. Causality-preserving; required for federation.</dd>
</div>

<div>
<dt><code>valid_until</code></dt>
<dt><span className="stigmem-fields__type">ISO 8601 UTC or null</span></dt>
<dd>Optional expiry. If set, the fact is expired after this time.</dd>
</div>

<div>
<dt><code>confidence</code></dt>
<dt><span className="stigmem-fields__type">float [0.0, 1.0]</span></dt>
<dd>Asserting party's confidence. <code>1.0</code> means certain, <code>0.5</code> uncertain, <code>0.0</code> retracted.</dd>
</div>

<div>
<dt><code>scope</code></dt>
<dt><span className="stigmem-fields__type">FactScope</span></dt>
<dd>Visibility / federation boundary.</dd>
</div>

</div>

## FactValue

`FactValue` is a discriminated union that constrains what a fact can
assert. The `type` tag forces consumers to handle each variant
explicitly so queries, indexing, and synthesis can operate on typed
data without runtime introspection.

```text
FactValue =
  | { type: "string",    v: string }
  | { type: "text",      v: string }
  | { type: "number",    v: number }
  | { type: "boolean",   v: boolean }
  | { type: "datetime",  v: ISO8601 }
  | { type: "ref",       v: URI }
  | { type: "null" }
```

<div className="stigmem-keypoint">

**The `string` vs `text` distinction is load-bearing.**

Nodes index `string` values for exact-match queries. `text` values
feed semantic recall when an embedding pipeline is enabled. The
`ref` type creates typed edges in the knowledge graph.

</div>

Inline `text` values SHOULD be 64 KB or less. For larger payloads,
assert a `ref` fact pointing to external storage and keep the text
value as a summary. Nodes MAY reject `text` values above their
configured limit and MUST return HTTP 413 if they do.

## FactScope

Scope is the visibility fence that determines which facts leave a
node during federation. It is a single string enum because the
common case is simple and more complex propagation rules build on
top of this primitive.

```text
FactScope =
  | "local"
  | "team"
  | "company"
  | "public"
```

<div className="stigmem-fields">

<div>
<dt>Scope</dt>
<dt><span className="stigmem-fields__type">Federation</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>local</code></dt>
<dt><span className="stigmem-fields__type">never federated</span></dt>
<dd>Visible only within this node.</dd>
</div>

<div>
<dt><code>team</code></dt>
<dt><span className="stigmem-fields__type">never federated</span></dt>
<dd>Visible within a logical team boundary.</dd>
</div>

<div>
<dt><code>company</code></dt>
<dt><span className="stigmem-fields__type">opt-in</span></dt>
<dd>Visible within the owning company node. Federated only when the active peer declaration explicitly includes <code>company</code> in its allowed scopes.</dd>
</div>

<div>
<dt><code>public</code></dt>
<dt><span className="stigmem-fields__type">federatable</span></dt>
<dd>Federatable to any peer with an active handshake.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Nodes MUST NOT federate `local` or `team` facts without explicit operator override.**

</div>

## Reification

The fact tuple is binary: one entity, one relation, one value.
N-ary relationships are represented by minting a synthetic
relationship entity and asserting participant facts about that
entity.

```text
(entity="stigmem:rel:abc123", relation="rel:subject", value={type:"ref", v:"stigmem://company.example/company/a"})
(entity="stigmem:rel:abc123", relation="rel:object",  value={type:"ref", v:"stigmem://company.example/company/b"})
(entity="stigmem:rel:abc123", relation="rel:type",    value={type:"string", v:"policy:board-approval"})
```

`rel:subject`, `rel:object`, and `rel:type` are reserved in the
`rel:` namespace. Graph traversal follows `ref` values out of
reified entities the same way it follows any other `ref`, so
reified relationships participate naturally in recall.

## Hybrid Logical Clock

Wall-clock timestamps alone cannot establish causality in a
distributed system because clocks drift. A pure logical clock
preserves causality but loses correlation with real time. Stigmem
uses a Hybrid Logical Clock (HLC) that combines both.

```text
HLC = wall_ms || counter
```

Wire format: `{wall_ms_utc}.{counter}`, for example
`1746230400000.003`. The string encoding uses a dot separator so
lexicographic comparison produces correct causal ordering without
parsing. `wall_ms` is zero-padded to 13 digits; `counter` is
zero-padded to 3 digits per node.

**Advance rules.**

<ol className="stigmem-steps">
<li>On local write: <code>hlc = max(now_ms, last_hlc_ms)</code> as <code>wall_ms</code>; increment <code>counter</code> if <code>wall_ms</code> is unchanged.</li>
<li>On receiving a federated fact: <code>hlc = max(now_ms, received_hlc_ms)</code> as <code>wall_ms</code>; increment <code>counter</code>.</li>
</ol>

<div className="stigmem-keypoint">

**Two facts `a` and `b` are causally ordered if `a.hlc < b.hlc`.**

Equal HLCs on different nodes indicate concurrent writes;
contradiction policy applies.

</div>

## Entity URI scheme

Entity URIs use this formal shape:

```text
stigmem://{authority}/{type}/{id}
```

<div className="stigmem-fields">

<div>
<dt>Component</dt>
<dt><span className="stigmem-fields__type">Examples</span></dt>
<dd>Description</dd>
</div>

<div>
<dt><code>authority</code></dt>
<dt><span className="stigmem-fields__type"><code>company.example</code></span></dt>
<dd>Hostname of the Stigmem node that owns this entity namespace.</dd>
</div>

<div>
<dt><code>type</code></dt>
<dt><span className="stigmem-fields__type"><code>user</code>, <code>agent</code>, <code>project</code></span></dt>
<dd>Entity type slug, lowercase with no spaces.</dd>
</div>

<div>
<dt><code>id</code></dt>
<dt><span className="stigmem-fields__type"><code>alice</code>, <code>eg-42</code></span></dt>
<dd>Opaque stable identifier for the entity.</dd>
</div>

</div>

Examples:

<div className="stigmem-grid">

<div><h4><code>stigmem://company.example/user/alice</code></h4></div>
<div><h4><code>stigmem://company.example/agent/cto</code></h4></div>
<div><h4><code>stigmem://company.example/issue/eg-42</code></h4></div>
<div><h4><code>stigmem://node.acme/decision/use-sqlite</code></h4></div>

</div>

<div className="stigmem-keypoint">

**Informal URIs (`user:alice`, `agent:cto`) are deprecated in the `v0.9.0a1` line.**

Nodes MAY accept informal URIs for backward compatibility and SHOULD
emit deprecation warnings when they do. Adapters targeting
`v0.9.0a1` or later SHOULD use formal URIs for all new fact
assertions and MUST NOT emit informal URIs in new code.

</div>

## Entity naming rules

The node applies a strict normalizer at ingest to prevent case-based
and whitespace-based fragmentation. Full alias resolution, such as
treating `user:alice` and `user:a.smith` as equivalent, is a
deferred resolver concern and is not part of this fact model.

**Canonical form.**

<ol className="stigmem-steps">
<li>Trim leading/trailing whitespace from <code>entity</code> and <code>source</code>.</li>
<li>Collapse internal ASCII whitespace runs to a single hyphen in path segments.</li>
<li>Lowercase the URI scheme, authority, type, and id components.</li>
<li>Percent-decode unreserved URI characters, then re-encode path segments using RFC 3986 unreserved set only.</li>
<li>Reject empty type or id segments.</li>
</ol>

**Examples.**

<div className="stigmem-fields">

<div>
<dt>Input</dt>
<dt><span className="stigmem-fields__type">→</span></dt>
<dd>Canonical</dd>
</div>

<div>
<dt><code> stigmem://Company.Example/User/Alice </code></dt>
<dt><span className="stigmem-fields__type">→</span></dt>
<dd><code>stigmem://company.example/user/alice</code></dd>
</div>

<div>
<dt><code>stigmem://company.example/Issue/EG-42</code></dt>
<dt><span className="stigmem-fields__type">→</span></dt>
<dd><code>stigmem://company.example/issue/eg-42</code></dd>
</div>

<div>
<dt><code>user:Alice Smith</code></dt>
<dt><span className="stigmem-fields__type">→</span></dt>
<dd><code>user:alice-smith</code></dd>
</div>

</div>

**Node behavior.**

<div className="stigmem-grid">

<div><h4>Normalize at ingest</h4><p>Ingest MUST normalize <code>entity</code> and <code>source</code> before persistence.</p></div>
<div><h4>Reject empty segments</h4><p>Ingest MUST reject formal URIs with empty authority, type, or id.</p></div>
<div><h4>Normalize query params</h4><p>Query parameters for <code>entity</code> and <code>source</code> MUST be normalized before matching.</p></div>
<div><h4>No rewrite of history</h4><p>Nodes SHOULD provide migration tooling for legacy non-canonical entities, but MUST NOT rewrite immutable historical facts in place.</p></div>

</div>
