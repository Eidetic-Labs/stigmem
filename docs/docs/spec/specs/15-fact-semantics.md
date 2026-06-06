---
spec_id: Spec-15-Fact-Semantics
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 3 fact-semantics material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
---

# Spec-15-Fact-Semantics

<p className="stigmem-meta"><span>4 min read</span><span>Spec contributor · SDK author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The supported behavior of facts after they are written: provenance,
expiry, contradiction detection, query-time winner selection, and
conflict entities.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for fact semantics.
Atomic fact shape is owned by `Spec-01-Fact-Model`; scope
enforcement is owned by `Spec-02-Scopes-and-ACL`; HTTP route shape
is owned by `Spec-03-HTTP-API`.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Provenance

<div className="stigmem-keypoint">

**Every fact carries `source` and `timestamp`. A node MUST store both without modification.**

Query responses MUST return the original `source`; relay metadata
MUST NOT replace the original source.

</div>

Inbound federated facts SHOULD record receiving-node provenance
separately from the original source. The receiving node MAY assert a
local meta-fact:

```text
entity=<fact-id>
relation="stigmem:received_from"
value={type:"ref", v:"<originating-node-id>"}
source="system:stigmem"
```

The receiving-node provenance fact is local accounting and MUST NOT
be re-replicated as if it were part of the origin peer's assertion
set.

## Expiry

Facts whose `valid_until` timestamp has passed MUST NOT be returned
by ordinary fact queries. A caller MAY request expired facts with an
explicit `include_expired=true` option on routes that support it.

Expired facts remain in the store. Expiry is a read-filtering and
operational health concern, not a destructive deletion rule.

## TTL meta-facts

Operators or agents that need to schedule future expiry for a fact
that was originally asserted without `valid_until` MAY attach a TTL
meta-fact. The meta-fact's entity is the target fact id, the relation
is `stigmem:ttl`, and the value is the intended expiry datetime:

```text
entity=<fact-id>
relation="stigmem:ttl"
value={type:"datetime", v:<expiry>}
```

<div className="stigmem-keypoint">

**`valid_until` and `confidence` are orthogonal.**

A historical certain fact may have `confidence=1.0` and a
`valid_until` timestamp that marks when it stopped being current.

</div>

## Contradiction detection

A contradiction exists when two facts `a` and `b` satisfy all of:

<div className="stigmem-grid">

<div><h4>Same entity</h4><p><code>a.entity == b.entity</code></p></div>
<div><h4>Same relation</h4><p><code>a.relation == b.relation</code></p></div>
<div><h4>Same scope</h4><p><code>a.scope == b.scope</code></p></div>
<div><h4>Different value</h4><p><code>a.value != b.value</code></p></div>
<div><h4>Both confident</h4><p><code>a.confidence &gt; 0.0</code> AND <code>b.confidence &gt; 0.0</code></p></div>

</div>

<div className="stigmem-keypoint">

**Both facts MUST be retained. Nodes MUST NOT silently overwrite one fact with the other.**

Entity normalization from `Spec-01-Fact-Model` applies before
contradiction detection. Facts written with different raw entity
strings that normalize to the same canonical entity participate in
the same contradiction set.

</div>

## Query-time resolution

When a query needs a single preferred fact for a contradicted
`(entity, relation, scope)` tuple, nodes SHOULD apply this ordering:

<ol className="stigmem-steps">
<li>Higher <code>confidence</code> wins.</li>
<li>Equal confidence: higher HLC wins.</li>
<li>Equal confidence and HLC: return both with <code>contradicted: true</code> and let the caller decide.</li>
</ol>

This ordering does not delete or mutate losing facts. It only
controls presentation and default winner selection.

## Conflict entities

When a contradiction is detected on write, a node SHOULD create a
first-class conflict entity in the `stigmem:conflict:` namespace. The
conflict entity reifies disagreement as queryable data.

The conflict relation links the competing fact ids:

```text
entity="stigmem:conflict:<uuid>"
relation="stigmem:conflict:between"
value={type:"text", v:"<fact-id-a> <fact-id-b>"}
source="system:stigmem"
confidence=1.0
scope=<same scope as the conflicting facts>
```

A companion status fact tracks resolution state:

```text
entity="stigmem:conflict:<uuid>"
relation="stigmem:conflict:status"
value={type:"string", v:"unresolved"}
source="system:stigmem"
confidence=1.0
scope=<same scope as the conflicting facts>
```

<div className="stigmem-keypoint">

**Resolution is itself represented as new provenance-bearing data.**

The node MUST NOT mutate original facts to hide the conflict.

</div>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Atomic fact field definitions</h4></div>
<div><h4>Scope authorization rules</h4></div>
<div><h4>HTTP route shape</h4><p>For conflict listing or resolution.</p></div>
<div><h4>Decay sweep algorithms</h4></div>
<div><h4>Async lint or decay jobs</h4></div>
<div><h4>Plugin-based custom resolution</h4><p>Policies.</p></div>

</div>
