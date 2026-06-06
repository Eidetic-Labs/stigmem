---
spec_id: Spec-16-Namespace-Registry
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 9 namespace-registry material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-15-Fact-Semantics >= 0.1.0-alpha.0
---

# Spec-16-Namespace-Registry

<p className="stigmem-meta"><span>2 min read</span><span>Spec contributor · Adapter author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The relation-prefix registry used by facts, meta-facts, and
protocol-owned relations.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for the namespace
registry. Atomic fact shape and relation field rules are owned by
`Spec-01-Fact-Model`; conflict and TTL semantics are owned by
`Spec-15-Fact-Semantics`.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Reserved prefixes

Reserved prefixes are maintained by the spec. Implementations and
adapters MUST NOT define incompatible meanings for these prefixes.

<div className="stigmem-fields">

<div>
<dt>Prefix</dt>
<dt><span className="stigmem-fields__type">Governed by</span></dt>
<dd>Purpose</dd>
</div>

<div>
<dt><code>stigmem:</code></dt>
<dt><span className="stigmem-fields__type">Spec maintainers</span></dt>
<dd>Core protocol relations, including <code>stigmem:ttl</code>, <code>stigmem:received_from</code>, <code>stigmem:member</code>, <code>stigmem:conflict:between</code>, <code>stigmem:conflict:status</code>, and <code>stigmem:resolves</code>.</dd>
</div>

<div>
<dt><code>rel:</code></dt>
<dt><span className="stigmem-fields__type">Spec maintainers</span></dt>
<dd>Reification primitives: <code>rel:subject</code>, <code>rel:object</code>, and <code>rel:type</code>.</dd>
</div>

<div>
<dt><code>stigmem:lint:</code></dt>
<dt><span className="stigmem-fields__type">Spec maintainers</span></dt>
<dd>Reserved for future lint-related protocol relations. Current lint behavior is an API operation and does not require fact assertions.</dd>
</div>

<div>
<dt><code>stigmem:decay:</code></dt>
<dt><span className="stigmem-fields__type">Spec maintainers</span></dt>
<dd>Reserved for future decay-related protocol relations. Current decay behavior is deferred and remains outside the stable component set.</dd>
</div>

</div>

## Registered community prefixes

Registered community prefixes are stable enough for interoperability
but are not owned by a single protocol mechanism.

<div className="stigmem-fields">

<div>
<dt>Prefix</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>memory:</code></dt>
<dt><span className="stigmem-fields__type">Registered</span></dt>
<dd>Agent memory: role, preference, context.</dd>
</div>

<div>
<dt><code>intent:</code></dt>
<dt><span className="stigmem-fields__type">Registered</span></dt>
<dd>Intent and delegation facts, including <code>intent:handoff_to</code>, <code>intent:handoff_summary</code>, <code>intent:context_ref</code>, <code>intent:continuation</code>, <code>intent:escalation</code>, <code>intent:escalate_to</code>, and <code>intent:goal</code>.</dd>
</div>

<div>
<dt><code>roadmap:</code></dt>
<dt><span className="stigmem-fields__type">Registered</span></dt>
<dd>Project and product state facts, including <code>roadmap:decision</code>, <code>roadmap:constraint</code>, <code>roadmap:status</code>, and <code>roadmap:summary</code>.</dd>
</div>

<div>
<dt><code>preference:</code></dt>
<dt><span className="stigmem-fields__type">Registered</span></dt>
<dd>User and agent preferences.</dd>
</div>

<div>
<dt><code>paperclip:</code></dt>
<dt><span className="stigmem-fields__type">Registered</span></dt>
<dd>Paperclip adapter lifecycle facts: <code>paperclip:checkout</code>, <code>paperclip:issue_status</code>, <code>paperclip:last_active</code>, and <code>paperclip:blocked_by</code>.</dd>
</div>

</div>

## Experimental prefix

The `x-` prefix is reserved for informal or experimental use. No
registration is required for `x-` relations.

<div className="stigmem-keypoint">

**Experimental prefixes MUST NOT be treated as stable protocol commitments.**

A relation that graduates from experimental use SHOULD move to a
registered or reserved prefix as part of its stabilization work.

</div>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Relation-specific semantics</h4></div>
<div><h4>Adapter-specific relation inventories</h4></div>
<div><h4>Namespace ownership outside Stigmem facts</h4></div>
<div><h4>A public registration workflow</h4></div>

</div>
