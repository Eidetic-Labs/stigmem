---
spec_id: Spec-07-Recall-Pipeline
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 6 and 20 recall material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
---

# Spec-07-Recall-Pipeline

<p className="stigmem-meta"><span>3 min read</span><span>Spec contributor · SDK author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The supported recall path: query filtering, scope and garden
authorization, scoring inputs, result packing, and the boundary
between basic recall and deferred advanced graph/embedding features.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for the basic
recall pipeline. Advanced graph traversal, subscriptions, memory
cards, and provenance walks remain experimental or separately
assigned.

## Recall inputs

Recall begins with caller-supplied filters such as entity, relation,
source, scope, confidence threshold, and optional garden id.
Implementations MUST apply normalization and authorization before
ranking or returning results.

<div className="stigmem-keypoint">

**The recall pipeline MUST NOT rank or pack facts the caller is not authorized to read.**

Scope and garden ACL are filters, not score penalties.

</div>

## Authorization order

Implementations MUST enforce:

<ol className="stigmem-steps">
<li>Caller identity and read permission.</li>
<li>Scope visibility.</li>
<li>Garden ACL for garden-tagged facts.</li>
<li>Tombstone, quarantine, or sanitizer suppression when those components are active.</li>
</ol>

Only surviving facts may enter scoring.

## Scoring inputs

Basic recall MAY combine:

<div className="stigmem-grid">

<div><h4>Lexical match</h4></div>
<div><h4>Semantic match</h4><p>When embeddings are enabled.</p></div>
<div><h4>Graph adjacency</h4><p>When the graph index is enabled.</p></div>
<div><h4>Source trust</h4></div>
<div><h4>Confidence</h4></div>
<div><h4>Recency or decay</h4></div>
<div><h4>Contradiction state</h4></div>
<div><h4>Garden tier</h4></div>

</div>

<div className="stigmem-keypoint">

**The result score is local and derived.**

Peers MUST NOT be allowed to supply an authoritative score in
federated fact payloads.

</div>

## Low-trust and quarantine interaction

Low-trust source handling belongs to federation trust and
quarantine specs, but recall must honor their outputs. Facts
admitted to quarantine gardens SHOULD be excluded or down-ranked
unless the caller explicitly has quarantine visibility and the
route semantics allow inspection.

## Packing

When recall is used to feed an agent context window, implementations
SHOULD pack results to preserve diversity and avoid spending the
entire budget on near duplicates. Entity-centric recall MAY disable
diversity packing and return the top facts for that entity.

<div className="stigmem-keypoint">

**Packing MUST preserve authorization decisions.**

A packed summary MUST NOT reveal the existence of unauthorized
facts.

</div>

## Response shape

```text
RecallResponse {
  results:      RecallResult[]
  generated_at: ISO 8601 UTC
  query:        object
}

RecallResult {
  fact:  FactRecord
  score: number
  why:   string[]?
}
```

Exact route shape is owned by `Spec-03-HTTP-API`.

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Advanced recall graph</h4><p><code>Spec-X11-Recall-Graph</code>.</p></div>
<div><h4>Subscriptions</h4><p><code>Spec-X7-Subscriptions</code>.</p></div>
<div><h4>Lazy instruction recall</h4><p><code>Spec-X1-Lazy-Instruction-Discovery</code>.</p></div>
<div><h4>Synthesis</h4><p><code>Spec-X10-Synthesis</code>.</p></div>
<div><h4>Adapter context injection</h4><p>Adapter ABI, component ID TBD.</p></div>

</div>
