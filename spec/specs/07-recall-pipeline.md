---
spec_id: Spec-07-Recall-Pipeline
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 6 and 20 recall material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
---

# Spec-07-Recall-Pipeline

`Spec-07-Recall-Pipeline` defines the supported recall path: query filtering,
scope and garden authorization, scoring inputs, result packing, and the boundary
between basic recall and deferred advanced graph/embedding features.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for the basic recall pipeline.
Advanced graph traversal, subscriptions, memory cards, and provenance walks
remain experimental or separately assigned.

## Recall Inputs

Recall begins with caller-supplied filters such as entity, relation, source,
scope, confidence threshold, and optional garden id. Implementations MUST apply
normalization and authorization before ranking or returning results.

The recall pipeline MUST NOT rank or pack facts the caller is not authorized to
read. Scope and garden ACL are filters, not score penalties.

## Authorization Order

Implementations MUST enforce:

1. Caller identity and read permission.
2. Scope visibility.
3. Garden ACL for garden-tagged facts.
4. Tombstone, quarantine, or sanitizer suppression when those components are
   active.

Only surviving facts may enter scoring.

## Scoring Inputs

Basic recall MAY combine:

- lexical match,
- semantic match when embeddings are enabled,
- graph adjacency when the graph index is enabled,
- source trust,
- confidence,
- recency or decay,
- contradiction state,
- garden tier.

The result score is local and derived. Peers MUST NOT be allowed to supply an
authoritative score in federated fact payloads.

## Low-Trust And Quarantine Interaction

Low-trust source handling belongs to federation trust and quarantine specs, but
recall must honor their outputs. Facts admitted to quarantine gardens SHOULD be
excluded or down-ranked unless the caller explicitly has quarantine visibility
and the route semantics allow inspection.

## Packing

When recall is used to feed an agent context window, implementations SHOULD pack
results to preserve diversity and avoid spending the entire budget on near
duplicates. Entity-centric recall MAY disable diversity packing and return the
top facts for that entity.

Packing MUST preserve authorization decisions. A packed summary MUST NOT reveal
the existence of unauthorized facts.

## Response Shape

Recall responses SHOULD include enough metadata for audit and debugging:

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

## Out Of Scope

This spec does not define:

- advanced recall graph semantics (`Spec-X11-Recall-Graph`),
- subscriptions (`Spec-X7-Subscriptions`),
- lazy instruction recall (`Spec-X1-Lazy-Instruction-Discovery`),
- synthesis (`Spec-X10-Synthesis`), or
- adapter-specific context injection (`Adapter ABI`, component ID TBD).
