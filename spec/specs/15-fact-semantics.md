---
spec_id: Spec-15-Fact-Semantics
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 3 fact-semantics material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
---

# Spec-15-Fact-Semantics

`Spec-15-Fact-Semantics` defines the supported behavior of facts after they are
written: provenance, expiry, contradiction detection, query-time winner
selection, and conflict entities.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for fact semantics. Atomic fact
shape is owned by `Spec-01-Fact-Model`; scope enforcement is owned by
`Spec-02-Scopes-and-ACL`; HTTP route shape is owned by `Spec-03-HTTP-API`.

Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Provenance

Every fact carries `source` and `timestamp`. A node MUST store both without
modification. Query responses MUST return the original `source`; relay metadata
MUST NOT replace the original source.

Inbound federated facts SHOULD record receiving-node provenance separately from
the original source. The receiving node MAY assert a local meta-fact:

```text
entity=<fact-id>
relation="stigmem:received_from"
value={type:"ref", v:"<originating-node-id>"}
source="system:stigmem"
```

The receiving-node provenance fact is local accounting and MUST NOT be
re-replicated as if it were part of the origin peer's assertion set.

## Expiry

Facts whose `valid_until` timestamp has passed MUST NOT be returned by ordinary
fact queries. A caller MAY request expired facts with an explicit
`include_expired=true` option on routes that support it.

Expired facts remain in the store. Expiry is a read-filtering and operational
health concern, not a destructive deletion rule.

## TTL Meta-Facts

Operators or agents that need to schedule future expiry for a fact that was
originally asserted without `valid_until` MAY attach a TTL meta-fact. The
meta-fact's entity is the target fact id, the relation is `stigmem:ttl`, and
the value is the intended expiry datetime:

```text
entity=<fact-id>
relation="stigmem:ttl"
value={type:"datetime", v:<expiry>}
```

`valid_until` and `confidence` are orthogonal. A historical certain fact may
have `confidence=1.0` and a `valid_until` timestamp that marks when it stopped
being current.

## Contradiction Detection

A contradiction exists when two facts `a` and `b` satisfy all of:

- `a.entity == b.entity`
- `a.relation == b.relation`
- `a.scope == b.scope`
- `a.value != b.value`
- `a.confidence > 0.0`
- `b.confidence > 0.0`

Both facts MUST be retained. Nodes MUST NOT silently overwrite one fact with
the other.

Entity normalization from `Spec-01-Fact-Model` applies before contradiction
detection. Facts written with different raw entity strings that normalize to
the same canonical entity participate in the same contradiction set.

## Query-Time Resolution

When a query needs a single preferred fact for a contradicted
`(entity, relation, scope)` tuple, nodes SHOULD apply this ordering:

1. Higher `confidence` wins.
2. Equal confidence: higher HLC wins.
3. Equal confidence and HLC: return both with `contradicted: true` and let the
   caller decide.

This ordering does not delete or mutate losing facts. It only controls
presentation and default winner selection.

## Conflict Entities

When a contradiction is detected on write, a node SHOULD create a first-class
conflict entity in the `stigmem:conflict:` namespace. The conflict entity
reifies disagreement as queryable data.

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

Resolution is itself represented as new provenance-bearing data. The node MUST
NOT mutate original facts to hide the conflict.

## Out Of Scope

This spec does not define:

- atomic fact field definitions,
- scope authorization rules,
- HTTP route shape for conflict listing or resolution,
- decay sweep algorithms,
- async lint or decay jobs, or
- plugin-based custom conflict resolution policies.
