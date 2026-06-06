---
spec_id: Spec-01-Fact-Model
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 2 fact-model material
depends_on: []
---

# Spec-01-Fact-Model

`Spec-01-Fact-Model` defines the atomic fact record, typed values, scopes,
reification pattern, Hybrid Logical Clock field, and entity URI normalization
rules used by the `v0.9.0a1` protocol line.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for the fact model component.
It intentionally does **not** include HTTP routes, schema migrations, adapter ABI,
lint semantics, or CID behavior; those belong in their own component specs.
Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Atomic Fact Shape

Every piece of knowledge in Stigmem is an atomic fact:

```text
(entity, relation, value, source, timestamp, hlc, confidence, scope)
```

| Field | Type | Description |
|---|---|---|
| `entity` | URI | What this fact is about. Formal: `stigmem://company.example/user/alice`. Informal forms such as `user:alice` are deprecated. Stored in canonical normalized form. |
| `relation` | string | Namespaced predicate. Examples: `memory:role`, `roadmap:status`, `preference:timezone`. |
| `value` | `FactValue` | The asserted typed value. |
| `source` | URI | Who asserted the fact. Examples: `stigmem://company.example/agent/assistant`, `stigmem://company.example/user/alice`. Stored in canonical normalized form. |
| `timestamp` | ISO 8601 UTC datetime | Wall-clock time when the fact was asserted. Set by the node at write time; clients may suggest. |
| `hlc` | HLC string | Hybrid Logical Clock timestamp. Causality-preserving; required for federation. |
| `valid_until` | ISO 8601 UTC datetime or null | Optional expiry. If set, the fact is expired after this time. |
| `confidence` | float in `[0.0, 1.0]` | Asserting party's confidence. `1.0` means certain, `0.5` uncertain, `0.0` retracted. |
| `scope` | `FactScope` | Visibility / federation boundary. |

A fact is immutable once written. Updates are expressed as new facts. The latest
fact for a given `(entity, relation, scope)` triple wins unless contradiction
policy applies in the fact-semantics spec.

## FactValue

`FactValue` is a discriminated union that constrains what a fact can assert. The
`type` tag forces consumers to handle each variant explicitly so queries,
indexing, and synthesis can operate on typed data without runtime introspection.

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

The `string` vs `text` distinction exists because short labels have different
indexing and display characteristics than multi-paragraph narratives. Nodes
index `string` values for exact-match queries. `text` values feed semantic
recall when an embedding pipeline is enabled. The `ref` type creates typed edges
in the knowledge graph.

Inline `text` values SHOULD be 64 KB or less. For larger payloads, assert a
`ref` fact pointing to external storage and keep the text value as a summary.
Nodes MAY reject `text` values above their configured limit and MUST return HTTP
413 if they do.

## FactScope

Scope is the visibility fence that determines which facts leave a node during
federation. It is a single string enum because the common case is simple and
more complex propagation rules build on top of this primitive.

```text
FactScope =
  | "local"
  | "team"
  | "company"
  | "public"
```

| Scope | Meaning |
|---|---|
| `local` | Visible only within this node; never federated. |
| `team` | Visible within a logical team boundary. |
| `company` | Visible within the owning company node. |
| `public` | Federatable to any peer with an active handshake. |

Nodes MUST NOT federate `local` or `team` facts without explicit operator
override. `company`-scoped facts are only federated when the active peer
declaration explicitly includes `company` in its allowed scopes.

## Reification

The fact tuple is binary: one entity, one relation, one value. N-ary
relationships are represented by minting a synthetic relationship entity and
asserting participant facts about that entity.

```text
(entity="stigmem:rel:abc123", relation="rel:subject", value={type:"ref", v:"stigmem://company.example/company/a"})
(entity="stigmem:rel:abc123", relation="rel:object",  value={type:"ref", v:"stigmem://company.example/company/b"})
(entity="stigmem:rel:abc123", relation="rel:type",    value={type:"string", v:"policy:board-approval"})
```

`rel:subject`, `rel:object`, and `rel:type` are reserved in the `rel:` namespace.
Graph traversal follows `ref` values out of reified entities the same way it
follows any other `ref`, so reified relationships participate naturally in
recall.

## Hybrid Logical Clock

Wall-clock timestamps alone cannot establish causality in a distributed system
because clocks drift. A pure logical clock preserves causality but loses
correlation with real time. Stigmem uses a Hybrid Logical Clock (HLC) that
combines both.

```text
HLC = wall_ms || counter
```

Wire format: `{wall_ms_utc}.{counter}`, for example `1746230400000.003`.

The string encoding uses a dot separator so lexicographic comparison produces
correct causal ordering without parsing. `wall_ms` is zero-padded to 13 digits;
`counter` is zero-padded to 3 digits per node.

Advance rules:

1. On local write: `hlc = max(now_ms, last_hlc_ms)` as `wall_ms`; increment
   `counter` if `wall_ms` is unchanged.
2. On receiving a federated fact: `hlc = max(now_ms, received_hlc_ms)` as
   `wall_ms`; increment `counter`.

Two facts `a` and `b` are causally ordered if `a.hlc < b.hlc`. Equal HLCs on
different nodes indicate concurrent writes; contradiction policy applies.

## Entity URI Scheme

Entity URIs use this formal shape:

```text
stigmem://{authority}/{type}/{id}
```

| Component | Description | Examples |
|---|---|---|
| `authority` | Hostname of the Stigmem node that owns this entity namespace. | `company.example`, `node.example.com` |
| `type` | Entity type slug, lowercase with no spaces. | `user`, `agent`, `project`, `issue`, `decision`, `team` |
| `id` | Opaque stable identifier for the entity. | `alice`, `cto`, `acme-roadmap`, `eg-42` |

Examples:

- `stigmem://company.example/user/alice`
- `stigmem://company.example/agent/cto`
- `stigmem://company.example/issue/eg-42`
- `stigmem://node.acme/decision/use-sqlite`

Informal URIs such as `user:alice`, `agent:cto`, and `project:acme-roadmap` are
deprecated in the `v0.9.0a1` protocol line. Nodes MAY accept informal URIs for
backward compatibility and SHOULD emit deprecation warnings when they do.
Adapters targeting `v0.9.0a1` or later SHOULD use formal URIs for all new fact
assertions and MUST NOT emit informal URIs in new code.

## Entity Naming Rules

The node applies a strict normalizer at ingest to prevent case-based and
whitespace-based fragmentation. Full alias resolution, such as treating
`user:alice` and `user:a.smith` as equivalent, is a deferred resolver concern and
is not part of this fact model.

Canonical form:

1. Trim leading/trailing whitespace from `entity` and `source`.
2. Collapse internal ASCII whitespace runs to a single hyphen in path segments.
3. Lowercase the URI scheme, authority, type, and id components.
4. Percent-decode unreserved URI characters, then re-encode path segments using
   RFC 3986 unreserved set only.
5. Reject empty type or id segments.

Examples:

| Input | Canonical |
|---|---|
| ` stigmem://Company.Example/User/Alice ` | `stigmem://company.example/user/alice` |
| `stigmem://company.example/Issue/EG-42` | `stigmem://company.example/issue/eg-42` |
| `user:Alice Smith` | `user:alice-smith` |

Node behavior:

- Ingest MUST normalize `entity` and `source` before persistence.
- Ingest MUST reject formal URIs with empty authority, type, or id.
- Query parameters for `entity` and `source` MUST be normalized before matching.
- Nodes SHOULD provide migration tooling for legacy non-canonical entities, but
  MUST NOT rewrite immutable historical facts in place.
