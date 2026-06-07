---
spec_id: Spec-21-Content-Addressed-IDs
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-21
supersedes: spec/stigmem-spec-v0.9.0a1.md section 25 content-addressed fact ID material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-09-Audit-Log >= 0.1.0-alpha.0
  - Spec-17-Schema-and-Migration >= 0.1.0-alpha.0
---

# Spec-21-Content-Addressed-IDs

## Extraction Status

This feature spec owns the content-addressed fact ID material that previously
lived in the monolithic `stigmem-spec-v0.9.0a1.md` lineage and the
compatibility projection at `spec/specs/21-content-addressed-ids.md`.

Content-addressed IDs are core Stigmem behavior per ADR-011. A conforming
default node MUST compute CIDs for new facts.

## Purpose

A CID is a deterministic, tamper-evident identifier for the canonical body of a
fact. Unlike a UUID-style fact id, a CID can be recomputed independently from
the fact payload.

CIDs provide:

- content integrity checks for stored facts;
- deduplication for identical assertions;
- stable provenance references across nodes and transports;
- a core defense-in-depth layer for storage immutability.

## CID Format

A CID MUST use the `sha256:` prefix followed by 64 lowercase hexadecimal
characters:

```text
sha256:<64 lowercase hex chars>
```

The CID MUST be computed as:

```text
CID = "sha256:" + hex_lowercase(SHA-256(canonical_fact_body_bytes))
```

Only lowercase hexadecimal output is valid for `sha256:` CIDs. Strings
beginning with `sha256:` that do not match this format MUST be treated as
malformed CIDs.

## Canonical Fact Body

The canonical fact body for CID v2 computation contains exactly these fields:

```json
{
  "confidence": 1.0,
  "entity": "stigmem://example/entity",
  "interpret_as": "content",
  "relation": "memory:prefers",
  "scope": "local",
  "source": "agent:example",
  "value_type": "string",
  "value_v": "dark mode"
}
```

`interpret_as` is CID-sensitive (CID v2): flipping a fact's interpretation
between `content` and `instruction` MUST produce a different CID, so the flip is
detected on read. CID v1 (which omitted `interpret_as`) is no longer accepted —
this is a breaking, version-gated change; pre-v2 facts are upgraded by the CID
backfill.

The canonical body MUST be serialized as compact UTF-8 JSON with deterministic
lexicographic key ordering and no insignificant whitespace. The reference node
uses JSON sorted keys with compact separators and `ensure_ascii=false`.

All eight canonical fields are CID-sensitive. Changing any of them MUST produce
a different CID.

## Excluded Fields

The following fields MUST NOT participate in CID computation:

| Field | Reason |
| --- | --- |
| `id` / `fact_id` | Cannot be part of its own CID. |
| `cid` | Cannot be self-referential. |
| `timestamp` / `created_at` | Write time is not part of the assertion. |
| `hlc` | Node-local logical clock metadata. |
| `valid_until` | Expiry policy, not the assertion body. |
| `derived_from` | Provenance references can create circularity. |
| `attestation_chain` / `signature` | Transport or attestation metadata. |
| `source_trust` | Locally derived trust score. |
| `reason` | Operator or audit context, not the assertion body. |

Excluded fields may still be security-relevant. Implementations MUST validate
those fields through their owning specs and MUST NOT treat a matching CID as
proof that excluded metadata is trustworthy.

## Storage Contract

The fact storage model MUST support:

- a nullable `cid` column on stored facts, nullable only for legacy rows pending
  backfill;
- a `fact_cid_aliases` table mapping stored fact ids to CIDs;
- a unique index on CID for efficient CID lookup;
- an index on fact id for alias maintenance.

Every new fact write MUST persist the computed CID on the fact row and insert
the corresponding alias row in the same transaction.

## Write Path And Deduplication

On local assertion, a node MUST:

1. normalize the assertion fields according to their owning specs;
2. compute the CID before writing the fact row;
3. persist the CID with all other fact fields;
4. insert the CID alias row in the same transaction.

If the computed CID already exists for the same tenant, the node SHOULD return
the existing record instead of creating a duplicate fact. If an implementation
detects the same CID for a different canonical body, it MUST treat that as a
CID collision and MUST NOT overwrite the existing record.

## Dual Addressing

The single-fact read route MUST accept either a UUID-style fact id or a CID:

```http
GET /v1/facts/{cid_or_fact_id}
```

When the path value starts with `sha256:`, the node MUST validate CID syntax
and resolve the fact through the CID alias index. Malformed CIDs MUST return a
validation error. Well-formed but unknown CIDs MUST return not found.

Fact responses SHOULD include the stored `cid` field. Legacy facts that have
not yet been backfilled MAY return `cid: null`.

## CID Verification

Nodes MUST expose an integrity check that recomputes the CID from the stored
fact body and compares it with the stored CID:

```http
POST /v1/facts/{fact_id}/verify-cid
```

The response MUST include:

| Field | Meaning |
| --- | --- |
| `cid_valid` | Whether the stored CID matches the recomputed CID. |
| `computed_cid` | CID computed from the stored canonical body. |
| `stored_cid` | Stored CID, or null for legacy rows pending backfill. |
| `mismatch_reason` | Human-readable reason when `cid_valid` is false. |

A false result SHOULD trigger operator investigation. A false result may
indicate data corruption, storage tampering, a legacy row pending backfill, or a
canonicalization bug.

## Backfill

Nodes MUST provide a backfill path for legacy rows whose `cid` is null. The
backfill process MUST:

1. iterate over facts with `cid IS NULL`;
2. recompute each CID from the canonical fact body;
3. update the fact row and insert the alias row;
4. be idempotent.

The reference node exposes a `backfill-cids` CLI command and this status route:

```http
GET /v1/admin/cid-backfill/status
```

The status response MUST include:

| Field | Meaning |
| --- | --- |
| `total_facts` | Total facts visible to the status query. |
| `backfilled_facts` | Facts with non-null `cid`. |
| `pending_facts` | Facts still missing `cid`. |
| `backfill_complete` | Whether `pending_facts` is zero. |

## Federation Use

Federation payloads SHOULD carry CIDs when fact records cross node boundaries.
Receiving nodes that receive a CID-bearing fact SHOULD recompute the CID from
the inbound canonical body and reject payloads whose declared CID does not
match the computed CID.

Legacy CID-null rows may exist during migration and backfill windows.
Federation policy for accepting or rejecting CID-null inbound facts is owned by
`Spec-05-Federation-Trust`; this spec defines the CID format and computation
needed to perform that validation.

## Error Conditions

Nodes SHOULD use these stable error meanings:

| Error | Condition |
| --- | --- |
| `cid_malformed` | A `sha256:` path value is not followed by 64 lowercase hex characters. |
| `fact_not_found` | Fact id or CID does not resolve to a readable fact. |
| `cid_mismatch` | A recomputed or inbound CID does not match the declared/stored CID. |
| `cid_collision_detected` | Two different canonical fact bodies produce the same CID. |

## Out Of Scope

This spec does not define:

- the full federation trust policy for CID-null legacy facts;
- hash algorithm rotation procedure beyond the `sha256:` prefix shape;
- provenance graph semantics for `derived_from`;
- tombstone, time-travel, or source-attestation behavior;
- storage-engine-specific DDL syntax.
