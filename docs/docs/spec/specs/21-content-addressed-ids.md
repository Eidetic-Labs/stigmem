---
spec_id: Spec-21-Content-Addressed-IDs
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 25 content-addressed fact ID material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-09-Audit-Log >= 0.1.0-alpha.0
  - Spec-17-Schema-and-Migration >= 0.1.0-alpha.0
---

# Spec-21-Content-Addressed-IDs

<p className="stigmem-meta"><span>5 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The content-addressed fact identifier (CID): deterministic,
tamper-evident identifiers for the canonical body of a fact.

</div>

## Extraction status

This component spec extracts the content-addressed fact ID material
that previously lived in the monolithic `stigmem-spec-v0.9.0a1.md`
lineage.

<div className="stigmem-keypoint">

**CIDs are core Stigmem behavior per ADR-011.**

They are not an experimental plugin feature, and a conforming
default node MUST compute CIDs for new facts.

</div>

## Purpose

A CID is a deterministic, tamper-evident identifier for the
canonical body of a fact. Unlike a UUID-style fact id, a CID can be
recomputed independently from the fact payload.

CIDs provide:

<div className="stigmem-grid">

<div><h4>Content integrity</h4><p>Checks for stored facts.</p></div>
<div><h4>Deduplication</h4><p>For identical assertions.</p></div>
<div><h4>Stable provenance</h4><p>References across nodes and transports.</p></div>
<div><h4>Defense-in-depth</h4><p>A core layer for storage immutability.</p></div>

</div>

## CID format

A CID MUST use the `sha256:` prefix followed by 64 lowercase
hexadecimal characters:

```text
sha256:<64 lowercase hex chars>
```

The CID MUST be computed as:

```text
CID = "sha256:" + hex_lowercase(SHA-256(canonical_fact_body_bytes))
```

<div className="stigmem-keypoint">

**Only lowercase hexadecimal output is valid for `sha256:` CIDs.**

Strings beginning with `sha256:` that do not match this format MUST
be treated as malformed CIDs.

</div>

## Canonical fact body

The canonical fact body for v0.9.0aN CID computation contains
exactly these fields:

```json
{
  "confidence": 1.0,
  "entity": "stigmem://example/entity",
  "relation": "memory:prefers",
  "scope": "local",
  "source": "agent:example",
  "value_type": "string",
  "value_v": "dark mode"
}
```

The canonical body MUST be serialized as compact UTF-8 JSON with
deterministic lexicographic key ordering and no insignificant
whitespace. The reference node uses JSON sorted keys with compact
separators and `ensure_ascii=false`.

<div className="stigmem-keypoint">

**All seven canonical fields are CID-sensitive. Changing any of them MUST produce a different CID.**

</div>

## Excluded fields

The following fields MUST NOT participate in CID computation:

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Reason</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>id</code> / <code>fact_id</code></dt>
<dt><span className="stigmem-fields__type">self-reference</span></dt>
<dd>Cannot be part of its own CID.</dd>
</div>

<div>
<dt><code>cid</code></dt>
<dt><span className="stigmem-fields__type">self-reference</span></dt>
<dd>Cannot be self-referential.</dd>
</div>

<div>
<dt><code>timestamp</code> / <code>created_at</code></dt>
<dt><span className="stigmem-fields__type">write-time metadata</span></dt>
<dd>Write time is not part of the assertion.</dd>
</div>

<div>
<dt><code>hlc</code></dt>
<dt><span className="stigmem-fields__type">node-local</span></dt>
<dd>Logical clock metadata.</dd>
</div>

<div>
<dt><code>valid_until</code></dt>
<dt><span className="stigmem-fields__type">policy</span></dt>
<dd>Expiry policy, not the assertion body.</dd>
</div>

<div>
<dt><code>derived_from</code></dt>
<dt><span className="stigmem-fields__type">provenance</span></dt>
<dd>References can create circularity.</dd>
</div>

<div>
<dt><code>attestation_chain</code> / <code>signature</code></dt>
<dt><span className="stigmem-fields__type">transport</span></dt>
<dd>Transport or attestation metadata.</dd>
</div>

<div>
<dt><code>source_trust</code></dt>
<dt><span className="stigmem-fields__type">local</span></dt>
<dd>Locally derived trust score.</dd>
</div>

<div>
<dt><code>reason</code></dt>
<dt><span className="stigmem-fields__type">audit context</span></dt>
<dd>Operator or audit context, not the assertion body.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**A matching CID is not proof that excluded metadata is trustworthy.**

Excluded fields may still be security-relevant. Implementations MUST
validate those fields through their owning specs.

</div>

## Storage contract

The fact storage model MUST support:

<div className="stigmem-grid">

<div><h4>Nullable <code>cid</code> column</h4><p>Nullable only for legacy rows pending backfill.</p></div>
<div><h4><code>fact_cid_aliases</code> table</h4><p>Mapping stored fact ids to CIDs.</p></div>
<div><h4>Unique CID index</h4><p>For efficient CID lookup.</p></div>
<div><h4>Fact id index</h4><p>For alias maintenance.</p></div>

</div>

Every new fact write MUST persist the computed CID on the fact row
and insert the corresponding alias row in the same transaction.

## Write path and deduplication

On local assertion, a node MUST:

<ol className="stigmem-steps">
<li>Normalize the assertion fields according to their owning specs.</li>
<li>Compute the CID before writing the fact row.</li>
<li>Persist the CID with all other fact fields.</li>
<li>Insert the CID alias row in the same transaction.</li>
</ol>

<div className="stigmem-keypoint">

**A CID collision MUST NOT overwrite the existing record.**

If the computed CID already exists for the same tenant, the node
SHOULD return the existing record instead of creating a duplicate
fact. If an implementation detects the same CID for a different
canonical body, it MUST treat that as a CID collision.

</div>

## Dual addressing

The single-fact read route MUST accept either a UUID-style fact id
or a CID:

```http
GET /v1/facts/{cid_or_fact_id}
```

When the path value starts with `sha256:`, the node MUST validate
CID syntax and resolve the fact through the CID alias index.
Malformed CIDs MUST return a validation error. Well-formed but
unknown CIDs MUST return not found.

Fact responses SHOULD include the stored `cid` field. Legacy facts
that have not yet been backfilled MAY return `cid: null`.

## CID verification

Nodes MUST expose an integrity check that recomputes the CID from
the stored fact body and compares it with the stored CID:

```http
POST /v1/facts/{fact_id}/verify-cid
```

The response MUST include:

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Required</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>cid_valid</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>Whether the stored CID matches the recomputed CID.</dd>
</div>

<div>
<dt><code>computed_cid</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>CID computed from the stored canonical body.</dd>
</div>

<div>
<dt><code>stored_cid</code></dt>
<dt><span className="stigmem-fields__type">nullable</span></dt>
<dd>Stored CID, or null for legacy rows pending backfill.</dd>
</div>

<div>
<dt><code>mismatch_reason</code></dt>
<dt><span className="stigmem-fields__type">conditional</span></dt>
<dd>Human-readable reason when <code>cid_valid</code> is false.</dd>
</div>

</div>

A false result SHOULD trigger operator investigation. It may
indicate data corruption, storage tampering, a legacy row pending
backfill, or a canonicalization bug.

## Backfill

Nodes MUST provide a backfill path for legacy rows whose `cid` is
null. The backfill process MUST:

<ol className="stigmem-steps">
<li>Iterate over facts with <code>cid IS NULL</code>.</li>
<li>Recompute each CID from the canonical fact body.</li>
<li>Update the fact row and insert the alias row.</li>
<li>Be idempotent.</li>
</ol>

The reference node exposes a `backfill-cids` CLI command and this
status route:

```http
GET /v1/admin/cid-backfill/status
```

The status response MUST include:

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Type</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>total_facts</code></dt>
<dt><span className="stigmem-fields__type">integer</span></dt>
<dd>Total facts visible to the status query.</dd>
</div>

<div>
<dt><code>backfilled_facts</code></dt>
<dt><span className="stigmem-fields__type">integer</span></dt>
<dd>Facts with non-null <code>cid</code>.</dd>
</div>

<div>
<dt><code>pending_facts</code></dt>
<dt><span className="stigmem-fields__type">integer</span></dt>
<dd>Facts still missing <code>cid</code>.</dd>
</div>

<div>
<dt><code>backfill_complete</code></dt>
<dt><span className="stigmem-fields__type">boolean</span></dt>
<dd>Whether <code>pending_facts</code> is zero.</dd>
</div>

</div>

## Federation use

<div className="stigmem-keypoint">

**Receiving nodes SHOULD recompute the CID from the inbound canonical body and reject payloads whose declared CID does not match.**

Federation payloads SHOULD carry CIDs when fact records cross node
boundaries. Legacy CID-null rows may exist during migration and
backfill windows. Federation policy for accepting or rejecting
CID-null inbound facts is owned by `Spec-05-Federation-Trust`; this
spec defines the CID format and computation needed to perform that
validation.

</div>

## Error conditions

Nodes SHOULD use these stable error meanings:

<div className="stigmem-fields">

<div>
<dt>Error</dt>
<dt><span className="stigmem-fields__type">Condition</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>cid_malformed</code></dt>
<dt><span className="stigmem-fields__type">syntax</span></dt>
<dd>A <code>sha256:</code> path value is not followed by 64 lowercase hex characters.</dd>
</div>

<div>
<dt><code>fact_not_found</code></dt>
<dt><span className="stigmem-fields__type">lookup</span></dt>
<dd>Fact id or CID does not resolve to a readable fact.</dd>
</div>

<div>
<dt><code>cid_mismatch</code></dt>
<dt><span className="stigmem-fields__type">integrity</span></dt>
<dd>A recomputed or inbound CID does not match the declared/stored CID.</dd>
</div>

<div>
<dt><code>cid_collision_detected</code></dt>
<dt><span className="stigmem-fields__type">integrity</span></dt>
<dd>Two different canonical fact bodies produce the same CID.</dd>
</div>

</div>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Federation CID-null policy</h4><p>Full trust policy for legacy facts.</p></div>
<div><h4>Hash algorithm rotation</h4><p>Beyond the <code>sha256:</code> prefix shape.</p></div>
<div><h4>Provenance graph</h4><p>Semantics for <code>derived_from</code>.</p></div>
<div><h4>Tombstone / time-travel</h4><p>Or source-attestation behavior.</p></div>
<div><h4>Storage-engine DDL syntax</h4></div>

</div>
