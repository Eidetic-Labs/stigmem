---
spec_id: Spec-17-Schema-and-Migration
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 10 schema-and-migration material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-08-Quarantine-Garden >= 0.1.0-alpha.0
  - Spec-09-Audit-Log >= 0.1.0-alpha.0
  - Spec-15-Fact-Semantics >= 0.1.0-alpha.0
---

# Spec-17-Schema-and-Migration

<p className="stigmem-meta"><span>4 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The stable storage and migration contract for Stigmem nodes: what
the schema must preserve, how migrations are ordered and tracked,
and what storage backends must guarantee.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for schema and
migration semantics. It intentionally describes schema contracts and
migration behavior, not an exhaustive dump of every reference-node
SQL migration.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Migration-versioned schema

Production nodes SHOULD use a migration-versioned schema. The
reference node uses numbered SQL migration files applied at startup
and records each applied migration in `schema_migrations`.

<div className="stigmem-keypoint">

**Migrations MUST be idempotent and apply in deterministic order.**

A migration whose version is already present in `schema_migrations`
MUST be skipped without re-running its DDL or DML. For file-backed
reference implementations, sorting migration filenames by stem is
sufficient.

</div>

## Schema migration cursor

Nodes MUST persist a migration cursor equivalent to:

```text
schema_migrations {
  version:    string
  applied_at: ISO 8601 UTC timestamp
}
```

The cursor is part of the node's operational state. Snapshots and
backups SHOULD include it so restores can prove which migrations
have already been applied.

## Additive evolution

Stable migrations SHOULD be additive:

<div className="stigmem-grid">

<div><h4>Add columns</h4><p>Instead of removing or renaming existing columns.</p></div>
<div><h4>Add tables</h4><p>Instead of changing existing table semantics in place.</p></div>
<div><h4>Add indexes</h4><p>Without changing query-visible behavior.</p></div>
<div><h4>Preserve rows</h4><p>During upgrade.</p></div>

</div>

<div className="stigmem-keypoint">

**Breaking storage rewrites require an explicit migration plan, rollback guidance, and conformance coverage.**

They MUST NOT be hidden inside ordinary additive migrations.

</div>

## Fact storage requirements

The facts table is the single source of truth for assertions. Each
row maps to the atomic fact shape defined by `Spec-01-Fact-Model`.

At minimum, storage MUST preserve:

<div className="stigmem-grid">

<div><h4>fact id</h4></div>
<div><h4>entity</h4></div>
<div><h4>relation</h4></div>
<div><h4>typed value</h4></div>
<div><h4>source</h4></div>
<div><h4>timestamp</h4></div>
<div><h4>optional <code>valid_until</code></h4></div>
<div><h4>confidence</h4></div>
<div><h4>scope</h4></div>
<div><h4>HLC</h4><p>When enabled.</p></div>
<div><h4>Federation provenance</h4><p>Fields needed by <code>Spec-05-Federation-Trust</code>.</p></div>
<div><h4>Core integrity fields</h4><p>Assigned by later core specs.</p></div>

</div>

<div className="stigmem-keypoint">

**Facts are append-oriented.**

Retractions, confidence changes, and conflict resolutions are
represented as new records or associated protocol records, not
silent mutation of the original assertion.

</div>

## Required index families

Implementations SHOULD provide indexes or equivalent backend-native
access paths for:

<div className="stigmem-grid">

<div><h4><code>(entity, relation)</code></h4></div>
<div><h4><code>(entity, relation, scope)</code></h4></div>
<div><h4><code>scope</code></h4></div>
<div><h4><code>timestamp</code></h4></div>
<div><h4>HLC / cursor fields</h4><p>Used by replication.</p></div>
<div><h4>conflict status</h4></div>
<div><h4>audit events</h4><p>By peer/principal and timestamp.</p></div>
<div><h4>expiry pruning</h4><p>For nonce or replay caches.</p></div>

</div>

The exact index names are implementation details.

## Federation and audit storage

Nodes that support federation MUST persist peer state, replication
cursors, replay/nonce state, and federation audit events. These
records support `Spec-05-Federation-Trust`, `Spec-09-Audit-Log`, and
`Spec-11-Replay-Protection`.

<div className="stigmem-keypoint">

**Federation metadata MUST be sufficient to resume replication after process restart.**

Without duplicating accepted facts or skipping eligible facts.

</div>

## Alias and compatibility storage

Nodes that accept legacy non-canonical entity URIs SHOULD provide
alias storage or migration tooling that maps raw entity/source
values to canonical forms.

Alias storage MUST NOT silently rewrite historical fact provenance.
It is a compatibility aid for query and migration workflows.

## Storage backend contract

A storage backend MUST provide:

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Requirement</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Connection lifecycle</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Manage open and close.</dd>
</div>

<div>
<dt>Transactions</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Commit on success, roll back on exception.</dd>
</div>

<div>
<dt>Row access</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>By column name.</dd>
</div>

<div>
<dt>Migration runner</dt>
<dt><span className="stigmem-fields__type">MUST</span></dt>
<dd>Idempotent.</dd>
</div>

<div>
<dt>Snapshot export/import</dt>
<dt><span className="stigmem-fields__type">SHOULD</span></dt>
<dd>When supported by the backend.</dd>
</div>

</div>

Backends MUST preserve the same logical schema contract even when
SQL dialects or execution mechanics differ.

## Plugin migration boundary

Core migrations are applied by the node. Plugin-declared migrations,
when enabled by the plugin infrastructure, MUST register through the
migration hook surface and MUST remain namespaced to the declaring
plugin.

Plugin migration graph resolution, downgrade handling, and package
discovery are outside the `v0.9.0a1` stable schema contract.

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Every reference-node migration</h4></div>
<div><h4>Backend-specific DDL syntax</h4></div>
<div><h4>Operator backup procedures</h4></div>
<div><h4>Plugin package discovery</h4></div>
<div><h4>Downgrade semantics</h4></div>
<div><h4>Future CID/tombstone migrations</h4><p>Beyond their stable component specs.</p></div>

</div>
