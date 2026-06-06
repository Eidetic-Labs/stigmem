---
spec_id: Spec-17-Schema-and-Migration
version: 0.1.0-alpha.0
status: Draft
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

`Spec-17-Schema-and-Migration` defines the stable storage and migration
contract for Stigmem nodes. It describes what the schema must preserve, how
migrations are ordered and tracked, and what storage backends must guarantee.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for schema and migration
semantics. It intentionally describes schema contracts and migration behavior,
not an exhaustive dump of every reference-node SQL migration.

Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Migration-Versioned Schema

Production nodes SHOULD use a migration-versioned schema. The reference node
uses numbered SQL migration files applied at startup and records each applied
migration in `schema_migrations`.

Migrations MUST be idempotent. A migration whose version is already present in
`schema_migrations` MUST be skipped without re-running its DDL or DML.

Migration versions MUST be applied in deterministic order. For file-backed
reference implementations, sorting migration filenames by stem is sufficient.

## Schema Migration Cursor

Nodes MUST persist a migration cursor equivalent to:

```text
schema_migrations {
  version:    string
  applied_at: ISO 8601 UTC timestamp
}
```

The cursor is part of the node's operational state. Snapshots and backups SHOULD
include it so restores can prove which migrations have already been applied.

## Additive Evolution

Stable migrations SHOULD be additive:

- add columns instead of removing or renaming existing columns,
- add tables instead of changing existing table semantics in place,
- add indexes without changing query-visible behavior, and
- preserve existing rows during upgrade.

Breaking storage rewrites require an explicit migration plan, rollback guidance,
and conformance coverage. They MUST NOT be hidden inside ordinary additive
migrations.

## Fact Storage Requirements

The facts table is the single source of truth for assertions. Each row maps to
the atomic fact shape defined by `Spec-01-Fact-Model`.

At minimum, storage MUST preserve:

- fact id,
- entity,
- relation,
- typed value,
- source,
- timestamp,
- optional `valid_until`,
- confidence,
- scope,
- HLC when enabled,
- federation provenance fields needed by `Spec-05-Federation-Trust`, and
- any core integrity fields assigned by later core specs.

Facts are append-oriented. Retractions, confidence changes, and conflict
resolutions are represented as new records or associated protocol records, not
silent mutation of the original assertion.

## Required Index Families

Implementations SHOULD provide indexes or equivalent backend-native access
paths for:

- `(entity, relation)`,
- `(entity, relation, scope)`,
- `scope`,
- `timestamp`,
- HLC or cursor fields used by replication,
- conflict status,
- audit events by peer/principal and timestamp, and
- expiry pruning for nonce or replay caches.

The exact index names are implementation details.

## Federation And Audit Storage

Nodes that support federation MUST persist peer state, replication cursors,
replay/nonce state, and federation audit events. These records support
`Spec-05-Federation-Trust`, `Spec-09-Audit-Log`, and
`Spec-11-Replay-Protection`.

Federation metadata MUST be sufficient to resume replication after process
restart without duplicating accepted facts or skipping eligible facts.

## Alias And Compatibility Storage

Nodes that accept legacy non-canonical entity URIs SHOULD provide alias storage
or migration tooling that maps raw entity/source values to canonical forms.

Alias storage MUST NOT silently rewrite historical fact provenance. It is a
compatibility aid for query and migration workflows.

## Storage Backend Contract

A storage backend MUST provide:

- connection lifecycle management,
- transaction semantics that commit on success and roll back on exception,
- row access by column name,
- an idempotent migration runner, and
- optional snapshot export/import hooks when supported by the backend.

Backends MUST preserve the same logical schema contract even when SQL dialects
or execution mechanics differ.

## Plugin Migration Boundary

Core migrations are applied by the node. Plugin-declared migrations, when
enabled by the plugin infrastructure, MUST register through the migration hook
surface and MUST remain namespaced to the declaring plugin.

Plugin migration graph resolution, downgrade handling, and package discovery are
outside the `v0.9.0a1` stable schema contract.

## Out Of Scope

This spec does not define:

- every reference-node migration file,
- backend-specific DDL syntax,
- operator backup procedures,
- plugin package discovery,
- downgrade semantics, or
- future CID/tombstone migration details beyond their stable component specs.
