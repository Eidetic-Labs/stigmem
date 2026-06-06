---
feature_id: storage-libsql
title: libSQL storage
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: adapter
default_surface: opt-in
canonical_spec: none
implementation_path: node/src/stigmem_node/storage/libsql_backend.py
package: stigmem-node
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - R-04
  - R-08
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# libSQL Storage

libSQL storage is the opt-in Turso-compatible persistence adapter for the
reference node. It implements the shared storage backend contract with local
libSQL mode and embedded-replica mode, where a local database file syncs with a
remote Turso/libSQL primary.

SQLite remains the default storage backend. libSQL storage is active in source
but experimental for operators until backend parity, restore, encryption, and
runbook evidence are fully certified for a release line.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `node/src/stigmem_node/storage/libsql_backend.py` |
| Primary package | `stigmem-node` |
| Canonical spec | `none` |
| Parent feature | [`features/storage-backends`](../storage-backends/README.md) |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
