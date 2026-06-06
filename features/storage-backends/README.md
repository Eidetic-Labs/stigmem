---
feature_id: storage-backends
title: Storage backends
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: adapter
default_surface: opt-in
canonical_spec: none
implementation_path: node/src/stigmem_node/storage
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

# Storage Backends

Storage backends are the reference node persistence adapters behind the shared
`StorageBackend` interface. SQLite remains the default backend. libSQL/Turso
and Postgres are opt-in adapter surfaces for operators who need cloud-backed
durability, multi-region reads, or an existing managed database tier.

The feature record owns the backend-selection contract, shared adapter
lifecycle, evidence, and security posture. Backend-specific detail can live in
child records such as `storage-libsql`.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `node/src/stigmem_node/storage/` |
| Primary package | `stigmem-node` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
