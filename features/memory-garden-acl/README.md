---
feature_id: memory-garden-acl
title: Memory Garden advanced ACL
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X5-Memory-Garden-Advanced-ACL
implementation_path: experimental/memory-garden-acl
package: stigmem-plugin-memory-garden-acl
adr_refs:
  - ADR-002
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-011
  - ADR-020 §11 (security taxonomy)
  - ADR-020
security_refs:
  - R-21
release_lines:
  - v0.9.0a1
  - v0.9.0a6
  - 0.9.xA
---

# Memory Garden Advanced ACL

Memory Garden advanced ACL behavior extends the core garden CRUD,
membership, and direct `garden_id` read/write guards with opt-in cross-surface
authorization hooks. The implementation remains the
`stigmem-plugin-memory-garden-acl` source package under
`experimental/memory-garden-acl/`.

This feature remains experimental. The feature record owns the spec, status,
evidence, security analysis, and feature-local history. The legacy
`experimental/memory-garden-acl/` directory remains the current implementation
path.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/memory-garden-acl/` |
| Primary package | `stigmem-plugin-memory-garden-acl` |
| Canonical spec | `Spec-X5-Memory-Garden-Advanced-ACL` |
| Current release validation | `v0.9.0a6` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
