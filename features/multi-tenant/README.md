---
feature_id: multi-tenant
title: Multi-tenant scoping
status: active
stability: experimental
since: 0.9.0a8
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: none
implementation_path: experimental/multi-tenant
package: stigmem-plugin-multi-tenant
adr_refs:
  - ADR-002
  - ADR-008
  - ADR-020 §13 (repo structure)
  - ADR-011
  - ADR-020 §11 (security taxonomy)
  - ADR-020
security_refs:
  - R-01
  - R-02
  - R-21
release_lines:
  - v0.9.0a8
  - 0.9.xA
---

# Multi-Tenant Scoping

Multi-tenant scoping is an opt-in experimental plugin that resolves API-key
tenant identity into a tenant-scoped request context. Default installs collapse
all callers into the single `default` tenant even when stored API keys carry
non-default tenant IDs.

The implementation remains the `stigmem-plugin-multi-tenant` source package
under `experimental/multi-tenant/`. Core storage compatibility columns remain
in the node so single-tenant deployments and upgraded data continue to use
`tenant_id = "default"`.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/multi-tenant/` |
| Primary package | `stigmem-plugin-multi-tenant` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
