---
feature_id: lazy-instruction-discovery
title: Lazy instruction discovery
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X1-Lazy-Instruction-Discovery
implementation_path: experimental/lazy-instruction-discovery
package: stigmem-plugin-lazy-instruction-discovery
adr_refs:
  - ADR-003
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-011
  - ADR-020 §11 (security taxonomy)
  - ADR-020
security_refs:
  - R-15
  - R-21
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Lazy Instruction Discovery

Lazy instruction discovery lets agents load instruction-typed facts on demand
through a boot stub, instruction manifest, and `recall_instruction` interface.
The feature is implemented as the opt-in
`stigmem-plugin-lazy-instruction-discovery` source package.

This feature remains experimental and blocked from graduation while R-15
instruction-scope write authority remains open.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/lazy-instruction-discovery/` |
| Primary package | `stigmem-plugin-lazy-instruction-discovery` |
| Canonical spec | `Spec-X1-Lazy-Instruction-Discovery` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
