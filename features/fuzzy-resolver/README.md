---
feature_id: fuzzy-resolver
title: Fuzzy resolver
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: core
default_surface: opt-in
canonical_spec: none
implementation_path: node/src/stigmem_node/recall/entity_resolver.py
package: stigmem-node
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Fuzzy Resolver

Fuzzy resolver is the core entity-resolution helper for matching variant entity
URIs to a canonical entity. It combines deterministic normalization, explicit
alias mappings, and same-type token scoring over the live fact graph.

The feature is experimental and outside the default critical-path surface. It
is implemented in core node code and exposed through authenticated entity and
alias APIs.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `node/src/stigmem_node/recall/entity_resolver.py` |
| Primary route | `node/src/stigmem_node/routes/resolver.py` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
