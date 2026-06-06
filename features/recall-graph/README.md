---
feature_id: recall-graph
title: Recall graph
status: deferred
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: protocol
default_surface: opt-in
canonical_spec: Spec-X11-Recall-Graph
implementation_path: experimental/recall-graph
adr_refs:
  - ADR-002
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - R-13
  - R-20
  - R-21
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Recall Graph

Recall graph preserves the advanced graph adjacency index, embedding storage,
hybrid recall pipeline, memory cards, and causal-link design. The default
supported recall surface remains owned by `Spec-07-Recall-Pipeline`; this
feature record owns the deferred advanced graph material.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/recall-graph/` |
| Primary package | None currently published |
| Canonical spec | `Spec-X11-Recall-Graph` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
