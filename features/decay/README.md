---
feature_id: decay
title: Decay semantics
status: deferred
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: protocol
default_surface: opt-in
canonical_spec: Spec-X9-Decay-Semantics
implementation_path: experimental/decay
adr_refs:
  - ADR-002
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - R-02
  - R-16
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Decay Semantics

Decay semantics define confidence decay and sweep behavior for stale facts.
The feature remains experimental and outside the default supported surface even
though parts of the current node expose decay-related code and tests.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/decay/` |
| Primary package | None currently published |
| Canonical spec | `Spec-X9-Decay-Semantics` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
