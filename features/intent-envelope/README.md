---
feature_id: intent-envelope
title: Intent envelope
status: deferred
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: protocol
default_surface: opt-in
canonical_spec: Spec-X8-Intent-Envelope
implementation_path: experimental/intent-envelope
adr_refs:
  - ADR-001
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - R-05
  - R-15
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Intent Envelope

Intent envelope preserves the deferred design for typed goal, constraint,
preference, handoff, abandon, and escalation facts. It remains outside the
default supported surface and has no current implementation package.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/intent-envelope/` |
| Primary package | None currently published |
| Canonical spec | `Spec-X8-Intent-Envelope` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
