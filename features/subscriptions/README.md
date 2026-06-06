---
feature_id: subscriptions
title: Subscriptions
status: deferred
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: protocol
default_surface: opt-in
canonical_spec: Spec-X7-Subscriptions
implementation_path: experimental/subscriptions
adr_refs:
  - ADR-002
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - R-14
  - R-16
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Subscriptions

Subscriptions define push-style notification for fact, contradiction, and
memory-card changes. The feature remains experimental because event delivery
can leak information after access revocation unless delivery-time
authorization, replay windows, and operator runbooks are fully validated.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/subscriptions/` |
| Primary package | None currently published |
| Canonical spec | `Spec-X7-Subscriptions` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
