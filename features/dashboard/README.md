---
feature_id: dashboard
title: Dashboard
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: tooling
default_surface: internal
canonical_spec: none
implementation_path: experimental/dashboard
package: dashboard
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Dashboard

The dashboard is a deferred Next.js curator UI for Stigmem fact graph
operations. It provides an authenticated web surface, navigation shell, API
client utilities, session handling, and smoke/unit tests under
`experimental/dashboard`.

The dashboard remains outside the current alpha artifact set. It is preserved
as experimental internal tooling until ownership, deployment posture,
dependency currency, live-node validation, and UI security gates are complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `internal` |
| Primary implementation | `experimental/dashboard` |
| Primary package | `dashboard` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
