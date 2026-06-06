---
feature_id: deploy-fly
title: Fly.io deployment
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: deployment
default_surface: external
canonical_spec: none
implementation_path: experimental/deploy-fly
package: stigmem
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

# Fly.io Deployment

The Fly.io deployment feature contains the experimental recipe for running a
single Stigmem node, and optionally the dashboard, on Fly.io. It includes
Fly machine configuration, persistent-volume guidance, health checks, metrics,
OIDC secret setup, and SQLite/libSQL storage options under
`experimental/deploy-fly`.

Fly.io remains outside the current supported alpha deployment surface. Docker
Compose is the supported default path; Fly.io remains deferred until live
deployment validation, secrets posture review, persistence and restore
validation, dashboard validation, and ownership gates complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/deploy-fly` |
| Primary package | `stigmem` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
