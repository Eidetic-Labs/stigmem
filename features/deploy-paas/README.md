---
feature_id: deploy-paas
title: PaaS deployment
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: deployment
default_surface: external
canonical_spec: none
implementation_path: experimental/deploy-paas
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

# PaaS Deployment

The PaaS deployment feature contains experimental recipes for running a
Stigmem node on managed container platforms: Render, Railway, AWS App Runner,
and Google Cloud Run. The implementation source under `experimental/deploy-paas`
captures platform-specific build, environment, secrets, health-check,
persistence, and rollback guidance.

PaaS remains outside the current supported alpha deployment surface. Docker
Compose is the supported default path; PaaS remains deferred until live
platform validation, secrets posture review, persistence validation, cost and
scaling review, and ownership gates complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/deploy-paas` |
| Primary package | `stigmem` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
