---
feature_id: deploy-helm
title: Helm deployment
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: deployment
default_surface: external
canonical_spec: none
implementation_path: experimental/deploy-helm
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

# Helm Deployment

The Helm deployment feature contains the experimental Kubernetes chart and
operator recipe for deploying a Stigmem node with Helm. It includes chart
metadata, values, templates, secret-reference patterns, hardening defaults, and
operator setup guidance under `experimental/deploy-helm`.

The chart remains outside the current supported alpha deployment surface.
Docker Compose is the supported default path; Helm remains deferred until
operator validation, chart publication, hardening review, and ownership gates
complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/deploy-helm` |
| Primary package | `stigmem` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
