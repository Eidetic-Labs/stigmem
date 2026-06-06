---
feature_id: deploy-grafana
title: Grafana deployment
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: deployment
default_surface: external
canonical_spec: none
implementation_path: experimental/deploy-grafana
package: none
adr_refs:
  - ADR-002
  - ADR-004
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Grafana Deployment

The Grafana deployment feature contains experimental observability seed
material for operators who want to visualize Stigmem metrics and traces. It
includes Grafana dashboard JSON, Grafana provisioning files, Prometheus scrape
and alert seeds, and a Tempo local trace configuration under
`experimental/deploy-grafana`.

Grafana remains outside the current supported alpha deployment surface. Docker
Compose is the supported default deployment path, while metrics and
OpenTelemetry signals are the supported observability interfaces. The packaged
Grafana/Prometheus/Tempo recipe remains deferred until live stack validation,
metric contract review, alert review, packaging guidance, and ownership gates
complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/deploy-grafana` |
| Primary package | `none` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
