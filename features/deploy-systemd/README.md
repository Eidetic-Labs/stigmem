---
feature_id: deploy-systemd
title: systemd deployment
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: deployment
default_surface: external
canonical_spec: none
implementation_path: experimental/deploy-systemd
package: stigmem-node
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

# systemd Deployment

The systemd deployment feature contains the experimental bare-metal Linux
recipe for running a Stigmem node without Docker. It includes installer
guidance, an environment template, a systemd unit, hardening options, reverse
proxy guidance, offline install notes, logging, upgrade, smoke-test, and
uninstall commands under `experimental/deploy-systemd`.

systemd remains outside the current supported alpha deployment surface. Docker
Compose is the supported default path; systemd remains deferred until live
distro validation, installer review, hardening review, upgrade/rollback
validation, offline-install validation, and ownership gates complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/deploy-systemd` |
| Primary package | `stigmem-node` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
