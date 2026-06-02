---
feature_id: tombstones
title: RTBF tombstones
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X2-RTBF-Tombstones
implementation_path: experimental/tombstones
package: stigmem-plugin-tombstones
adr_refs:
  - ADR-008
  - ADR-010
  - ADR-011
  - ADR-018
  - ADR-020
security_refs:
  - R-16
  - R-17
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# RTBF Tombstones

RTBF tombstones are signed, durable suppression records for right-to-be-
forgotten workflows. The feature is implemented as the opt-in
`stigmem-plugin-tombstones` source package; default installs mount the
tombstone route contracts but keep them access-gated and do not apply tombstone
filters unless the plugin is registered.

This feature remains experimental because tombstone issuance, revocation,
federation propagation, and legal-hold access all carry compliance and security
risk.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/tombstones/` |
| Primary package | `stigmem-plugin-tombstones` |
| Canonical spec | `Spec-X2-RTBF-Tombstones` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
