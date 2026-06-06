---
feature_id: source-attestation
title: Source attestation
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X6-Source-Attestation
implementation_path: experimental/source-attestation
package: stigmem-plugin-source-attestation
adr_refs:
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-011
  - ADR-020 §11 (security taxonomy)
  - ADR-020
security_refs:
  - R-22
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Source Attestation

Source attestation validates asserted fact `source` values against
authenticated principals and explicit delegation lists in plugin-loaded
deployments. The feature is implemented as the opt-in
`stigmem-plugin-source-attestation` source package. Default installs remain
inert unless the plugin is registered and the relevant gates are enabled.

The current alpha plugin validates direct source matches, normalized source
matches, delegated-source identity metadata, recall rank contribution, and
federation inbound guard behavior. It does not prove release artifact
provenance, does not publish standalone plugin artifacts, and does not mark
accepted facts as locally re-attested.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/source-attestation/` |
| Primary package | `stigmem-plugin-source-attestation` |
| Canonical spec | `Spec-X6-Source-Attestation` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
