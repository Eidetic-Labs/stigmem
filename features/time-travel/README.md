---
feature_id: time-travel
title: Time-travel queries
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X3-Time-Travel-Queries
implementation_path: experimental/time-travel
package: stigmem-plugin-time-travel
adr_refs:
  - ADR-008
  - ADR-020 §9 (modular specs)
  - ADR-011
  - ADR-020
security_refs:
  - R-17
  - R-18
release_lines:
  - v0.9.0a1
  - v0.9.0a4
---

# Time-Travel Queries

Time-travel queries allow fact and recall reads at a caller-supplied historical
timestamp through the `as_of` parameter. The feature is implemented as the
opt-in `stigmem-plugin-time-travel` source package. Default installs fail
closed when `as_of` is supplied without the plugin; registered plugin installs
still require explicit operator gates before fact-query or recall `as_of`
surfaces run.

This feature remains experimental. The feature record owns the long-term spec,
status, evidence, security analysis, and change history. The legacy
`experimental/time-travel/` directory remains the current implementation path
and now links to this record for canonical product truth.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/time-travel/` |
| Primary package | `stigmem-plugin-time-travel` |
| Canonical spec | `Spec-X3-Time-Travel-Queries` |

## Implementation Surface

| Surface | Path | Notes |
| --- | --- | --- |
| Plugin package | `experimental/time-travel/` | Source package, manifest, config schema, and hook handlers. |
| Plugin manifest | `experimental/time-travel/src/stigmem_plugin_time_travel/manifest.py` | Declares package name, capabilities, hooks, and config schema. |
| Plugin config | `experimental/time-travel/src/stigmem_plugin_time_travel/config.py` | Defaults historical reads off until explicitly enabled. |
| Core fail-closed behavior | `node/src/stigmem_node/routes/time_travel_gate.py`; `node/src/stigmem_node/routes/facts/query.py`; `node/src/stigmem_node/routes/recall/orchestration.py` | Rejects `as_of` without the plugin or without explicit surface gates. |
| Historical read implementation | `node/src/stigmem_node/routes/recall/as_of.py` and fact query helpers | Validates a4 timestamp, retention, retraction, expiry, CID, tombstone, legal-hold, and recall-scoring behavior when enabled. |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
