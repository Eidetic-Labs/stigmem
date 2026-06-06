---
feature_id: eval-harness
title: Evaluation harness
status: active
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: tooling
default_surface: internal
canonical_spec: none
implementation_path: eval
package: none
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - v0.9.0a11
---

# Evaluation Harness

The evaluation harness is experimental internal tooling for validating Stigmem
node correctness, adversarial resilience, and recall quality. The current
repository surface under `eval/` includes runnable pytest entry points,
adversarial and recall corpora, harness helpers, result artifacts, Make targets,
and CI coverage.

For `v0.9.0a11`, the harness is treated as an internal foundation gate rather
than a standalone package. The legacy `experimental/eval-harness` directory
remains as concept documentation and a compatibility pointer to this feature
record.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `internal` |
| Primary implementation | `eval` |
| Primary package | `none` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
