---
feature_id: zep-adapter
title: Zep adapter
status: active
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: opt-in
canonical_spec: Spec-X7-Zep-Adapter
implementation_path: experimental/zep-adapter
package: stigmem-plugin-zep-adapter
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - v0.9.0a10
---

# Zep Adapter

The Zep adapter bridges Stigmem shared coordination facts with Zep
per-user/per-session episodic memory. It mirrors Stigmem facts into a Zep
session as structured system messages and maps Zep extracted facts back into
Stigmem-shaped records for query hydration or re-assertion.

The adapter source exists under `experimental/zep-adapter` and is packaged as
`stigmem-plugin-zep-adapter` for the v0.9.0a10 adapter publication batch. It
remains experimental and host-application opt-in; live Zep validation is
operator-owned for v0.1.0.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/zep-adapter` |
| Primary package | `stigmem-plugin-zep-adapter` |
| Canonical spec | `Spec-X7-Zep-Adapter` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
