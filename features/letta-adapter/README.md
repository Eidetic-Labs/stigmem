---
feature_id: letta-adapter
title: Letta adapter
status: active
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: opt-in
canonical_spec: Spec-X7-Letta-Adapter
implementation_path: experimental/letta-adapter
package: stigmem-plugin-letta-adapter
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

# Letta Adapter

The Letta adapter bridges Stigmem shared coordination facts with Letta
per-agent archival memory. It writes Stigmem facts into a Letta agent as tagged
archival passages and can read Letta archival memory back as Stigmem-shaped
records.

The adapter source exists under `experimental/letta-adapter` and is packaged as
`stigmem-plugin-letta-adapter` for the v0.9.0a10 adapter publication batch. It
remains experimental and host-application opt-in; live Letta validation is
operator-owned for v0.1.0.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/letta-adapter` |
| Primary package | `stigmem-plugin-letta-adapter` |
| Canonical spec | `Spec-X7-Letta-Adapter` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
