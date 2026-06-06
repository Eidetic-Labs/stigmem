---
feature_id: gemini-adapter
title: Gemini adapter
status: active
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: opt-in
canonical_spec: Spec-X7-Gemini-Adapter
implementation_path: experimental/gemini-adapter
package: stigmem-plugin-gemini-adapter
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

# Gemini Adapter

The Gemini adapter exposes Stigmem tool calls in Google Gemini's native
`FunctionDeclaration` format. It provides raw function declarations, a dispatch
surface for Gemini function-call parts, and an optional convenience loop for a
tool-enabled Gemini turn.

The adapter source exists under `experimental/gemini-adapter` and is packaged
as `stigmem-plugin-gemini-adapter` for the v0.9.0a10 adapter publication batch.
It remains experimental and host-application opt-in; live Gemini validation is
operator-owned for v0.1.0.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/gemini-adapter` |
| Primary package | `stigmem-plugin-gemini-adapter` |
| Canonical spec | `Spec-X7-Gemini-Adapter` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
