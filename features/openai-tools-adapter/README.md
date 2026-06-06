---
feature_id: openai-tools-adapter
title: OpenAI tools adapter
status: active
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: opt-in
canonical_spec: Spec-X7-OpenAI-Tools-Adapter
implementation_path: experimental/openai-tools-adapter
package: stigmem-plugin-openai-tools-adapter
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

# OpenAI Tools Adapter

The OpenAI tools adapter exposes Stigmem operations in OpenAI-compatible
function-calling format. It provides lower-case JSON Schema tool declarations,
dispatch for model-returned tool calls, and optional convenience loops for
LiteLLM and the OpenAI Python SDK.

The adapter is packaged as an experimental opt-in plugin under
`experimental/openai-tools-adapter`. It is discoverable through the
`stigmem.plugins` entry-point group after installation, but it has no
node-global behavior gate and performs no work unless a host application
imports and calls the adapter.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/openai-tools-adapter` |
| Primary package | `stigmem-plugin-openai-tools-adapter` |
| Canonical spec | `Spec-X7-OpenAI-Tools-Adapter` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
