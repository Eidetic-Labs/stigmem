---
feature_id: ollama-litellm-adapter
title: Ollama/LiteLLM adapter
status: superseded
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: external
canonical_spec: none
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
  - 0.9.xA
---

# Ollama/LiteLLM Adapter

The Ollama/LiteLLM adapter record preserves the legacy connector name for
local and LiteLLM-hosted models. The implementation is the OpenAI-compatible
tools adapter, which exposes Stigmem tools in lower-case JSON Schema
function-calling format for LiteLLM, Ollama-compatible chat endpoints, and the
OpenAI Python SDK.

This feature record exists to keep the historical Ollama/LiteLLM surface
discoverable without creating a second source of truth. Behavior, code, and
tests live under `experimental/openai-tools-adapter`; the OpenAI tools feature
record now owns the package publication facts.

## Current State

| Field | Value |
| --- | --- |
| Status | `superseded` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/openai-tools-adapter` |
| Primary package | `stigmem-plugin-openai-tools-adapter` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
