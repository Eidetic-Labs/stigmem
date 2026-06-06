---
feature_id: cognee-adapter
title: Cognee adapter
status: active
stability: experimental
since: 0.9.0a10
owner: eidetic-labs
feature_type: adapter
default_surface: opt-in
canonical_spec: none
implementation_path: experimental/cognee-adapter
package: stigmem-plugin-cognee-adapter
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

# Cognee Adapter

The Cognee adapter bridges Stigmem atomic facts with Cognee's knowledge-graph
layer. It serializes facts into structured text for Cognee ingestion and maps
Cognee semantic-search results back into Stigmem-shaped fact records.

The adapter source exists under `experimental/cognee-adapter`. It is packaged
as an experimental opt-in plugin for the v0.9.0a10 adapter publication batch.
Installing the package makes the plugin discoverable; host applications still
choose when to call the Cognee bridge.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `experimental/cognee-adapter` |
| Primary package | `stigmem-plugin-cognee-adapter` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
