---
feature_id: obsidian-adapter
title: Obsidian adapter
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: adapter
default_surface: external
canonical_spec: none
implementation_path: experimental/obsidian-adapter
package: stigmem-obsidian
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - R-07
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Obsidian Adapter

The Obsidian adapter synchronizes markdown vault content with a Stigmem node.
It has two experimental implementation surfaces: a Python CLI/daemon package
for Obsidian, Logseq, Dendron, and plain-folder vaults, and an Obsidian plugin
that runs inside the Obsidian process.

The adapter source exists under `experimental/obsidian-adapter` and includes
tests for the CLI and plugin. It remains outside the current alpha artifact set
until package, plugin, threat-model, and live-vault validation are complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/obsidian-adapter` |
| Primary package | `stigmem-obsidian` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
