---
feature_id: mcp-adapter
title: MCP adapter
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: adapter
default_surface: external
canonical_spec: none
implementation_path: adapters/mcp
package: "@eidetic-labs/stigmem-mcp"
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020
security_refs:
  - R-05
  - R-15
  - R-21
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# MCP Adapter

The MCP adapter exposes a running Stigmem node as Model Context Protocol tools
for stdio-capable agent hosts. `0.1.0` scopes validated host UI support
to Codex CLI, Claude Code, Gemini CLI with its final-response caveat, and
repo-local MCP protocol smoke. Continue.dev, Cursor, Zed, and custom-host use
remain experimental until host-specific smoke evidence exists. The adapter is a
stateless TypeScript process that translates MCP tool calls into HTTP requests
against the configured node.

The adapter source is active and tested. The `@eidetic-labs/stigmem-mcp`
package is independently versioned from the Stigmem project release line and
repo-local MCP protocol smoke passes against a live node. The `0.1.0` package
is public on npm as the manual bootstrap publication; future publications use
npm Trusted Publisher/OIDC via `.github/workflows/mcp-publish.yml`.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `adapters/mcp` |
| Primary package | `@eidetic-labs/stigmem-mcp` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
