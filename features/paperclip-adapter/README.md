---
feature_id: paperclip-adapter
title: Paperclip adapter
status: deferred
stability: experimental
since: 0.9.0a1
owner: unowned
feature_type: adapter
default_surface: external
canonical_spec: none
implementation_path: experimental/paperclip-adapter
package: none
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

# Paperclip Adapter

The Paperclip adapter records Paperclip agent lifecycle events as Stigmem
facts. It provides a company skill, a JavaScript fact-emission helper, and a
shell hook that can assert checkout, issue status, blocker, heartbeat, handoff,
and decision facts from Paperclip-managed agent workflows.

The adapter is preserved as experimental external adapter surface area under
`experimental/paperclip-adapter`. It remains outside the current alpha artifact
set until ownership, installation packaging, live Paperclip validation, and
security review are complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/paperclip-adapter` |
| Primary package | `none` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
