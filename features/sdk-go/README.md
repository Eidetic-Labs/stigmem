---
feature_id: sdk-go
title: Go SDK
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: sdk
default_surface: external
canonical_spec: none
implementation_path: experimental/sdk-go
package: stigmem-go
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

# Go SDK

The Go SDK is an experimental Go client for the Stigmem node HTTP API. It
provides typed helpers for node metadata, fact assertion and querying, conflict
resolution, federation peer listing, polling-style subscriptions, recall, and
memory-card access.

The source exists under `experimental/sdk-go` and includes unit tests and an
example. The SDK remains outside the current alpha artifact set until package,
API parity, and release-line validation are complete.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `external` |
| Primary implementation | `experimental/sdk-go` |
| Primary package | `stigmem-go` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
