---
feature_id: async-jobs
title: Async jobs
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: core
default_surface: opt-in
canonical_spec: none
implementation_path: node/src/stigmem_node/jobs.py
package: stigmem-node
adr_refs:
  - ADR-002
  - ADR-020 §13 (repo structure)
  - ADR-020 §9 (modular specs)
  - ADR-020
security_refs:
  - none
release_lines:
  - v0.9.0a1
  - 0.9.xA
---

# Async Jobs

Async jobs are the node-local background execution path for long-running lint
and decay sweeps. Small scopes return synchronous HTTP 200 responses. Scopes
above the configured threshold can return HTTP 202 with a job id that callers
poll until completion.

The feature is experimental and outside the default product surface. It is
implemented in core node routes and job storage rather than as a plugin.
Detailed lint and decay semantics remain owned by their respective feature or
spec records; this feature owns the shared job lifecycle, polling shape,
threshold behavior, and cross-type isolation.

## Current State

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `opt-in` |
| Primary implementation | `node/src/stigmem_node/jobs.py` |
| Primary tests | `node/tests/lifecycle/test_async_jobs.py` |
| Canonical spec | `none` |

## Feature Files

- [Spec](./spec.md)
- [Status](./status.md)
- [Evidence](./evidence.md)
- [Security](./security.md)
- [Changelog](./changelog.md)
