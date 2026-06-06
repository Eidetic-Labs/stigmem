---
spec_id: Spec-16-Namespace-Registry
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 9 namespace-registry material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-15-Fact-Semantics >= 0.1.0-alpha.0
---

# Spec-16-Namespace-Registry

`Spec-16-Namespace-Registry` defines the relation-prefix registry used by facts,
meta-facts, and protocol-owned relations.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for the namespace registry.
Atomic fact shape and relation field rules are owned by `Spec-01-Fact-Model`;
conflict and TTL semantics are owned by `Spec-15-Fact-Semantics`.

Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Reserved Prefixes

Reserved prefixes are maintained by the spec. Implementations and adapters
MUST NOT define incompatible meanings for these prefixes.

| Prefix | Governed by | Purpose |
|---|---|---|
| `stigmem:` | Spec maintainers | Core protocol relations, including `stigmem:ttl`, `stigmem:received_from`, `stigmem:member`, `stigmem:conflict:between`, `stigmem:conflict:status`, and `stigmem:resolves`. |
| `rel:` | Spec maintainers | Reification primitives: `rel:subject`, `rel:object`, and `rel:type`. |
| `stigmem:lint:` | Spec maintainers | Reserved for future lint-related protocol relations. Current lint behavior is an API operation and does not require fact assertions. |
| `stigmem:decay:` | Spec maintainers | Reserved for future decay-related protocol relations. Current decay behavior is deferred and remains outside the stable component set. |

## Registered Community Prefixes

Registered community prefixes are stable enough for interoperability but are not
owned by a single protocol mechanism.

| Prefix | Status | Notes |
|---|---|---|
| `memory:` | Registered | Agent memory: role, preference, context. |
| `intent:` | Registered | Intent and delegation facts, including `intent:handoff_to`, `intent:handoff_summary`, `intent:context_ref`, `intent:continuation`, `intent:escalation`, `intent:escalate_to`, and `intent:goal`. |
| `roadmap:` | Registered | Project and product state facts, including `roadmap:decision`, `roadmap:constraint`, `roadmap:status`, and `roadmap:summary`. |
| `preference:` | Registered | User and agent preferences. |
| `paperclip:` | Registered | Paperclip adapter lifecycle facts: `paperclip:checkout`, `paperclip:issue_status`, `paperclip:last_active`, and `paperclip:blocked_by`. |

## Experimental Prefix

The `x-` prefix is reserved for informal or experimental use. No registration is
required for `x-` relations.

Experimental prefixes MUST NOT be treated as stable protocol commitments. A
relation that graduates from experimental use SHOULD move to a registered or
reserved prefix as part of its stabilization work.

## Out Of Scope

This spec does not define:

- relation-specific semantics,
- adapter-specific relation inventories,
- namespace ownership outside Stigmem facts, or
- a public registration workflow.
