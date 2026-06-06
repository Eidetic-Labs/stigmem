---
spec_id: Spec-19-Adapter-ABI
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 12 adapter ABI material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
  - Spec-07-Recall-Pipeline >= 0.1.0-alpha.0
  - Spec-16-Namespace-Registry >= 0.1.0-alpha.0
  - Spec-18-Conformance-and-Failure-Modes >= 0.1.0-alpha.0
---

# Spec-19-Adapter-ABI

`Spec-19-Adapter-ABI` defines the stable adapter contract for code that bridges
Stigmem into agent runtimes, tools, and platform hooks.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for the adapter ABI. It focuses
on adapter behavior and failure contracts. Protocol-wide conformance vectors
belong to their owning component specs.

Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Adapter Archetypes

The ABI recognizes two adapter archetypes:

- **Process-mode adapters** are standalone processes whose primary purpose is to
  bridge another protocol to Stigmem. If Stigmem is unconfigured, fast failure
  is acceptable.
- **Middleware adapters** extend an existing agent runtime. Stigmem is optional;
  the host agent MUST continue operating if Stigmem is absent, unreachable, or
  degraded.

Adapters SHOULD clearly document which archetype they implement.

## Environment Contract

Adapters MUST honor these environment variables:

| Variable | Required by | Default | Description |
|---|---|---|---|
| `STIGMEM_URL` | All adapters | none | Base URL of the Stigmem node. |
| `STIGMEM_API_KEY` | All adapters | none | API key when node auth is required. |
| `STIGMEM_SOURCE_ENTITY` | Middleware adapters | adapter-specific | Entity URI used as `source` on write operations. |

Process-mode adapters MUST exit non-zero with a clear stderr message if
`STIGMEM_URL` is absent.

Middleware adapters MUST skip Stigmem operations when `STIGMEM_URL` is absent
and MUST NOT change the host process exit code.

## Boot Handshake

Adapters SHOULD probe the node at startup:

```http
GET /.well-known/stigmem
```

The response must advertise node version, node id, node URL, auth mode, and
federation capability. Missing or malformed required fields SHOULD be treated as
a failed probe.

Process-mode adapters SHOULD log a probe failure and allow individual tool
calls to fail with adapter-level errors. Middleware adapters MUST return an
empty boot context and continue.

## BootContext

Middleware adapters that inject Stigmem context return:

```text
BootContext {
  facts:   Fact[]
  summary: string
}
```

`BootContext` is always returned. On total failure, it MUST be:

```text
BootContext { facts: [], summary: "" }
```

## Context Pull

Middleware adapters MAY pull context during boot. All context queries are
non-fatal. A failed or empty query MUST NOT abort startup.

Common context pulls include:

- user or agent facts above an adapter-defined confidence threshold,
- project constraints,
- pending handoffs targeting `STIGMEM_SOURCE_ENTITY`, and
- recent escalations.

Adapters SHOULD filter pulled facts to relevant namespaces to avoid injecting
unbounded or noisy context.

## Write Surfaces

Adapters may assert lifecycle, handoff, decision, or escalation facts. Write
operations MUST use fire-and-forget semantics:

- write failures MUST NOT crash the host process,
- write failures SHOULD be logged at warning level,
- lifecycle and intent-routing facts SHOULD use `confidence=1.0`, and
- activity/heartbeat facts MUST remain local unless a component spec explicitly
  says otherwise.

Paperclip-style lifecycle facts use the `paperclip:` namespace registered by
`Spec-16-Namespace-Registry`. Intent and delegation facts use the `intent:`
namespace.

## Context Injection Format

Adapters that inject facts into an agent prompt SHOULD group facts by relation
namespace and render a concise Markdown summary:

```markdown
## Stigmem context - {user_entity}

### {namespace}
- **{relation}** on `{entity}`: {value_str}[ _(confidence: {confidence:.2f})_]
```

Rendering rules:

- omit the entire context block when no facts were retrieved,
- preserve relation and entity strings verbatim,
- render `null` values as `(null)`,
- include confidence only when below `1.0`, and
- order facts by descending confidence, then descending HLC where available.

Adapters that handle prompt injection risks SHOULD layer additional sanitizer or
structural-channel controls; those controls are outside this ABI.

## Error Handling Contract

The crash-forbidden invariant applies to middleware adapters: a Stigmem node
failure MUST NOT crash the host agent process.

| Scenario | Process-mode adapter | Middleware adapter |
|---|---|---|
| `STIGMEM_URL` absent | Exit non-zero with clear stderr message. | Skip Stigmem operations; exit code unchanged. |
| Node unreachable at boot | Log error; individual calls may fail. | Log warning; return empty `BootContext`. |
| Node unreachable on write | Log warning; no crash. | Log warning; no crash. |
| Node returns HTTP 4xx on write | Log error; no retry; no crash. | Log error; no retry; no crash. |
| Node returns HTTP 5xx on write | Log error; MAY retry once; no crash. | Log error; MAY retry once; no crash. |
| Boot query returns HTTP 4xx or 5xx | Treat as empty for that query. | Treat as empty for that query. |

## Adapter-Specific Conformance

Adapters that write lifecycle or intent facts SHOULD include integration tests
that verify:

1. Expected relations appear in the fact store after lifecycle events.
2. Client-side validation rejects facts with wrong scope or too-low confidence,
   or the node response is handled without crashing.
3. Node unavailability does not crash middleware-mode hosts.

## Out Of Scope

This spec does not define:

- protocol-wide conformance vectors,
- adapter package layout,
- plugin lifecycle APIs,
- prompt-injection sanitizer requirements,
- adapter-specific relation inventories beyond registered namespace examples,
- SDK implementation details, or
- experimental adapter behavior.
