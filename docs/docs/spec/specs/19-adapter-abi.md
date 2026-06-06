---
spec_id: Spec-19-Adapter-ABI
version: 0.1.0-alpha.0
status: Draft
audience: Spec
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

<p className="stigmem-meta"><span>5 min read</span><span>Spec contributor · Adapter author</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The stable adapter contract for code that bridges Stigmem into agent
runtimes, tools, and platform hooks. Adapter behavior and failure
contracts; protocol-wide conformance vectors belong to their owning
component specs.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for the adapter ABI.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Adapter archetypes

<div className="stigmem-fields">

<div>
<dt>Archetype</dt>
<dt><span className="stigmem-fields__type">Failure posture</span></dt>
<dd>Description</dd>
</div>

<div>
<dt>Process-mode</dt>
<dt><span className="stigmem-fields__type">fail fast</span></dt>
<dd>Standalone processes whose primary purpose is to bridge another protocol to Stigmem. If Stigmem is unconfigured, fast failure is acceptable.</dd>
</div>

<div>
<dt>Middleware</dt>
<dt><span className="stigmem-fields__type">fail open</span></dt>
<dd>Extend an existing agent runtime. Stigmem is optional; the host agent MUST continue operating if Stigmem is absent, unreachable, or degraded.</dd>
</div>

</div>

Adapters SHOULD clearly document which archetype they implement.

## Environment contract

Adapters MUST honor these environment variables:

<div className="stigmem-fields">

<div>
<dt>Variable</dt>
<dt><span className="stigmem-fields__type">Required by</span></dt>
<dd>Description</dd>
</div>

<div>
<dt><code>STIGMEM_URL</code></dt>
<dt><span className="stigmem-fields__type">all adapters</span></dt>
<dd>Base URL of the Stigmem node. No default.</dd>
</div>

<div>
<dt><code>STIGMEM_API_KEY</code></dt>
<dt><span className="stigmem-fields__type">all adapters</span></dt>
<dd>API key when node auth is required. No default.</dd>
</div>

<div>
<dt><code>STIGMEM_SOURCE_ENTITY</code></dt>
<dt><span className="stigmem-fields__type">middleware</span></dt>
<dd>Entity URI used as <code>source</code> on write operations. Default is adapter-specific.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Process-mode adapters MUST exit non-zero if `STIGMEM_URL` is absent. Middleware adapters MUST skip Stigmem operations and MUST NOT change the host process exit code.**

</div>

## Boot handshake

Adapters SHOULD probe the node at startup:

```http
GET /.well-known/stigmem
```

The response must advertise node version, node id, node URL, auth
mode, and federation capability. Missing or malformed required
fields SHOULD be treated as a failed probe.

Process-mode adapters SHOULD log a probe failure and allow
individual tool calls to fail with adapter-level errors. Middleware
adapters MUST return an empty boot context and continue.

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

## Context pull

Middleware adapters MAY pull context during boot. All context
queries are non-fatal. A failed or empty query MUST NOT abort
startup.

Common context pulls include:

<div className="stigmem-grid">

<div><h4>Confident user/agent facts</h4><p>Above an adapter-defined confidence threshold.</p></div>
<div><h4>Project constraints</h4></div>
<div><h4>Pending handoffs</h4><p>Targeting <code>STIGMEM_SOURCE_ENTITY</code>.</p></div>
<div><h4>Recent escalations</h4></div>

</div>

Adapters SHOULD filter pulled facts to relevant namespaces to avoid
injecting unbounded or noisy context.

## Write surfaces

Adapters may assert lifecycle, handoff, decision, or escalation
facts. Write operations MUST use fire-and-forget semantics:

<div className="stigmem-grid">

<div><h4>No host crash</h4><p>Write failures MUST NOT crash the host process.</p></div>
<div><h4>Log warning</h4><p>Write failures SHOULD be logged at warning level.</p></div>
<div><h4>Lifecycle confidence=1.0</h4><p>Lifecycle and intent-routing facts SHOULD use <code>confidence=1.0</code>.</p></div>
<div><h4>Local heartbeats</h4><p>Activity/heartbeat facts MUST remain local unless a component spec explicitly says otherwise.</p></div>

</div>

Paperclip-style lifecycle facts use the `paperclip:` namespace
registered by `Spec-16-Namespace-Registry`. Intent and delegation
facts use the `intent:` namespace.

## Context injection format

Adapters that inject facts into an agent prompt SHOULD group facts
by relation namespace and render a concise Markdown summary:

```markdown
## Stigmem context - {user_entity}

### {namespace}
- **{relation}** on `{entity}`: {value_str}[ _(confidence: {confidence:.2f})_]
```

Rendering rules:

<div className="stigmem-grid">

<div><h4>Omit empty blocks</h4><p>Omit the entire context block when no facts were retrieved.</p></div>
<div><h4>Verbatim identifiers</h4><p>Preserve relation and entity strings verbatim.</p></div>
<div><h4>Null rendering</h4><p>Render <code>null</code> values as <code>(null)</code>.</p></div>
<div><h4>Confidence threshold</h4><p>Include confidence only when below <code>1.0</code>.</p></div>
<div><h4>Ordering</h4><p>Descending confidence, then descending HLC where available.</p></div>

</div>

Adapters that handle prompt injection risks SHOULD layer additional
sanitizer or structural-channel controls; those controls are outside
this ABI.

## Error handling contract

<div className="stigmem-keypoint">

**The crash-forbidden invariant applies to middleware adapters.**

A Stigmem node failure MUST NOT crash the host agent process.

</div>

<div className="stigmem-fields">

<div>
<dt>Scenario</dt>
<dt><span className="stigmem-fields__type">Process-mode</span></dt>
<dd>Middleware</dd>
</div>

<div>
<dt><code>STIGMEM_URL</code> absent</dt>
<dt><span className="stigmem-fields__type">exit non-zero</span></dt>
<dd>Skip Stigmem operations; exit code unchanged.</dd>
</div>

<div>
<dt>Node unreachable at boot</dt>
<dt><span className="stigmem-fields__type">log error; calls may fail</span></dt>
<dd>Log warning; return empty <code>BootContext</code>.</dd>
</div>

<div>
<dt>Node unreachable on write</dt>
<dt><span className="stigmem-fields__type">log warning; no crash</span></dt>
<dd>Log warning; no crash.</dd>
</div>

<div>
<dt>HTTP 4xx on write</dt>
<dt><span className="stigmem-fields__type">log error; no retry</span></dt>
<dd>Log error; no retry; no crash.</dd>
</div>

<div>
<dt>HTTP 5xx on write</dt>
<dt><span className="stigmem-fields__type">log error; MAY retry once</span></dt>
<dd>Log error; MAY retry once; no crash.</dd>
</div>

<div>
<dt>Boot query 4xx/5xx</dt>
<dt><span className="stigmem-fields__type">treat as empty</span></dt>
<dd>Treat as empty for that query.</dd>
</div>

</div>

## Adapter-specific conformance

Adapters that write lifecycle or intent facts SHOULD include
integration tests that verify:

<ol className="stigmem-steps">
<li>Expected relations appear in the fact store after lifecycle events.</li>
<li>Client-side validation rejects facts with wrong scope or too-low confidence, or the node response is handled without crashing.</li>
<li>Node unavailability does not crash middleware-mode hosts.</li>
</ol>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Protocol-wide conformance vectors</h4></div>
<div><h4>Adapter package layout</h4></div>
<div><h4>Plugin lifecycle APIs</h4></div>
<div><h4>Sanitizer requirements</h4><p>Prompt-injection.</p></div>
<div><h4>Adapter relation inventories</h4><p>Beyond registered namespace examples.</p></div>
<div><h4>SDK implementation details</h4></div>
<div><h4>Experimental adapter behavior</h4></div>

</div>
