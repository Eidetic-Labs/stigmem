---
title: Features
sidebar_label: Features
sidebar_position: 1
description: What Stigmem does today in v0.9.0a1 — feature status table calibrated to ADR-002 v1 critical-path scope.
---

# Features

<p className="stigmem-meta"><span>6 min read</span><span>Evaluator · Integrator · Operator</span><span>v0.9.0a1</span></p>

<div className="stigmem-lead">

**What Stigmem is**

An open, federated knowledge protocol — a layer where AI agents and
humans store typed, traceable facts that travel across tools,
platforms, and organizations. Each fact is an immutable record
`(entity, relation, value, source, timestamp, confidence, scope)`
written once, queryable forever, with full provenance and a defined
expiry.

</div>

<div className="stigmem-keypoint">

**This page describes v0.9.0a1 and the active alpha extraction line.**

The canonical version line of stigmem begins at <code>v0.9.0a1</code>
per [ADR-001](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md)
+ [ADR-001](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md).
Earlier version markers labeled internal development checkpoints, not
tagged releases. Many features that earlier docs described as
"Stable" were deferred per [ADR-002](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/002-v1-scope.md)
— the v1 critical-path scope cut. Those features remain in the
codebase as opt-in or deferred surfaces. Migrated feature truth now lives in
[`features/<feature>/`](https://github.com/eidetic-labs/stigmem/tree/main/features);
implementation packages that still live under
[`experimental/<feature>/`](https://github.com/eidetic-labs/stigmem/tree/main/experimental)
remain gated and off by default.

</div>

## How to read this page

<div className="stigmem-fields">

<div>
<dt>Status</dt>
<dt><span className="stigmem-fields__type">Promise</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><strong>Stable</strong></dt>
<dt><span className="stigmem-fields__type">spec normative · core</span></dt>
<dd>Spec section normative in v0.9.0a1; in core; no breaking changes within v0.9.0a series wire-format scope.</dd>
</div>

<div>
<dt><strong>Preview</strong></dt>
<dt><span className="stigmem-fields__type">no guarantee · pin versions</span></dt>
<dd>Shipped as part of v0.9.0a1 with no stability guarantee.</dd>
</div>

<div>
<dt><strong>Experimental</strong></dt>
<dt><span className="stigmem-fields__type">opt-in plugin</span></dt>
<dd>Feature record lives under <code>features/&lt;feature&gt;/</code> once migrated; implementation may remain under <code>experimental/&lt;feature&gt;/</code>. Not in the default install.</dd>
</div>

<div>
<dt><strong>Deferred</strong></dt>
<dt><span className="stigmem-fields__type">non-critical-path</span></dt>
<dd>Feature is outside the v1 critical path; migrated rows point to <code>features/&lt;feature&gt;/status.md</code>, while unmigrated rows still use <code>experimental/&lt;feature&gt;/STATUS.md</code>.</dd>
</div>

</div>

**No calendar dates.** Stigmem is phase-gated, not time-gated. Phase
progression is documented in
[ROADMAP.md](https://github.com/eidetic-labs/stigmem/blob/main/ROADMAP.md).

<div className="stigmem-keypoint">

**Why pick Stigmem over a vector-RAG product?**

Stigmem retrieves <em>typed atomic facts</em>, not opaque chunks.
Each embedding has an explicit <code>(entity, relation, value)</code>
contract. Recall in v0.9.0a1 covers basic typed-fact retrieval;
advanced recall (graph BFS, vector embeddings, MMR packing, memory
cards) is deferred per ADR-002 and ships incrementally as plugins.
Read the spec at
[<code>spec/stigmem-spec-v0.9.0a1.md</code>](https://github.com/eidetic-labs/stigmem/blob/main/spec/stigmem-spec-v0.9.0a1.md).

</div>

## Core memory model (v0.9.0a1 critical path)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec</dd>
</div>

<div>
<dt>Immutable typed facts (entity, relation, value, source, timestamp, confidence, scope)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-01-Fact-Model, Spec-15-Fact-Semantics</dd>
</div>

<div>
<dt>Scope enforcement (<code>local</code> / <code>team</code> / <code>company</code> / <code>public</code>)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-02-Scopes-and-ACL</dd>
</div>

<div>
<dt>Confidence (<code>valid_until</code>, retraction)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-15-Fact-Semantics</dd>
</div>

<div>
<dt>Conflict surfacing & resolution</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-15-Fact-Semantics</dd>
</div>

<div>
<dt>Entity naming rules</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-01-Fact-Model</dd>
</div>

<div>
<dt>Lint semantics</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-20-Lint-Semantics</dd>
</div>

<div>
<dt>Content-addressed fact IDs (CIDs)</dt>
<dt><span className="stigmem-fields__type">Stable in core (ADR-011)</span></dt>
<dd>Spec-21-Content-Addressed-IDs</dd>
</div>

</div>

## Recall (v0.9.0a1 critical path)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec</dd>
</div>

<div>
<dt><code>POST /v1/recall</code> basic typed-fact retrieval</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-07-Recall-Pipeline</dd>
</div>

<div>
<dt><code>query_facts</code> operation</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-03-HTTP-API</dd>
</div>

<div>
<dt><code>assert_fact</code> operation</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-03-HTTP-API</dd>
</div>

</div>

## Federation (v0.9.0a1 critical path)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec</dd>
</div>

<div>
<dt>Two-node mTLS federation (TLS 1.3 floor, SAN ↔ entity_uri binding)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-10-Hardening mTLS transport</dd>
</div>

<div>
<dt>Ed25519 signed manifests at <code>/.well-known/stigmem-manifest.json</code></dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-04-Manifests</dd>
</div>

<div>
<dt>Capability tokens (≤90d, Ed25519, verb+object validated at admission)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-06-Capability-Tokens</dd>
</div>

<div>
<dt>Bounded HLC skew + per-peer drift tracking</dt>
<dt><span className="stigmem-fields__type">Implemented on main for v0.9.0a2 (R-19)</span></dt>
<dd>Spec-11-Replay-Protection</dd>
</div>

<div>
<dt>Quarantine garden (federation inbound writes)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-08-Quarantine-Garden</dd>
</div>

<div>
<dt>Pull replication</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-05-Federation-Trust</dd>
</div>

</div>

## Authentication & authorization (v0.9.0a1 critical path)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec</dd>
</div>

<div>
<dt>API-key authentication (per-scope)</dt>
<dt><span className="stigmem-fields__type">Stable (Argon2id for new; SHA-256 rows rehash per <a href="../../../docs/adr/archive/007-argon2id.md">ADR-007</a>)</span></dt>
<dd>Spec-02-Scopes-and-ACL</dd>
</div>

<div>
<dt>Enforced API key max-age (default 90d)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-10-Hardening key rotation</dd>
</div>

<div>
<dt>Per-principal token-bucket rate limits (7 dimensions)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-10-Hardening rate limits</dd>
</div>

<div>
<dt>Capability-based instruction handling (<code>interpret_as</code>)</dt>
<dt><span className="stigmem-fields__type">Implemented on <code>main</code>; future cert/validation pending (ADR-003)</span></dt>
<dd>Spec-15-Fact-Semantics</dd>
</div>

</div>

## Observability (v0.9.0a1 critical path)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec</dd>
</div>

<div>
<dt>WAL-ordered audit log (14 event types, 90-day retention)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-09-Audit-Log</dd>
</div>

<div>
<dt>Prometheus metrics (node health, request rates, quotas, federation peer status)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-09-Audit-Log</dd>
</div>

</div>

## Storage, embedding, SDKs, adapters, operations \{#operations-v090a1-critical-path\}

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>SQLite backend</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Default storage; backend-family record: <a href="https://github.com/eidetic-labs/stigmem/tree/main/features/storage-backends"><code>features/storage-backends</code></a>.</dd>
</div>

<div>
<dt>libSQL/Turso storage</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd>Adapter-specific feature record: <a href="https://github.com/eidetic-labs/stigmem/tree/main/features/storage-libsql"><code>features/storage-libsql</code></a>.</dd>
</div>

<div>
<dt>SQLCipher at-rest encryption</dt>
<dt><span className="stigmem-fields__type">Stable (opt-in)</span></dt>
<dd>Required for regulated data.</dd>
</div>

<div>
<dt>Local <code>nomic-embed-text-v1.5</code> embeddings</dt>
<dt><span className="stigmem-fields__type">Stable (default, offline)</span></dt>
<dd>Cloud embedding opt-in only.</dd>
</div>

<div>
<dt>Python SDK (<code>stigmem-py</code>)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Sole fully-supported SDK in v0.9.0a1 per ADR-002.</dd>
</div>

<div>
<dt>TypeScript SDK (<code>@eidetic-labs/stigmem-ts</code>)</dt>
<dt><span className="stigmem-fields__type">Preview</span></dt>
<dd>Pin to specific versions.</dd>
</div>

<div>
<dt>Go SDK (<code>stigmem-go</code>)</dt>
<dt><span className="stigmem-fields__type">Experimental, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/sdk-go"><code>features/sdk-go</code></a>; package alignment remains future alpha work.</dd>
</div>

<div>
<dt>OpenClaw adapter (<code>stigmem-openclaw</code>)</dt>
<dt><span className="stigmem-fields__type">Alpha (evaluation only)</span></dt>
<dd>Published in v0.9.0a1; copy/framing corrections for v0.9.0a2; safety hardening/audit closure pending the v0.9.0aN/beta hardening path.</dd>
</div>

<div>
<dt>MCP adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/mcp-adapter"><code>features/mcp-adapter</code></a>; <code>@eidetic-labs/stigmem-mcp</code> is independently versioned and installs the <code>stigmem-mcp</code> binary.</dd>
</div>

<div>
<dt>OpenAI tools adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/openai-tools-adapter"><code>features/openai-tools-adapter</code></a>; packaged as <code>stigmem-plugin-openai-tools-adapter</code> for v0.9.0a10; live LiteLLM, OpenAI SDK, and Ollama validation remains operator-owned for v0.1.0.</dd>
</div>

<div>
<dt>Paperclip adapter</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/paperclip-adapter"><code>features/paperclip-adapter</code></a>; live Paperclip validation remains future alpha work.</dd>
</div>

<div>
<dt>Ollama/LiteLLM adapter</dt>
<dt><span className="stigmem-fields__type">Superseded, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/ollama-litellm-adapter"><code>features/ollama-litellm-adapter</code></a>; compatibility identity for the OpenAI-compatible tools adapter.</dd>
</div>

<div>
<dt>Gemini adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/gemini-adapter"><code>features/gemini-adapter</code></a>; packaged as <code>stigmem-plugin-gemini-adapter</code> for v0.9.0a10; live Gemini validation remains operator-owned for v0.1.0.</dd>
</div>

<div>
<dt>Zep adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/zep-adapter"><code>features/zep-adapter</code></a>; packaged as <code>stigmem-plugin-zep-adapter</code> for v0.9.0a10; live Zep validation remains operator-owned for v0.1.0.</dd>
</div>

<div>
<dt>Letta adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/letta-adapter"><code>features/letta-adapter</code></a>; packaged as <code>stigmem-plugin-letta-adapter</code> for v0.9.0a10; live Letta validation remains operator-owned for v0.1.0.</dd>
</div>

<div>
<dt>Cognee adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/cognee-adapter"><code>features/cognee-adapter</code></a>; packaged as <code>stigmem-plugin-cognee-adapter</code> for v0.9.0a10; live Cognee validation remains operator-owned for v0.1.0.</dd>
</div>

<div>
<dt>Obsidian adapter</dt>
<dt><span className="stigmem-fields__type">Experimental, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/obsidian-adapter"><code>features/obsidian-adapter</code></a>; CLI, plugin, and live-vault validation remain future alpha work.</dd>
</div>

<div>
<dt>Docker Compose reference deployment</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd><code>make demo</code>, <code>make demo-attack</code>.</dd>
</div>

<div>
<dt>Container hardening (distroless, non-root UID, read-only fs, seccomp)</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd>Spec-10-Hardening container baseline.</dd>
</div>

<div>
<dt>Helm / Kubernetes</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-helm"><code>features/deploy-helm</code></a>; live cluster validation remains future alpha work.</dd>
</div>

<div>
<dt>Fly.io</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-fly"><code>features/deploy-fly</code></a>; live deployment, persistence, dashboard validation, and secrets review remain future alpha work.</dd>
</div>

<div>
<dt>Grafana</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-grafana"><code>features/deploy-grafana</code></a>; live stack validation, metric review, alert review, and packaging remain future alpha work.</dd>
</div>

<div>
<dt>PaaS</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-paas"><code>features/deploy-paas</code></a>; live platform validation, persistence, secrets, and scaling review remain future alpha work.</dd>
</div>

<div>
<dt>systemd</dt>
<dt><span className="stigmem-fields__type">Deferred, external</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-systemd"><code>features/deploy-systemd</code></a>; live distro validation, installer review, hardening review, and upgrade/rollback remain future alpha work.</dd>
</div>

</div>

## Plugin infrastructure (alpha-series foundation)

<div className="stigmem-fields">

<div>
<dt>Capability</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Stable 22-hook registry surface</dt>
<dt><span className="stigmem-fields__type">Landed on main</span></dt>
<dd>Queued for the next alpha artifact refresh.</dd>
</div>

<div>
<dt>Typed hook semantics</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Voting, filter-chain, score-delta, fire-and-forget.</dd>
</div>

<div>
<dt>Manual/core handler registration</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Deterministic ordering with minimum manifest/context/capability APIs.</dd>
</div>

<div>
<dt>Hook-site wiring</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Across assertion, recall, federation, auth, migration, and audit paths.</dd>
</div>

<div>
<dt>Registry observability and tests</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Audit/metrics plumbing, test registry helpers, hook-firing benchmark gate.</dd>
</div>

<div>
<dt>Entry-point discovery, lifecycle, health polling, operator CLI</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Startup registration with dependency ordering, lifecycle health reporting, <code>stigmem plugins</code> inspection.</dd>
</div>

<div>
<dt>Production signing/trust + author/operator plugin docs</dt>
<dt><span className="stigmem-fields__type">Landed</span></dt>
<dd>Fail-closed production signing gate, trusted-publisher policy, operator override metadata, author/operator references, alpha tester migration guidance.</dd>
</div>

</div>

## Experimental & deferred features

The following features are **not in v0.9.0a1's default install**. Migrated
feature records own the product truth under
[`features/<feature>/`](https://github.com/eidetic-labs/stigmem/tree/main/features).
Implementation code may still live under `experimental/<feature>/`. Unmigrated
future-alpha adapters, SDKs, deployments, dashboards, and tooling still carry
`experimental/<surface>/STATUS.md` tracking.

<div className="stigmem-keypoint">

**Alpha extraction is NOT ADR-008 graduation.**

Across the v0.9.0a2..a8 alpha series, cross-cutting features are
extracted into opt-in experimental plugin packages per ADR-011.
Graduation into the supported surface happens later, after the
ADR-008 five-gate process.

</div>

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec or tracker</dd>
</div>

<div>
<dt>Lazy instruction discovery</dt>
<dt><span className="stigmem-fields__type">opt-in plugin source on main; graduation blocked on ADR-003</span></dt>
<dd>Spec-X1-Lazy-Instruction-Discovery</dd>
</div>

<div>
<dt>RTBF tombstones</dt>
<dt><span className="stigmem-fields__type">opt-in plugin source on main; default routes/filters inactive</span></dt>
<dd>Spec-X2-RTBF-Tombstones</dd>
</div>

<div>
<dt>Time-travel <code>as_of</code> queries</dt>
<dt><span className="stigmem-fields__type">opt-in plugin source on main; explicit operator gates; default fails closed on <code>as_of</code></span></dt>
<dd>Spec-X3-Time-Travel-Queries</dd>
</div>

<div>
<dt>Memory Garden advanced ACL</dt>
<dt><span className="stigmem-fields__type">opt-in plugin source on main; default ACL inactive</span></dt>
<dd>Spec-X5-Memory-Garden-Advanced-ACL</dd>
</div>

<div>
<dt>Source attestation</dt>
<dt><span className="stigmem-fields__type">opt-in plugin source on main; default inert</span></dt>
<dd>Spec-X6-Source-Attestation</dd>
</div>

<div>
<dt>Subscriptions</dt>
<dt><span className="stigmem-fields__type">Experimental, dormant</span></dt>
<dd>Spec-X7-Subscriptions</dd>
</div>

<div>
<dt>Intent envelope</dt>
<dt><span className="stigmem-fields__type">Deferred indefinitely</span></dt>
<dd>Spec-X8-Intent-Envelope</dd>
</div>

<div>
<dt>Decay semantics</dt>
<dt><span className="stigmem-fields__type">Experimental, dormant</span></dt>
<dd>Spec-X9-Decay-Semantics</dd>
</div>

<div>
<dt>Synthesis</dt>
<dt><span className="stigmem-fields__type">Experimental, dormant</span></dt>
<dd>Spec-X10-Synthesis</dd>
</div>

<div>
<dt>Recall graph, vector embeddings, MMR, memory cards</dt>
<dt><span className="stigmem-fields__type">Experimental, dormant</span></dt>
<dd>Spec-X11-Recall-Graph</dd>
</div>

<div>
<dt>Multi-tenant isolation</dt>
<dt><span className="stigmem-fields__type">Experimental, no Spec-X assigned</span></dt>
<dd><code>features/multi-tenant/</code></dd>
</div>

<div>
<dt>OIDC SSO, async jobs, fuzzy resolver, billing hooks</dt>
<dt><span className="stigmem-fields__type">Experimental, no Spec-X assigned</span></dt>
<dd><code>experimental/&lt;feature&gt;/STATUS.md</code></dd>
</div>

<div>
<dt>Dashboard</dt>
<dt><span className="stigmem-fields__type">Experimental internal tooling, no Spec-X assigned</span></dt>
<dd><code>features/dashboard/</code></dd>
</div>

<div>
<dt>Evaluation harness</dt>
<dt><span className="stigmem-fields__type">Experimental internal tooling, no Spec-X assigned</span></dt>
<dd><code>features/eval-harness/</code></dd>
</div>

<div>
<dt>Adapters, SDKs, deployment recipes</dt>
<dt><span className="stigmem-fields__type">Experimental, no Spec-X assigned</span></dt>
<dd><code>experimental/&lt;surface&gt;/STATUS.md</code></dd>
</div>

</div>

See the full deferred-features list and source locations at
[Experimental Features](../reference/experimental-features).

## v0.9.0a1 architecture in flight (Option A acknowledgment)

The v0.9.0a1 default install ships with feature-specific code in
`node/src/stigmem_node/` for several deferred features
(`tombstones.py`, `instruction_migrate.py`, `card_materializer.py`,
`source_trust.py`, etc.). The routes are mounted but the features
are dormant unless explicitly configured. Per ADR-001 iteration
semantics, each v0.9.0aN extracts one cross-cutting feature into a
plugin per ADR-011's C1 plugin architecture; after v0.9.0a8, default
install will be true to ADR-011's commitment.

Main now includes the hook-registry foundation and stable 22-hook
surface, with manual/core handler registration, minimum
manifest/context/capability APIs, hook-site wiring, registry
observability, test helpers, benchmark coverage, entry-point package
discovery, startup registration, operator inspection commands, and
production signing/trust gates. Lazy instruction discovery,
time-travel queries, RTBF tombstones, advanced Memory Garden ACLs,
source attestation, and multi-tenant isolation have been extracted
as opt-in experimental plugin source packages; signed/package
artifact evidence remains deferred until the plugin launch train. The ADR-003 instruction-handling
core is also present on `main`: `interpret_as`, `instruction:write`,
instruction quarantine, channel-separated recall output, MCP/OpenClaw
channel framing, instruction audit events, and same-session
provenance controls. Plugin authors can start from the
[Plugin Author Guide](../guides/plugins/author-guide).

See [LIMITATIONS.md §11 — v0.9.0a1 architecture in flight](https://github.com/eidetic-labs/stigmem/blob/main/LIMITATIONS.md)
for the full architectural-gap acknowledgment.

## What's coming next \{#whats-coming-next\}

The phase progression is in
[ROADMAP.md](https://github.com/eidetic-labs/stigmem/blob/main/ROADMAP.md).

<ol className="stigmem-steps">
<li><strong>v0.9.0a2 through v0.9.0a8</strong> — incremental plugin extraction per ADR-011. Lazy instruction discovery, time-travel queries, RTBF tombstones, advanced Memory Garden ACLs, source attestation, and multi-tenant isolation are extracted on <code>main</code> as opt-in experimental source. CIDs remain core.</li>
<li><strong>Future hardened-core line</strong> — complete the remaining hardening evidence around the landed capability redesign, finish ADR-015 model-certification runner/results, federation hardening, OpenClaw audit closeout, storage immutability stack per ADR-016, 30-day external operator soak.</li>
<li><strong>Future release-candidate and GA lines</strong> — Sigstore-signed releases, reproducible builds, SBOM, 3+ external operators in production. Wire format frozen.</li>
</ol>

## Out of scope — explicit non-targets

<div className="stigmem-grid">

<div><h4>A hosted/SaaS Stigmem product</h4><p>Reference deployments only; operators run their own nodes.</p></div>
<div><h4>A competing agent runtime</h4><p>To OpenClaw / Claude Code / LangChain etc.</p></div>
<div><h4>A multi-agent orchestration layer</h4><p>Stigmem is a memory substrate — it makes existing agent frameworks more capable, not redundant.</p></div>
<div><h4>An in-house GRC / compliance product</h4><p>Stigmem provides provenance primitives; compliance application logic is out of scope.</p></div>
<div><h4>A vertical agent product</h4><p>Support agent, bookkeeping agent, etc. — until post-v1.0.0.</p></div>
<div><h4>A chatbot of any kind</h4></div>

</div>

---

*This page is regenerated each release to reflect actual ship-state.
The previous "Spec v2.0 — in flight" framing was retired during the
v0.9.0a1 reset. For the development history, see
[`spec/EVOLUTION.md`](https://github.com/eidetic-labs/stigmem/blob/main/spec/EVOLUTION.md).*
