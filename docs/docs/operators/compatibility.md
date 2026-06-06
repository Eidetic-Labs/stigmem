---
title: Compatibility
sidebar_label: Compatibility
audience: Operator
description: Cross-package compatibility matrix per ADR-020 §10 (compatibility matrix).
---

# Compatibility

<p className="stigmem-meta"><span>4 min read</span><span>Node operator</span><span>v0.9.0a10</span></p>

<div className="stigmem-lead">

**What this page covers**

The cross-package compatibility matrix per [ADR-020](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/020-feature-owned-product-structure.md) §10 (compatibility matrix).
The source-of-truth YAML is at
[`docs/compatibility-matrix.yaml`](https://github.com/eidetic-labs/stigmem/blob/main/docs/compatibility-matrix.yaml).
This page renders the YAML as human-readable tables.

</div>

> **Initial population at v0.9.0a1 baseline.** The full Docusaurus plugin that auto-renders the YAML at build time is acknowledged as a follow-up; this page is the hand-maintained equivalent for the active alpha line. Updates ship with every release.

## Package versions

<div className="stigmem-fields">

<div>
<dt>Package</dt>
<dt><span className="stigmem-fields__type">Latest</span></dt>
<dd>Distribution</dd>
</div>

<div>
<dt><code>stigmem-node</code></dt>
<dt><span className="stigmem-fields__type">0.9.0a10</span></dt>
<dd>PyPI</dd>
</div>

<div>
<dt><code>stigmem-py</code></dt>
<dt><span className="stigmem-fields__type">0.9.0a10</span></dt>
<dd>PyPI</dd>
</div>

<div>
<dt><code>stigmem</code> (meta-package)</dt>
<dt><span className="stigmem-fields__type">0.9.0a10</span></dt>
<dd>PyPI</dd>
</div>

<div>
<dt><code>stigmem-openclaw</code> (adapter)</dt>
<dt><span className="stigmem-fields__type">0.9.0a10</span></dt>
<dd>PyPI</dd>
</div>

<div>
<dt><code>@eidetic-labs/stigmem-ts</code> (SDK)</dt>
<dt><span className="stigmem-fields__type">0.9.0-alpha.10</span></dt>
<dd>npm</dd>
</div>

<div>
<dt><code>stigmem-go</code> (SDK)</dt>
<dt><span className="stigmem-fields__type">deferred</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/sdk-go"><code>features/sdk-go/</code></a>; package alignment remains future alpha work.</dd>
</div>

<div>
<dt><code>@eidetic-labs/stigmem-mcp</code> (adapter)</dt>
<dt><span className="stigmem-fields__type">0.1.0</span></dt>
<dd><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/mcp-adapter"><code>features/mcp-adapter/</code></a>; independently versioned npm package that installs the <code>stigmem-mcp</code> binary.</dd>
</div>

</div>

## Connector compatibility

<div className="stigmem-fields">

<div>
<dt>Connector</dt>
<dt><span className="stigmem-fields__type">Stigmem-side</span></dt>
<dd>Host-side</dd>
</div>

<div>
<dt>OpenClaw</dt>
<dt><span className="stigmem-fields__type">openclaw≥0.9.0a10, py≥0.9.0a10,&lt;1.0.0</span></dt>
<dd>OpenClaw runtime ≥1.2. Experimental alpha connector only.</dd>
</div>

</div>

## Feature Record Compatibility

Feature records own feature metadata. This table projects the migrated feature
records into the operator compatibility view; release-specific package
compatibility remains in [`docs/compatibility-matrix.yaml`](https://github.com/eidetic-labs/stigmem/blob/main/docs/compatibility-matrix.yaml).

| Feature | Type | Stability / surface | Release lines | Package / implementation |
| --- | --- | --- | --- | --- |
| [Async jobs](https://github.com/eidetic-labs/stigmem/blob/main/features/async-jobs/README.md) | core | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `node/src/stigmem_node/jobs.py` |
| [Content-addressed fact IDs](https://github.com/eidetic-labs/stigmem/blob/main/features/content-addressed-ids/README.md) | core | stable / default | `v0.9.0a1`, `v0.9.0a3` | `stigmem-node`; `node/src/stigmem_node/cid.py` |
| [Dashboard](https://github.com/eidetic-labs/stigmem/blob/main/features/dashboard/README.md) | tooling | experimental / internal | `v0.9.0a1`, `0.9.xA` | `dashboard`; `experimental/dashboard` |
| [Decay semantics](https://github.com/eidetic-labs/stigmem/blob/main/features/decay/README.md) | protocol | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `experimental/decay` |
| [Evaluation harness](https://github.com/eidetic-labs/stigmem/blob/main/features/eval-harness/README.md) | tooling | experimental / internal | `v0.9.0a1`, `v0.9.0a11` | `eval` |
| [Fly.io deployment](https://github.com/eidetic-labs/stigmem/blob/main/features/deploy-fly/README.md) | deployment | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem`; `experimental/deploy-fly` |
| [Fuzzy resolver](https://github.com/eidetic-labs/stigmem/blob/main/features/fuzzy-resolver/README.md) | core | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `node/src/stigmem_node/recall/entity_resolver.py` |
| [Grafana deployment](https://github.com/eidetic-labs/stigmem/blob/main/features/deploy-grafana/README.md) | deployment | experimental / external | `v0.9.0a1`, `0.9.xA` | `experimental/deploy-grafana` |
| [Helm deployment](https://github.com/eidetic-labs/stigmem/blob/main/features/deploy-helm/README.md) | deployment | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem`; `experimental/deploy-helm` |
| [PaaS deployment](https://github.com/eidetic-labs/stigmem/blob/main/features/deploy-paas/README.md) | deployment | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem`; `experimental/deploy-paas` |
| [systemd deployment](https://github.com/eidetic-labs/stigmem/blob/main/features/deploy-systemd/README.md) | deployment | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `experimental/deploy-systemd` |
| [Gemini adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/gemini-adapter/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `v0.9.0a10` | `stigmem-plugin-gemini-adapter`; `experimental/gemini-adapter` |
| [Go SDK](https://github.com/eidetic-labs/stigmem/blob/main/features/sdk-go/README.md) | sdk | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem-go`; `experimental/sdk-go` |
| [Intent envelope](https://github.com/eidetic-labs/stigmem/blob/main/features/intent-envelope/README.md) | protocol | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `experimental/intent-envelope` |
| [Lazy instruction discovery](https://github.com/eidetic-labs/stigmem/blob/main/features/lazy-instruction-discovery/README.md) | plugin | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-plugin-lazy-instruction-discovery`; `experimental/lazy-instruction-discovery` |
| [Letta adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/letta-adapter/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `v0.9.0a10` | `stigmem-plugin-letta-adapter`; `experimental/letta-adapter` |
| [Memory Garden advanced ACL](https://github.com/eidetic-labs/stigmem/blob/main/features/memory-garden-acl/README.md) | plugin | experimental / opt-in | `v0.9.0a1`, `v0.9.0a6`, `0.9.xA` | `stigmem-plugin-memory-garden-acl`; `experimental/memory-garden-acl` |
| [MCP adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/mcp-adapter/README.md) | adapter | experimental / external | `v0.9.0a1`, `0.9.xA` | `"@eidetic-labs/stigmem-mcp"`; `adapters/mcp` |
| [Multi-tenant scoping](https://github.com/eidetic-labs/stigmem/blob/main/features/multi-tenant/README.md) | plugin | experimental / opt-in | `v0.9.0a8`, `0.9.xA` | `stigmem-plugin-multi-tenant`; `experimental/multi-tenant` |
| [Obsidian adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/obsidian-adapter/README.md) | adapter | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem-obsidian`; `experimental/obsidian-adapter` |
| [Ollama/LiteLLM adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/ollama-litellm-adapter/README.md) | adapter | experimental / external | `v0.9.0a1`, `0.9.xA` | `stigmem-plugin-openai-tools-adapter`; `experimental/openai-tools-adapter` |
| [OpenAI tools adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/openai-tools-adapter/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `v0.9.0a10` | `stigmem-plugin-openai-tools-adapter`; `experimental/openai-tools-adapter` |
| [Paperclip adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/paperclip-adapter/README.md) | adapter | experimental / external | `v0.9.0a1`, `0.9.xA` | `experimental/paperclip-adapter` |
| [Cognee adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/cognee-adapter/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `v0.9.0a10` | `stigmem-plugin-cognee-adapter`; `experimental/cognee-adapter` |
| [Zep adapter](https://github.com/eidetic-labs/stigmem/blob/main/features/zep-adapter/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `v0.9.0a10` | `stigmem-plugin-zep-adapter`; `experimental/zep-adapter` |
| [OIDC SSO](https://github.com/eidetic-labs/stigmem/blob/main/features/oidc-sso/README.md) | core | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `node/src/stigmem_node/routes/auth.py` |
| [Recall graph](https://github.com/eidetic-labs/stigmem/blob/main/features/recall-graph/README.md) | protocol | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `experimental/recall-graph` |
| [Source attestation](https://github.com/eidetic-labs/stigmem/blob/main/features/source-attestation/README.md) | plugin | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-plugin-source-attestation`; `experimental/source-attestation` |
| [Storage backends](https://github.com/eidetic-labs/stigmem/blob/main/features/storage-backends/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `node/src/stigmem_node/storage` |
| [libSQL storage](https://github.com/eidetic-labs/stigmem/blob/main/features/storage-libsql/README.md) | adapter | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-node`; `node/src/stigmem_node/storage/libsql_backend.py` |
| [Subscriptions](https://github.com/eidetic-labs/stigmem/blob/main/features/subscriptions/README.md) | protocol | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `experimental/subscriptions` |
| [Synthesis](https://github.com/eidetic-labs/stigmem/blob/main/features/synthesis/README.md) | protocol | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `experimental/synthesis` |
| [Time-travel queries](https://github.com/eidetic-labs/stigmem/blob/main/features/time-travel/README.md) | plugin | experimental / opt-in | `v0.9.0a1`, `v0.9.0a4` | `stigmem-plugin-time-travel`; `experimental/time-travel` |
| [RTBF tombstones](https://github.com/eidetic-labs/stigmem/blob/main/features/tombstones/README.md) | plugin | experimental / opt-in | `v0.9.0a1`, `0.9.xA` | `stigmem-plugin-tombstones`; `experimental/tombstones` |

## Baseline Compatibility Summary

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Spec / Required versions</dd>
</div>

<div>
<dt>Immutable typed facts</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd><code>Spec-01-Fact-Model</code>, <code>Spec-15-Fact-Semantics</code>; <code>node≥0.9.0a1</code>, <code>py≥0.9.0a1</code>.</dd>
</div>

<div>
<dt>Scope enforcement</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd><code>Spec-02-Scopes-and-ACL</code>; <code>node≥0.9.0a1</code>.</dd>
</div>

<div>
<dt>Two-node mTLS federation</dt>
<dt><span className="stigmem-fields__type">Stable</span></dt>
<dd><code>Spec-10-Hardening</code>, <code>Spec-05-Federation-Trust</code>; <code>node≥0.9.0a1</code>.</dd>
</div>

<div>
<dt><code>Stigmem-Version</code> header</dt>
<dt><span className="stigmem-fields__type">Documented; future hardened-core work</span></dt>
<dd><code>Spec-03-HTTP-API</code>; implementation planned for a future hardened-core line.</dd>
</div>

<div>
<dt>Argon2id API key hashing</dt>
<dt><span className="stigmem-fields__type">Current alpha line</span></dt>
<dd>Per <a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/archive/007-argon2id.md">ADR-007</a>; new API keys use Argon2id in the current alpha implementation.</dd>
</div>

</div>

## Protocol release composition

<div className="stigmem-keypoint">

**`v0.9.0a2`** — `stigmem-node@0.9.0a2`, `stigmem-py@0.9.0a2`,
`stigmem-openclaw@0.9.0a2`, `stigmem@0.9.0a2` (PyPI) +
`@eidetic-labs/stigmem-ts@0.9.0-alpha.2` (npm).

Default install matches v1.0 critical-path scope per ADR-002
(single-tenant; no tombstones, time-travel, memory cards, source
attestation, or lazy instruction discovery in default behavior).
OpenClaw/ClawHub is available for alpha evaluation only and remains
subject to [LIMITATIONS.md §9](https://github.com/eidetic-labs/stigmem/blob/main/LIMITATIONS.md#9-running-the-openclaw-bundled-adapter-as-is).
See [LIMITATIONS.md §11](https://github.com/eidetic-labs/stigmem/blob/main/LIMITATIONS.md)
for the architectural-gap acknowledgment.

</div>

## Cross-references

<div className="stigmem-grid">

<div><h4>Source-of-truth YAML</h4><p><a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/compatibility-matrix.yaml"><code>docs/compatibility-matrix.yaml</code></a></p></div>
<div><h4>ADR-020 §10 (compatibility matrix)</h4><p><a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/archive/014-compatibility-matrix.md">Compatibility matrix</a></p></div>
<div><h4>ADR-008 §Deprecation policy</h4><p><a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/archive/013-deprecation-policy.md">Deprecation policy</a></p></div>
<div><h4>Commitment</h4><p><a href="../security/compatibility-commitment.md">Compatibility commitment</a> — written commitment scaled to v0.9.0a1.</p></div>

</div>
