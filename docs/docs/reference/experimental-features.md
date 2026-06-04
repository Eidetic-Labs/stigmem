---
title: Experimental Features
sidebar_label: Experimental Features
sidebar_position: 5
audience: Operator
description: "Canonical public index of Stigmem features outside the v0.9.0a1 default surface, including Spec-X protocol features, adapters, SDKs, deployment recipes, and tooling."
---

# Experimental Features

<p className="stigmem-meta"><span>4 min read</span><span>Operator · Curious user</span><span>Outside v0.9.0a1 default</span></p>

<div className="stigmem-lead">

**What this page covers**

Features that exist outside the v0.9.0a1 default surface.
Experimental does not mean "almost stable" — it means the feature
is opt-in, unsupported for production reliance, and must pass the
ADR-008 reintroduction gates before it can graduate into the
supported surface.

</div>

Start with the [feature matrix](../concepts/features.md) for the supported v0.9.0a1 surface. Use this page when you need to inspect what was deferred, where it lives, and whether it has a protocol spec.

## Status model

<div className="stigmem-fields">

<div>
<dt>Status</dt>
<dt><span className="stigmem-fields__type">Type</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>Spec-XN</code> experimental protocol</dt>
<dt><span className="stigmem-fields__type">protocol</span></dt>
<dd>Has real protocol/design substance. Migrated records own the canonical source under <code>features/&lt;feature&gt;/spec.md</code>; compatibility pointers remain under <code>experimental/&lt;feature&gt;/spec.md</code> where needed. Rendered spec pages live under the Specification section.</dd>
</div>

<div>
<dt>Experimental implementation surface</dt>
<dt><span className="stigmem-fields__type">impl</span></dt>
<dd>Has code, docs, deployment recipes, adapter code, SDK code, or operational tooling under <code>experimental/&lt;feature&gt;/</code>, but no protocol spec yet. Migrated product truth lives under <code>features/&lt;feature&gt;/</code>.</dd>
</div>

<div>
<dt>Dormant</dt>
<dt><span className="stigmem-fields__type">paused</span></dt>
<dd>Preserved for future work, but no active ADR-008 gate progress.</dd>
</div>

<div>
<dt>Blocked</dt>
<dt><span className="stigmem-fields__type">gated</span></dt>
<dd>Cannot progress until another roadmap item lands first.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Every feature should have one visible status owner.**

A `Spec-XN` assignment is reserved for protocol-bearing features;
migrated features use `features/<feature>/status.md`, while unmigrated
adapters, SDKs, dashboards, deployment recipes, and tooling continue to use
`experimental/<surface>/STATUS.md`. Do not assign fake specs unless a surface
later defines protocol behavior.

</div>

## Protocol features

These features have a `Spec-XN-*` experimental spec. They are not part of the supported default install.

<div className="stigmem-fields">

<div>
<dt>Feature · Spec</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Lazy instruction discovery · <a href="../spec/experimental/lazy-instruction-discovery.md">Spec-X1</a></dt>
<dt><span className="stigmem-fields__type">extracted · ADR-008 blocked</span></dt>
<dd>Source extracted behind plugin registration. Requires ADR-003 capability redesign before supported reintroduction; signed artifact evidence deferred until the plugin launch train.</dd>
</div>

<div>
<dt>RTBF tombstones · <a href="../spec/experimental/rtbf-tombstones.md">Spec-X2</a></dt>
<dt><span className="stigmem-fields__type">extracted · ADR-008 blocked</span></dt>
<dd>Plugin-loaded validation covers default/plugin behavior and hook ordering. Regulatory-impact graduation still needs threat-model, conformance, soak, and operator-runbook gates.</dd>
</div>

<div>
<dt>Time-travel queries · <a href="../spec/experimental/time-travel-queries.md">Spec-X3</a></dt>
<dt><span className="stigmem-fields__type">extracted · ADR-008 blocked</span></dt>
<dd>Default installs reject <code>as_of</code> fail-closed; registered plugins require explicit operator gates; a4 validation covers fact query, recall, tombstone/legal-hold safety, CID interaction, hook ordering, and plugin-required conformance.</dd>
</div>

<div>
<dt>Memory Garden advanced ACL · <a href="../spec/experimental/memory-garden-advanced-acl.md">Spec-X5</a></dt>
<dt><span className="stigmem-fields__type">extracted · ADR-008 blocked</span></dt>
<dd>Default installs keep advanced ACL inactive while preserving basic garden CRUD, membership, and direct <code>garden_id</code> guards in core.</dd>
</div>

<div>
<dt>Source attestation · <a href="../spec/experimental/source-attestation.md">Spec-X6</a></dt>
<dt><span className="stigmem-fields__type">extracted · ADR-008 blocked</span></dt>
<dd>Default installs keep source-attestation behavior inert; plugin-loaded validation covers assertion source checks, recall trust-rank contribution, and federation inbound guards without proving release provenance or locally re-attesting federated facts.</dd>
</div>

<div>
<dt>Subscriptions · <a href="../spec/experimental/subscriptions.md">Spec-X7</a></dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Push delivery waits for pull federation validation.</dd>
</div>

<div>
<dt>Intent envelope · <a href="../spec/experimental/intent-envelope.md">Spec-X8</a></dt>
<dt><span className="stigmem-fields__type">deferred indefinitely</span></dt>
<dd>Preserved design intent; no active reintroduction path.</dd>
</div>

<div>
<dt>Decay semantics · <a href="../spec/experimental/decay-semantics.md">Spec-X9</a></dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Deferred memory-hygiene feature.</dd>
</div>

<div>
<dt>Synthesis · <a href="../spec/experimental/synthesis.md">Spec-X10</a></dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Deferred snapshot/commercial-path feature.</dd>
</div>

<div>
<dt>Recall graph · <a href="../spec/experimental/recall-graph.md">Spec-X11</a></dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Advanced recall, graph traversal, embeddings, MMR packing, and memory cards.</dd>
</div>

</div>

## Cross-cutting features without Spec-X

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Multi-tenant isolation</dt>
<dt><span className="stigmem-fields__type">source-available</span></dt>
<dd>Adds an opt-in tenant boundary above scopes through <code>stigmem-plugin-multi-tenant</code>. Default installs collapse to <code>default</code>; v0.9.0a9 does not claim shared-node readiness or tenant-aware non-default federation. Feature record: <a href="https://github.com/eidetic-labs/stigmem/tree/main/features/multi-tenant"><code>features/multi-tenant</code></a>; no Spec-X yet.</dd>
</div>

<div>
<dt>Async jobs</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Deferred async execution surface for long-running jobs.</dd>
</div>

<div>
<dt>Fuzzy resolver</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Convenience resolver, not critical-path protocol behavior.</dd>
</div>

<div>
<dt>OIDC SSO</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Adds an external identity-provider trust boundary.</dd>
</div>

<div>
<dt>Billing hooks</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Commercial/operational concern; not part of the OSS default surface.</dd>
</div>

</div>

## Storage and embedding surfaces

<div className="stigmem-fields">

<div>
<dt>Surface</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Storage backend family</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><code>features/storage-backends/</code>; non-default backends remain outside the stable default surface.</dd>
</div>

<div>
<dt>libSQL/Turso storage</dt>
<dt><span className="stigmem-fields__type">Experimental, opt-in</span></dt>
<dd><code>features/storage-libsql/</code>; adds third-party service trust and backend-specific behavior.</dd>
</div>

<div>
<dt>Cloud embedding providers</dt>
<dt><span className="stigmem-fields__type">accepted risk</span></dt>
<dd>R-20 accepted with operator warnings; local embeddings remain the supported default.</dd>
</div>

</div>

## Adapters and SDKs

<div className="stigmem-grid">

<div><h4>MCP adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/mcp-adapter"><code>features/mcp-adapter</code></a> — experimental external adapter; package metadata is aligned, but publication remains held pending live connector smoke and security certification.</p></div>
<div><h4>Go SDK</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/sdk-go"><code>features/sdk-go</code></a> — experimental external SDK; package alignment and live-node validation remain future alpha work.</p></div>
<div><h4>Obsidian adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/obsidian-adapter"><code>features/obsidian-adapter</code></a> — experimental external adapter; package, plugin, and live-vault validation remain future alpha work.</p></div>
<div><h4>Cognee adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/cognee-adapter"><code>features/cognee-adapter</code></a> — experimental opt-in plugin packaged as <code>stigmem-plugin-cognee-adapter</code>; live Cognee runtime validation remains operator-owned for v0.1.0.</p></div>
<div><h4>Letta adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/letta-adapter"><code>features/letta-adapter</code></a> — experimental opt-in adapter packaged for v0.9.0a10; live Letta validation remains operator-owned for v0.1.0.</p></div>
<div><h4>Zep adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/zep-adapter"><code>features/zep-adapter</code></a> — experimental opt-in adapter packaged for v0.9.0a10; live Zep validation remains operator-owned for v0.1.0.</p></div>
<div><h4>Gemini adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/gemini-adapter"><code>features/gemini-adapter</code></a> — experimental opt-in adapter packaged for v0.9.0a10; live Gemini validation remains operator-owned for v0.1.0.</p></div>
<div><h4>Ollama-LiteLLM adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/ollama-litellm-adapter"><code>features/ollama-litellm-adapter</code></a> — superseded compatibility identity; behavior lives with the OpenAI-compatible tools adapter.</p></div>
<div><h4>OpenAI tools adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/openai-tools-adapter"><code>features/openai-tools-adapter</code></a> — experimental opt-in adapter packaged for v0.9.0a10; live LiteLLM, OpenAI SDK, and Ollama validation remains operator-owned for v0.1.0.</p></div>
<div><h4>Paperclip adapter</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/paperclip-adapter"><code>features/paperclip-adapter</code></a> — deferred lifecycle/event adapter; live Paperclip validation remains future alpha work.</p></div>

</div>

## Deployment, UI, and evaluation

<div className="stigmem-grid">

<div><h4>Curator dashboard</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/dashboard"><code>features/dashboard</code></a> — deferred internal tooling; live-node and deployment validation remain future alpha work.</p></div>
<div><h4>Eval harness</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/eval-harness"><code>features/eval-harness</code></a> — active internal evaluation tooling for adversarial and recall validation; standalone package publication remains future alpha work.</p></div>
<div><h4>Helm deployment</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-helm"><code>features/deploy-helm</code></a> — deferred Kubernetes deployment recipe; live cluster validation remains future alpha work.</p></div>
<div><h4>Fly.io deployment</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-fly"><code>features/deploy-fly</code></a> — deferred Fly.io deployment recipe; live deployment, persistence, dashboard validation, and secrets review remain future alpha work.</p></div>
<div><h4>Grafana deployment</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-grafana"><code>features/deploy-grafana</code></a> — deferred observability deployment seed; live stack validation, metric review, alert review, and packaging remain future alpha work.</p></div>
<div><h4>PaaS deployment</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-paas"><code>features/deploy-paas</code></a> — deferred managed-platform deployment recipes; live platform validation, persistence, secrets, and scaling review remain future alpha work.</p></div>
<div><h4>systemd deployment</h4><p><a href="https://github.com/eidetic-labs/stigmem/tree/main/features/deploy-systemd"><code>features/deploy-systemd</code></a> — deferred bare-metal deployment recipe; live distro validation, installer review, hardening review, and upgrade/rollback remain future alpha work.</p></div>

</div>

## Promotion path

<div className="stigmem-keypoint">

**ADR-008 defines the five gates for any experimental feature.**

</div>

<ol className="stigmem-steps">
<li>Threat-model delta.</li>
<li>Accepted ADR or amendment.</li>
<li>Positive, negative, and adversarial conformance vectors wired into CI.</li>
<li>External operator soak with public bug reporting.</li>
<li>Documentation parity across Learn, Build, Operate, and Secure.</li>
</ol>

Gate progress lives in each feature's `STATUS.md`. Public pages summarize status; they do not promote a feature by themselves.
