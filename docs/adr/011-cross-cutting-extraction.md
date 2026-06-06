# ADR-011: Plugin architecture for cross-cutting features (C1)

<p className="stigmem-meta"><span>12 min read</span><span>Accepted</span><span>Recorded 2026-05-07</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Stigmem adopts a plugin architecture (Option C1) for all cross-cutting
features. Core has no awareness of specific features; all integration
happens via a generic hook/registry system with capability-restricted
contexts, signed entry points, and fail-closed semantics. Default
install matches the v1.0 scope contract exactly.

</div>

<div className="stigmem-keypoint">

**Six cross-cutting plugins + CIDs-as-core.**

Folds in ADR-017 (de-contrition consolidation, 2026-06-06): content-
addressed fact IDs (CIDs, §25) are **core, not a plugin** — default
install computes CIDs on every fact write and verifies on every read,
because CIDs are load-bearing for ADR-003's trust boundary and
ADR-016's immutability stack (L3). The CID code lives in
`node/src/stigmem_node/cid.py` (core); CID hooks (`pre_assert_transform`
for generation, `federation_inbound_validate` for verification)
register from node startup, not via plugin discovery. **Operators
cannot disable CIDs — there is no `STIGMEM_CIDS_ENABLED=false`; the CID
is part of fact identity.** The remaining six cross-cutting features
(lazy instruction discovery, time-travel, RTBF tombstones,
memory-garden advanced ACL, source attestation, multi-tenant) stay
plugins per the C1 architecture below, which is otherwise unchanged.
The original [ADR-017](./archive/017-amendment-to-adr-011-cids-as-core)
text is retained in `docs/adr/archive/` for history.

</div>

**Status:** Accepted · **Date:** 2026-05-07 · **Authors:** Eidetic Labs · **Supersedes:** ADR-011 (revised 2026-05-06, direct-to-C2) · **Related:** [ADR-002](./002-v1-scope), [ADR-008](./008-experimental-gates) (version exposure + deprecation, folds ADR-012/ADR-013), [ADR-020](./020-feature-owned-product-structure) (repo structure + modular specs, folds ADR-009/ADR-010); `stigmem/analyses/feature-extraction-analysis.md`

## Context

ADR-020 §13 (repo structure) establishes `experimental/<feature>/` as the home for deferred
features. ADR-002 names which features are deferred. The implicit
assumption — that moving a feature to `experimental/` is a `git mv` —
holds for ~75% of features but fails for the cross-cutting ones
(tombstones, time-travel, CIDs, multi-tenant, lazy instruction
discovery, memory-garden advanced ACL, source attestation), which are
woven into the core node module with dozens of references in single
files.

The choice was between three approaches, in increasing order of
architectural cleanliness and upfront cost:

<div className="stigmem-fields">

<div>
<dt>Option</dt>
<dt><span className="stigmem-fields__type">Pattern</span></dt>
<dd>Trade-off</dd>
</div>

<div>
<dt>C3</dt>
<dt><span className="stigmem-fields__type">feature flags only</span></dt>
<dd>Implementation stays in core, gated by feature flags. Scope contract leak; security surface includes all deferred features regardless of whether enabled.</dd>
</div>

<div>
<dt>C2</dt>
<dt><span className="stigmem-fields__type">thin shims</span></dt>
<dd>Implementation lives in <code>experimental/&lt;feature&gt;/</code>; core has named integration points that no-op when the experimental package isn't installed. Cleaner code surface; integration points are feature-specific.</dd>
</div>

<div>
<dt>C1</dt>
<dt><span className="stigmem-fields__type">plugin architecture</span></dt>
<dd>Core has no awareness of specific features; all integration happens via a generic hook/registry system. Plugins register themselves and provide implementations. Cleanest architecture; substantial upfront design work.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Two prior versions proposed C3-then-C2 and direct-to-C2. Both superseded.**

If C1 is the long-term architectural destination, doing C2 first means
refactoring twice. The "do it once" principle that argued against
C3-then-C2 also argues against C2-then-C1. Stigmem commits to C1 from
Phase A.

</div>

## Decision

We adopt **Option C1: a plugin architecture** for all cross-cutting
features. The architecture is committed in this ADR with the design
specifics below. All seven cross-cutting features are implemented as
plugins in `experimental/<feature>/` before v0.9.0-preview ships. Core
has no feature-specific code; cross-cutting concerns are expressed
exclusively through hook firing.

### Architectural goals

<div className="stigmem-grid">

<div><h4>Security</h4><p>Default install ships only what v1.0 critical-path scope commits to. Plugins are registered via signed entry points, run in capability-restricted contexts, fail closed on errors, and are auditable from registration through every hook firing.</p></div>
<div><h4>Scalability</h4><p>Hook firing is O(1) per registered plugin per call. The registry is read-mostly after startup. Plugins declare async-safety in their manifest. The system supports thousands of registered plugins without coordination overhead at runtime.</p></div>

</div>

These two properties are non-negotiable. Specific design choices below
derive from them.

### The hook surface

Stigmem core fires named hooks at well-defined points in the protocol's
request lifecycle. Plugins register handlers for hooks they care
about. Core has no compile-time or import-time knowledge of any
specific feature.

#### Fact assertion lifecycle

<div className="stigmem-fields">

<div>
<dt>Hook</dt>
<dt><span className="stigmem-fields__type">Band · Return semantics</span></dt>
<dd>When</dd>
</div>

<div>
<dt><code>pre_assert_authorize</code></dt>
<dt><span className="stigmem-fields__type">AUTHZ · voting (first deny wins)</span></dt>
<dd>Before fact validation; capability and scope check.</dd>
</div>

<div>
<dt><code>pre_assert_validate</code></dt>
<dt><span className="stigmem-fields__type">VALIDATE · voting (first reject wins, with reason)</span></dt>
<dd>After authorize; structural validation.</dd>
</div>

<div>
<dt><code>pre_assert_transform</code></dt>
<dt><span className="stigmem-fields__type">TRANSFORM · filter chain (fact in, fact out)</span></dt>
<dd>After validate; enrichment (CID generation, derive_from, etc.).</dd>
</div>

<div>
<dt><code>post_assert_persist</code></dt>
<dt><span className="stigmem-fields__type">PERSIST · fire-and-forget</span></dt>
<dd>After successful storage.</dd>
</div>

<div>
<dt><code>post_assert_propagate</code></dt>
<dt><span className="stigmem-fields__type">PERSIST · fire-and-forget</span></dt>
<dd>After persist; federation queue.</dd>
</div>

<div>
<dt><code>post_assert_audit</code></dt>
<dt><span className="stigmem-fields__type">AUDIT · fire-and-forget</span></dt>
<dd>Always last after assert.</dd>
</div>

</div>

#### Recall lifecycle

<div className="stigmem-fields">

<div>
<dt>Hook</dt>
<dt><span className="stigmem-fields__type">Band · Return semantics</span></dt>
<dd>When</dd>
</div>

<div>
<dt><code>pre_recall_authorize</code></dt>
<dt><span className="stigmem-fields__type">AUTHZ · voting</span></dt>
<dd>Before query parse; capability + tenant + scope.</dd>
</div>

<div>
<dt><code>pre_recall_rewrite</code></dt>
<dt><span className="stigmem-fields__type">TRANSFORM · filter chain (query in, query out)</span></dt>
<dd>After authorize; query transformation (as_of for time-travel, garden filter scope).</dd>
</div>

<div>
<dt><code>recall_filter</code></dt>
<dt><span className="stigmem-fields__type">FILTER · filter chain (results in, results out)</span></dt>
<dd>After search results returned; filter (tombstone removal, source-trust threshold, scope).</dd>
</div>

<div>
<dt><code>recall_rank</code></dt>
<dt><span className="stigmem-fields__type">RANK · score-delta accumulation</span></dt>
<dd>After filter; ranking signal adjustment (source-trust, recency, derived-from boost).</dd>
</div>

<div>
<dt><code>post_recall_audit</code></dt>
<dt><span className="stigmem-fields__type">AUDIT · fire-and-forget</span></dt>
<dd>Always last.</dd>
</div>

</div>

#### Federation lifecycle

<div className="stigmem-fields">

<div>
<dt>Hook</dt>
<dt><span className="stigmem-fields__type">Band · Return semantics</span></dt>
<dd>When</dd>
</div>

<div>
<dt><code>federation_peer_authenticate</code></dt>
<dt><span className="stigmem-fields__type">AUTHN · voting</span></dt>
<dd>Inbound peer connection.</dd>
</div>

<div>
<dt><code>federation_inbound_validate</code></dt>
<dt><span className="stigmem-fields__type">VALIDATE · voting</span></dt>
<dd>Inbound fact (HLC bounds, signature, scope).</dd>
</div>

<div>
<dt><code>federation_inbound_filter</code></dt>
<dt><span className="stigmem-fields__type">FILTER · filter chain</span></dt>
<dd>After validate; filter what peer is allowed to send.</dd>
</div>

<div>
<dt><code>federation_outbound_filter</code></dt>
<dt><span className="stigmem-fields__type">FILTER · filter chain</span></dt>
<dd>Before send; filter what we send to peer (scope/tenant strip).</dd>
</div>

<div>
<dt><code>federation_outbound_sign</code></dt>
<dt><span className="stigmem-fields__type">TRANSFORM · filter chain</span></dt>
<dd>After filter; signature attachment.</dd>
</div>

</div>

#### Identity and auth

<div className="stigmem-fields">

<div>
<dt>Hook</dt>
<dt><span className="stigmem-fields__type">Band · Return semantics</span></dt>
<dd>When</dd>
</div>

<div>
<dt><code>identity_resolve</code></dt>
<dt><span className="stigmem-fields__type">AUTHN · filter chain (credentials in, identity out)</span></dt>
<dd>Per request; resolve identity from credentials.</dd>
</div>

<div>
<dt><code>tenant_resolve</code></dt>
<dt><span className="stigmem-fields__type">AUTHN · filter chain (identity in, TenantContext out)</span></dt>
<dd>After identity_resolve; resolve tenant context (default: <code>system</code>).</dd>
</div>

<div>
<dt><code>capability_check</code></dt>
<dt><span className="stigmem-fields__type">AUTHZ · voting</span></dt>
<dd>Per protected operation.</dd>
</div>

</div>

#### Lifecycle and maintenance

<div className="stigmem-fields">

<div>
<dt>Hook</dt>
<dt><span className="stigmem-fields__type">Band · Return semantics</span></dt>
<dd>When</dd>
</div>

<div>
<dt><code>migration_register</code></dt>
<dt><span className="stigmem-fields__type">(startup) · filter chain (collect migrations)</span></dt>
<dd>Plugin registration; declare schema migrations.</dd>
</div>

<div>
<dt><code>audit_emit</code></dt>
<dt><span className="stigmem-fields__type">AUDIT · fire-and-forget</span></dt>
<dd>Per audit event; plugins listen.</dd>
</div>

<div>
<dt><code>decay_sweep_filter</code></dt>
<dt><span className="stigmem-fields__type">FILTER · filter chain</span></dt>
<dd>Before decay sweep; exclude facts.</dd>
</div>

<div>
<dt><code>health_check</code></dt>
<dt><span className="stigmem-fields__type">OBSERVE · fire-and-forget (status reported)</span></dt>
<dd>Periodic; report plugin health.</dd>
</div>

<div>
<dt><code>config_validate</code></dt>
<dt><span className="stigmem-fields__type">(startup) · voting (registration aborts on reject)</span></dt>
<dd>Plugin registration; validate plugin config.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Total: 22 hooks.**

This is the *initial* surface; new hooks may be added via ADR-011
amendment with sign-off. Removing or changing the signature of an
existing hook is a breaking change requiring a major version bump per
ADR-008 §Deprecation policy.

</div>

### Hook composition order — bands

When multiple plugins register the same hook, they fire in order
determined by **bands** plus FIFO within band.

<div className="stigmem-fields">

<div>
<dt>Band</dt>
<dt><span className="stigmem-fields__type">Value</span></dt>
<dd>Purpose</dd>
</div>

<div>
<dt><code>AUTHN</code></dt>
<dt><span className="stigmem-fields__type">10</span></dt>
<dd>Identity resolution (must run before authz).</dd>
</div>

<div>
<dt><code>AUTHZ</code></dt>
<dt><span className="stigmem-fields__type">20</span></dt>
<dd>Authorization checks.</dd>
</div>

<div>
<dt><code>VALIDATE</code></dt>
<dt><span className="stigmem-fields__type">30</span></dt>
<dd>Input/output validation.</dd>
</div>

<div>
<dt><code>TRANSFORM</code></dt>
<dt><span className="stigmem-fields__type">40</span></dt>
<dd>Input transformation (CIDs, query rewriting).</dd>
</div>

<div>
<dt><code>FILTER</code></dt>
<dt><span className="stigmem-fields__type">50</span></dt>
<dd>Output filtering (tombstones, scope).</dd>
</div>

<div>
<dt><code>RANK</code></dt>
<dt><span className="stigmem-fields__type">60</span></dt>
<dd>Output ranking adjustments.</dd>
</div>

<div>
<dt><code>PERSIST</code></dt>
<dt><span className="stigmem-fields__type">70</span></dt>
<dd>Write-side effects.</dd>
</div>

<div>
<dt><code>AUDIT</code></dt>
<dt><span className="stigmem-fields__type">80</span></dt>
<dd>Audit emission.</dd>
</div>

<div>
<dt><code>OBSERVE</code></dt>
<dt><span className="stigmem-fields__type">90</span></dt>
<dd>Metrics and logging (must not change behavior).</dd>
</div>

</div>

Each hook is bound to one band. Plugins don't specify priority
directly; their handler's band is determined by the hook they register
for. **Within a band**, plugins fire in order of plugin name (stable
lexicographic). Plugins MUST be designed to be order-independent within
a band; relying on a specific peer plugin's behavior is a manifest
declaration of dependency (which the registry validates as a
topological constraint).

### Hook return semantics — typed protocol

Each hook category has typed semantics enforced by the registry.

<div className="stigmem-grid">

<div><h4>Voting hooks</h4><p>Each handler returns <code>Allow | Deny(reason)</code> or raises <code>RejectError(reason)</code>. Registry stops at first deny; subsequent handlers don't fire. Default: <code>Allow</code> for optional checks, <code>Deny("not implemented")</code> for required checks.</p></div>
<div><h4>Filter chain hooks</h4><p>Each handler receives the previous handler's output. Returns the transformed value. Type signature is hook-specific and enforced. Default: identity function; <code>tenant_resolve</code> defaults to <code>SystemTenant</code>.</p></div>
<div><h4>Score-delta hooks</h4><p>Each handler receives the current scored result list. Returns <code>dict[fact_id, float_delta]</code>. Registry sums all deltas and applies once. Default: empty deltas.</p></div>
<div><h4>Fire-and-forget hooks</h4><p>Each handler executes independently. No return value; exceptions are logged and don't halt the operation. <strong>Exception:</strong> in strict mode, exceptions in <code>post_assert_audit</code> and <code>audit_emit</code> are escalated — audit failures must not be silent.</p></div>

</div>

### Plugin lifecycle

#### Registration

Plugins register at process startup via Python `entry_points` — the
same mechanism pytest plugins, setuptools, and the broader Python
ecosystem use. The entry point group is `stigmem.plugins`.

```toml
[project]
name = "stigmem-plugin-tombstones"
version = "1.0.0"
requires-python = ">=3.11"
dependencies = ["stigmem-core>=1.0.0,<2.0.0"]

[project.entry-points."stigmem.plugins"]
tombstones = "stigmem_plugin_tombstones:register"
```

The `register()` function returns a `PluginManifest`:

```python
def register(context: PluginContext) -> PluginManifest:
    return PluginManifest(
        name="tombstones",
        version="1.0.0",
        requires_stigmem=">=1.0.0,<2.0.0",
        capabilities={"facts.read", "facts.write", "audit.emit"},
        async_safe=True,
        hooks={
            "post_assert_persist": handle_assert_for_tombstone_propagation,
            "recall_filter": filter_tombstoned_facts,
            "federation_inbound_validate": validate_tombstone_signature,
            "migration_register": declare_tombstone_migrations,
        },
        config_schema=TombstonesConfig,
        depends_on={"federation"},
    )
```

#### Registration validation

Core validates each plugin at registration. Failure aborts process
startup with a clear error message.

<ol className="stigmem-steps">
<li><strong>Manifest schema.</strong> Manifest is well-formed.</li>
<li><strong>Stigmem version compatibility.</strong> <code>requires_stigmem</code> is satisfied by current stigmem version.</li>
<li><strong>Hook signatures.</strong> Each registered handler matches the expected signature for its hook (return type, argument types).</li>
<li><strong>Capability declaration.</strong> Plugin's declared capabilities are in the allowlist (no escalation by registration).</li>
<li><strong>Dependency resolution.</strong> Declared <code>depends_on</code> plugins are also registered; no cycles.</li>
<li><strong>Configuration validity.</strong> <code>config_validate</code> hook fires; any plugin's <code>config_schema</code> validates against actual config.</li>
<li><strong>Signature validation (production).</strong> Plugin's distribution must be cryptographically signed by a trusted key. Sigstore signatures verified at registration. Development mode skips signing with loud startup warning.</li>
</ol>

#### Health and deregistration

<div className="stigmem-grid">

<div><h4>Health monitoring</h4><p>Plugins MAY implement <code>health_check</code>. Core polls every 60 seconds (configurable). Unhealthy plugins are logged with warning but NOT auto-disabled — operator action only. Automatic disabling can mask real problems.</p></div>
<div><h4>Deregistration</h4><p>Only at process shutdown. No hot-unloading. If an operator wants to remove a plugin, they uninstall the package and restart the process. Hot-unloading introduces consistency hazards (in-flight requests) that aren't worth the complexity for v1.0.</p></div>

</div>

### Plugin trust and security model

The plugin system follows defense-in-depth principles. The threat
model: a malicious or buggy plugin must not be able to compromise data
integrity, exfiltrate data beyond its declared capabilities, or
escalate the privileges of other plugins.

#### Capability-restricted contexts

Plugins receive a `PluginContext` at registration that contains
restricted handles to core APIs.

```python
class PluginContext:
    def get_facts_reader(self) -> FactsReader:
        """Available if 'facts.read' capability declared."""

    def get_audit_emitter(self) -> AuditEmitter:
        """Available if 'audit.emit' capability declared."""

    def get_federation_outbound(self) -> FederationOutbound:
        """Available if 'federation.write' capability declared."""
```

The well-known capability set (initial):

<div className="stigmem-grid">

<div><h4><code>facts.*</code></h4><p><code>read</code>, <code>write</code>.</p></div>
<div><h4><code>recall.*</code></h4><p><code>read</code>, <code>write</code> (separate because recall has different reader semantics).</p></div>
<div><h4><code>audit.*</code></h4><p><code>emit</code>, <code>read</code>.</p></div>
<div><h4><code>federation.*</code></h4><p><code>read</code>, <code>write</code>.</p></div>
<div><h4><code>identity</code>, <code>tenant</code></h4><p><code>identity.read</code>, <code>tenant.read</code>, <code>tenant.write</code>.</p></div>
<div><h4><code>config.read</code></h4></div>
<div><h4><code>network.outbound</code></h4><p>Most plugins do not get this; only plugins like cloud embedding adapters.</p></div>

</div>

Capability values are an enumerated allowlist. New capabilities require
ADR-011 amendment. Any attempt to access a capability not declared
raises `CapabilityError` at the API call site.

#### Defense layers

<div className="stigmem-grid">

<div><h4>Code signing (production default)</h4><p>Plugins must be cryptographically signed via Sigstore. Distribution is hashed, signature verified against transparency log entry, signing identity checked against operator's trusted-publisher list. Failure halts registration. Disable for dev with <code>STIGMEM_PLUGIN_SIGNING_REQUIRED=false</code> (logs warning at every request until removed).</p></div>
<div><h4>Audit trail</h4><p>Plugin registration is itself an audit event recording plugin name, version, dependencies, declared capabilities, signing identity, and stigmem version. Operators audit via <code>stigmem plugins describe</code>.</p></div>
<div><h4>Fail-closed</h4><p>Plugins that fail (registration error, exception in a non-fire-and-forget hook, capability violation) abort the operation they were participating in. Plugins NEVER silently no-op on error. Errors propagate as <code>PluginExecutionError</code>.</p></div>
<div><h4>No introspection</h4><p>Plugins cannot list other registered plugins, read other plugins' configuration, or modify other plugins' state. Enforced by <code>PluginContext</code> not exposing such APIs. Information leakage between plugins is structurally impossible.</p></div>
<div><h4>Async-safety declaration</h4><p>Each plugin declares <code>async_safe: bool</code>. Stigmem's runtime is async-first; non-async-safe plugins run in a thread pool with documented overhead. Forces plugin authors to make a conscious choice.</p></div>

</div>

### Plugin scalability

The architecture commits to specific scalability properties.

<div className="stigmem-grid">

<div><h4>Hook firing performance</h4><p>Registry is <code>dict[hook_name, list[HandlerEntry]]</code> populated at startup. Lookup: O(1). Fire: O(N) where N = registered handlers for that hook. For 100 plugins, N is typically 1–3 per hook. Overhead: tens of microseconds per firing.</p></div>
<div><h4>Read-mostly registry</h4><p>After startup, the registry is read-only. No locks needed for reads. Plugin registration / deregistration only at process boundaries.</p></div>
<div><h4>Backpressure</h4><p>The plugin system itself does NOT impose rate limits on hook firing. Rate limiting belongs in the protocol layer. Plugins that want to rate-limit do so via their own internal mechanisms.</p></div>
<div><h4>Concurrency model</h4><p>Async-safe plugins run inline in the event loop. Non-async-safe plugins run in <code>ThreadPoolExecutor</code> with configurable worker count (default: 4). Mixed should declare <code>async_safe=false</code>.</p></div>
<div><h4>Memory footprint</h4><p>Each registered plugin: typically 100KB–1MB. Core targets 50+ registered plugins without memory pressure. Plugins encouraged but not required to lazy-import dependencies.</p></div>

</div>

Hooks must NOT do expensive setup at fire time. Setup happens at
registration. If a plugin needs configured state, it captures a
closure at registration.

### Configuration model

Per-plugin configuration via two mechanisms (operators choose).

<div className="stigmem-fields">

<div>
<dt>Mechanism</dt>
<dt><span className="stigmem-fields__type">Format</span></dt>
<dd>Example</dd>
</div>

<div>
<dt>Environment variables</dt>
<dt><span className="stigmem-fields__type"><code>STIGMEM_PLUGIN_&lt;NAME&gt;_&lt;KEY&gt;</code></span></dt>
<dd><code>STIGMEM_PLUGIN_TOMBSTONES_RETENTION_DAYS=90</code></dd>
</div>

<div>
<dt>Declarative pyproject.toml</dt>
<dt><span className="stigmem-fields__type"><code>[tool.stigmem.plugins.&lt;name&gt;]</code></span></dt>
<dd><code>retention_days = 90</code></dd>
</div>

</div>

Both are read at startup and fed into the plugin's `config_schema` (a
Pydantic model). The plugin's `config_validate` hook fires on
registration; rejection aborts startup.

Operators discover plugin config via `stigmem plugins describe
<name>`, which reports plugin name, version, config schema with
defaults and bounds, declared capabilities, and registered hooks.

### Testing infrastructure

<div className="stigmem-grid">

<div><h4>Test plugin registry</h4><p>Tests use <code>TestPluginRegistry</code> via <code>with stigmem_plugins([TombstonesPlugin, TenantsPlugin]):</code> — registry contains exactly these plugins for the test's duration.</p></div>
<div><h4>Hook protocol tests</h4><p>Tests fire hooks against a controlled registry without going through full request paths — verifies ordering and composition.</p></div>
<div><h4>Composition tests</h4><p>Each cross-cutting feature ships its own composition tests verifying deterministic ordering, capability violations are caught, fail-closed behavior, and config validation.</p></div>
<div><h4>Conformance integration</h4><p>v1.0 conformance vectors fire against a default install (no plugins) to verify the no-plugin baseline. Each plugin ships its own conformance vectors against the registry with that plugin loaded.</p></div>

</div>

### Default behavior — no plugins registered

When no plugin is registered for a hook:

<div className="stigmem-fields">

<div>
<dt>Hook kind</dt>
<dt><span className="stigmem-fields__type">Default</span></dt>
<dd>Effect</dd>
</div>

<div>
<dt>AUTHN / AUTHZ (voting)</dt>
<dt><span className="stigmem-fields__type"><code>Allow</code> for optional, <code>Deny</code> for required</span></dt>
<dd><code>tenant_resolve</code> defaults to <code>SystemTenant</code>. <code>identity_resolve</code> defaults are based on configured auth mode.</dd>
</div>

<div>
<dt>VALIDATE</dt>
<dt><span className="stigmem-fields__type">core runs always-on</span></dt>
<dd>Plugin VALIDATE hooks are layered additions.</dd>
</div>

<div>
<dt>TRANSFORM</dt>
<dt><span className="stigmem-fields__type">identity</span></dt>
<dd>Input passes through unchanged.</dd>
</div>

<div>
<dt>FILTER</dt>
<dt><span className="stigmem-fields__type">identity</span></dt>
<dd>Full result set returned.</dd>
</div>

<div>
<dt>RANK</dt>
<dt><span className="stigmem-fields__type">zero deltas</span></dt>
<dd>Base scoring applies.</dd>
</div>

<div>
<dt>PERSIST / AUDIT</dt>
<dt><span className="stigmem-fields__type">core's built-in runs</span></dt>
<dd>Plugin hooks are layered additions.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**The architectural promise of C1: default install matches v1.0 critical-path scope exactly.**

Single-tenant, no tombstones, no time-travel, no CIDs, no source
attestation, no advanced ACL, no lazy instruction discovery — because
no plugins for those concerns are registered.

</div>

### Per-feature plugin manifests (Phase A scope)

Six cross-cutting plugins, plus CIDs as core (CIDs were originally
scoped as the seventh plugin; the folded ADR-017 decision moved them to
core — see the Status block). The manifest table below lists all seven
as originally designed; the CID row is annotated as core.

<div className="stigmem-fields">

<div>
<dt>Plugin</dt>
<dt><span className="stigmem-fields__type">Hooks · Effort</span></dt>
<dd>Replaces concept</dd>
</div>

<div>
<dt><code>stigmem-plugin-lazy-instruction-discovery</code></dt>
<dt><span className="stigmem-fields__type"><code>pre_recall_rewrite</code>, <code>recall_filter</code>, <code>migration_register</code> · 5–7 days</span></dt>
<dd>§21</dd>
</div>

<div>
<dt><code>stigmem-plugin-cids</code></dt>
<dt><span className="stigmem-fields__type"><code>pre_assert_transform</code>, <code>federation_inbound_validate</code>, <code>migration_register</code> · 4–5 days</span></dt>
<dd>§25 (NOTE: CIDs are core, not a plugin — folded from ADR-017; see Status block)</dd>
</div>

<div>
<dt><code>stigmem-plugin-time-travel</code></dt>
<dt><span className="stigmem-fields__type"><code>pre_recall_authorize</code>, <code>pre_recall_rewrite</code>, <code>migration_register</code> · 5–7 days</span></dt>
<dd>§24</dd>
</div>

<div>
<dt><code>stigmem-plugin-tombstones</code></dt>
<dt><span className="stigmem-fields__type"><code>recall_filter</code>, <code>federation_inbound_validate</code>, <code>post_assert_propagate</code>, <code>migration_register</code> · 7–10 days</span></dt>
<dd>§23</dd>
</div>

<div>
<dt><code>stigmem-plugin-memory-garden-acl</code></dt>
<dt><span className="stigmem-fields__type"><code>pre_assert_authorize</code>, <code>pre_recall_authorize</code>, <code>recall_filter</code> · 5–7 days</span></dt>
<dd>§17 advanced</dd>
</div>

<div>
<dt><code>stigmem-plugin-source-attestation</code></dt>
<dt><span className="stigmem-fields__type"><code>pre_assert_validate</code>, <code>recall_rank</code>, <code>federation_inbound_validate</code> · 5–7 days</span></dt>
<dd>§18</dd>
</div>

<div>
<dt><code>stigmem-plugin-multi-tenant</code></dt>
<dt><span className="stigmem-fields__type"><code>tenant_resolve</code>, <code>pre_assert_authorize</code>, <code>pre_recall_authorize</code>, <code>recall_filter</code>, <code>federation_outbound_filter</code>, <code>migration_register</code> · 14–21 days</span></dt>
<dd>multi-tenant (largest plugin)</dd>
</div>

</div>

Default install: no multi-tenant plugin → `tenant_resolve` returns
`SystemTenant` → core is single-tenant.

### Versioning and compatibility

<div className="stigmem-grid">

<div><h4>Stigmem-version range</h4><p>Plugins declare <code>requires_stigmem</code> SemVer range. Core checks at registration.</p></div>
<div><h4>Major bump = re-release</h4><p>Stigmem MAJOR version bumps may require plugin re-release; plugins should test against <code>&gt;=X.0.0,&lt;X+1.0.0</code>.</p></div>
<div><h4>Hook signatures are stable API</h4><p>Per ADR-008 §Deprecation policy. Changing a hook signature requires major version bump.</p></div>
<div><h4>New hooks are additive</h4><p>MINOR bumps. Plugins can be developed and shipped independently of core releases within their declared range.</p></div>

</div>

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Option C2 (thin shims)</dt>
<dt><span className="stigmem-fields__type">rejected (was the prior decision)</span></dt>
<dd>Same "do it once" argument that rejected C3-then-C2 also rejects C2-then-C1. C2's named integration points embed feature-specific concept names in core. C2's reintroduction story under ADR-008 still requires architectural changes when a feature graduates; C1's reintroduction is a label change. C1 supports new features as plugin packages without core changes.</dd>
</div>

<div>
<dt>Option C3 (feature flags only)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Scope contract leak, security surface includes everything regardless of enablement, no path to graduation that doesn't involve refactor.</dd>
</div>

<div>
<dt>Direct plugin loading (no registry)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Without a registry, plugins are discovered by import order. Hook composition order becomes implicit and fragile, capability-restricted contexts impossible (no central enforcement point), operator audit expensive.</dd>
</div>

<div>
<dt>Plugin sandboxing via subprocess isolation</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Strongest security model (a malicious plugin can't compromise core's memory) but adds significant per-call overhead and complicates hook return semantics. Reconsider for v2.0 if plugin ecosystem grows or threat model changes.</dd>
</div>

<div>
<dt>WebAssembly-based plugin model</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Genuinely interesting for the long term but the tooling, debug story, and ecosystem are still maturing for Python-first projects. Defer to a future ADR.</dd>
</div>

<div>
<dt>Hook ordering via topological dependencies only (no bands)</dt>
<dt><span className="stigmem-fields__type">considered</span></dt>
<dd>Bands + FIFO is simpler to reason about and matches real-world usage patterns (Apache, pytest). Plugins that need explicit ordering relative to a peer can declare dependencies; ordering within a band stays FIFO.</dd>
</div>

<div>
<dt>No code signing in v1.0; trust on first install</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Plugin signing is the difference between an ecosystem that's hardenable and one that isn't. Doing it right at v1.0 is much cheaper than retrofitting.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Default install matches scope contract exactly</h4><p>The architecture itself enforces the v1.0 scope boundary; there's no risk of feature creep into core.</p></div>
<div><h4>Reintroduction is a label change</h4><p>When a feature graduates from experimental per ADR-008, the plugin stays a plugin; only its trust tier changes. No core refactor needed.</p></div>
<div><h4>Security surface bounded by capabilities</h4><p>Audit answers "what can plugin X do?" via the manifest, not by reading source.</p></div>
<div><h4>External contributors write plugins</h4><p>Once the hook surface is stable, third-party plugins are first-class. No core PR needed to add a feature.</p></div>
<div><h4>Failure mode is uniform</h4><p>All plugins fail-closed via the same mechanism. Operators have one place to look when something breaks.</p></div>
<div><h4>Auditability built in</h4><p>Plugin registration is an audit event; capability declarations are explicit; signing identifies trusted publishers.</p></div>
<div><h4>Versioning is consistent</h4><p>Plugins follow SemVer with stigmem-version compatibility ranges, integrating with ADR-008's <code>Stigmem-Version</code> header model (§Version exposure) and ADR-008's deprecation policy (§Deprecation policy).</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Phase A timeline grows substantially</h4><p>Plugin infrastructure is ~2–3 weeks before any feature extracts. Per-feature work ~5–7 weeks for seven features. Total Phase A extension: ~9–12 weeks. v0.9.0-preview ships later than under C2 or C3.</p></div>
<div><h4>Architectural decisions are sticky</h4><p>Hook surface changes are breaking. The strawman in this ADR commits to a specific surface; getting it wrong is expensive.</p></div>
<div><h4>Plugin authors face higher bar</h4><p>Writing a plugin requires understanding the hook surface, capability model, signing requirements. Documentation has to compensate.</p></div>
<div><h4>Test infrastructure investment</h4><p>TestPluginRegistry, hook composition tests, conformance integration — all real engineering work that pays off later but takes time upfront.</p></div>
<div><h4>Operator complexity increases</h4><p>Operators have a new concept (plugins) to understand. CLI tools (<code>stigmem plugins list</code>, <code>describe</code>) help; docs have to make this approachable.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-PLUG-1</code> · hook surface design wrong</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>If a hook is missing or has wrong semantics, plugins can't express what they need. Mitigation: hook surface is amendable; new hooks are additive (MINOR); existing hooks can be deprecated per ADR-008 §Deprecation policy. The first six plugin implementations are the test — if all map cleanly, design is sound; if not, surface needs revision before multi-tenant lands.</dd>
</div>

<div>
<dt><code>R-PLUG-2</code> · registry overhead at runtime</dt>
<dt><span className="stigmem-fields__type">mitigated</span></dt>
<dd>Hook firing on the request hot path could become a bottleneck. Mitigation: flat dict-of-lists; no dynamic lookups; benchmark per-hook overhead in CI; budget under 10μs per firing.</dd>
</div>

<div>
<dt><code>R-PLUG-3</code> · plugin signing infrastructure delays</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Sigstore integration adds dependency on a Sigstore-compatible signing pipeline. Mitigation: dev mode allows unsigned (with loud warning); production signing can land in v0.9.x if not ready by v0.9.0-preview tag.</dd>
</div>

<div>
<dt><code>R-PLUG-4</code> · capability set drift</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>New plugins request new capabilities; the allowlist grows. Mitigation: capability additions require ADR-011 amendment.</dd>
</div>

<div>
<dt><code>R-PLUG-5</code> · security regression in a plugin compromises operator</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A bug in tombstones plugin (for example) causes data loss in operators who installed it. Mitigation: signing identifies the responsible publisher; audit log shows registration provenance; capability boundaries limit blast radius.</dd>
</div>

<div>
<dt><code>R-PLUG-6</code> · plugin evolution drives core surface churn</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Plugins demand new hooks; the surface grows. Mitigation: hook additions are additive; ADR amendment process is the gate; periodic review of hook surface bloat at major version boundaries.</dd>
</div>

</div>

### Net effect on the project

<div className="stigmem-grid">

<div><h4>v1.0 ships with a tight, auditable core</h4><p>And a coherent plugin architecture. Adopters know exactly what default install does. Operators choose their security/feature tradeoff explicitly via plugin install.</p></div>
<div><h4><code>experimental/</code> becomes a directory of plugin packages</h4><p>Each is independently versioned, releaseable, and deprecatable. ADR-008 reintroduction gates apply to plugins; graduation is about trust, not architecture.</p></div>
<div><h4>Recognizably a "serious infrastructure project" pattern</h4><p>Maps to PostgreSQL extensions, pytest plugins, Envoy filters, and similar systems that the federated infrastructure category respects.</p></div>

</div>

## Implementation plan

### Phase A — plugin infrastructure (weeks 1–3 of extraction work)

Order matters. Infrastructure first, then the seven plugins.

<ol className="stigmem-steps">
<li><strong>A.1 · Hook protocol and registry (~1 week).</strong> Implement <code>HookRegistry</code> with band-based composition. Implement typed <code>HookHandler</code> protocols (voting, filter chain, score-delta, fire-and-forget). Implement <code>PluginContext</code> and capability-restricted accessors. Implement <code>PluginManifest</code> schema and validation. Add hook firing in core at all 22 named locations. Verify: empty registry produces single-tenant, no-cross-cutting-features behavior identical to v1.0 critical-path scope. Benchmark hook firing overhead; budget enforcement in CI (&lt;10μs per hook).</li>
<li><strong>A.2 · Lifecycle, validation, signing (~1 week).</strong> Plugin discovery via <code>entry_points</code>. Manifest validation at registration; failure aborts startup. Capability allowlist enforcement. Dependency resolution (depends_on); cycle detection. Sigstore-based signing in production mode; dev-mode override with warning. Plugin registration audit events. Health-check polling and reporting. CLI: <code>stigmem plugins list</code>, <code>describe</code>.</li>
<li><strong>A.3 · Testing infrastructure (~3–5 days).</strong> <code>TestPluginRegistry</code> for test mounting. <code>pytest</code> fixture: <code>stigmem_plugins([...])</code>. Hook protocol unit tests. Composition order tests. Capability violation tests (negative). Failure-mode tests (fail-closed verification).</li>
<li><strong>A.4 · Documentation (~3–5 days).</strong> Plugin author guide in <code>docs/Build/Plugins/</code>. Hook reference in <code>docs/Reference/Plugin-API/</code>. Capability reference. Operator guide in <code>docs/Operate/Plugins/</code>. Migration guide for any operators using v1.0 features that become plugins.</li>
</ol>

### Phase A — per-feature plugin implementations (weeks 4–12)

Each plugin is its own three-PR cycle:

<ol className="stigmem-steps">
<li><strong>Pre-implementation analysis PR.</strong> Document the plugin's hook usage, capability requirements, and configuration. Validate the hook surface supports what the plugin needs; if not, file an ADR-011 amendment first.</li>
<li><strong>Implementation PR.</strong> Implement the plugin in <code>experimental/&lt;feature&gt;/</code>. Includes plugin code, tests, manifest, docs.</li>
<li><strong>Validation PR.</strong> Conformance vectors with the plugin loaded; integration tests; signed release artifact.</li>
</ol>

Per-feature ordering:

<div className="stigmem-fields">

<div>
<dt>Weeks</dt>
<dt><span className="stigmem-fields__type">Plugin</span></dt>
<dd>Why this order</dd>
</div>

<div>
<dt>4–5</dt>
<dt><span className="stigmem-fields__type">lazy-instruction-discovery</span></dt>
<dd>Priority 1; couples to ADR-003.</dd>
</div>

<div>
<dt>5–6</dt>
<dt><span className="stigmem-fields__type">cids</span></dt>
<dd>Validates the plugin pattern on a tightly-bounded module. (Per ADR-017: this work later folded back into core.)</dd>
</div>

<div>
<dt>6–7</dt>
<dt><span className="stigmem-fields__type">time-travel</span></dt>
<dd>Mid-difficulty; tests query rewriting hook semantics.</dd>
</div>

<div>
<dt>7–9</dt>
<dt><span className="stigmem-fields__type">tombstones</span></dt>
<dd>Largest non-multi-tenant; tests <code>recall_filter</code> under load.</dd>
</div>

<div>
<dt>9–10</dt>
<dt><span className="stigmem-fields__type">memory-garden-acl</span></dt>
<dd>Tests authz hooks.</dd>
</div>

<div>
<dt>10–11</dt>
<dt><span className="stigmem-fields__type">source-attestation</span></dt>
<dd>Tests rank hook.</dd>
</div>

<div>
<dt>11–12</dt>
<dt><span className="stigmem-fields__type">multi-tenant</span></dt>
<dd>Most complex; capability model gets its hardest test here.</dd>
</div>

</div>

### Phase A exit (v0.9.0-preview ships)

<div className="stigmem-grid">

<div><h4>All seven plugins shipped</h4><p>Implemented, tested, signed, released.</p></div>
<div><h4>Default install matches v1.0</h4><p>No plugins → v1.0 critical-path behavior.</p></div>
<div><h4>Conformance passes both</h4><p>Vectors pass against default install AND against the full plugin set.</p></div>
<div><h4>Plugin author docs published</h4><p>First plugin contributors can self-serve.</p></div>
<div><h4>Operator docs explain plugin management</h4><p>And trust posture.</p></div>
<div><h4>No core code references features by name</h4><p>Other than as test scaffolding.</p></div>

</div>

### Post-Phase-A — stewardship

The hook surface is reviewed at every major release for hook
deprecations (per ADR-008 §Deprecation policy), new hooks (additive; ADR-011 amendment),
and capability evolution. Phase B (capability redesign, federation
hardening, OpenClaw rewrite, operator soak) operates against the
post-extraction codebase. The plugin architecture provides the
substrate for Phase B work.

## Amendment process

This ADR commits to:

<ol className="stigmem-steps">
<li>C1 plugin architecture as the cross-cutting strategy.</li>
<li>The 22-hook surface (with bands).</li>
<li>The capability model with declared allowlist.</li>
<li>The signing/trust model (Sigstore in production, dev override with warning).</li>
<li>The plugin lifecycle (entry-point discovery, registration validation, no hot-unload).</li>
<li>The default-install-matches-scope-contract guarantee.</li>
</ol>

Changes require ADR-011 amendment with sign-off (two contributors or
the founder alone, per ADR-001 §Contributor approval rule). Common
amendment cases: adding a new hook (additive; MINOR core version
bump); adding a new capability to the allowlist; changing a hook
signature (breaking; MAJOR core version bump per ADR-008 §Deprecation policy); adding
plugin sandboxing (subprocess isolation, WASM-based, etc.) — would
supersede the registration-only trust model; promoting a plugin's
default-on status (would also amend ADR-008 reintroduction gates if
applicable).

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
