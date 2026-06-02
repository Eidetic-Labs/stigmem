---
title: Alpha Tester Migration Guide
sidebar_label: Alpha Tester Migration
description: Migration guidance for testers moving from deferred or pre-plugin Stigmem feature flows to the v0.9.0aN plugin infrastructure path.
audience: Integrator
---

# Alpha Tester Migration Guide

<p className="stigmem-meta"><span>3 min read</span><span>Alpha tester</span><span>v0.9.0a1</span></p>

<div className="stigmem-lead">

**What this guide covers**

Migration guidance for testers moving from deferred or pre-plugin
Stigmem feature flows to the v0.9.0aN plugin infrastructure path.

</div>

**Audience:** Alpha testers who used deferred Stigmem feature surfaces before the plugin infrastructure landed.

<div className="stigmem-keypoint">

**The v0.9.0a1 default install is the supported critical-path surface.**

It includes typed facts, scopes, basic recall, federation, audit,
SQLite storage, Docker Compose deployment, and CIDs as core
behavior. It does **not** include production support for deferred
features such as lazy instruction discovery, time-travel queries,
RTBF tombstones, advanced Memory Garden ACLs, source attestation,
multi-tenant isolation, or advanced recall graph features.

</div>

The plugin infrastructure now exists on `main`: stable 22-hook dispatch, package entry-point discovery, dependency ordering, lifecycle health checks, operator CLI inspection, production signing/trust policy, and author/operator documentation. Lazy instruction discovery, time-travel queries, RTBF tombstones, advanced Memory Garden ACLs, and source attestation have been extracted as opt-in experimental plugin source packages under `experimental/`.

## What changed

<div className="stigmem-fields">

<div>
<dt>Area</dt>
<dt><span className="stigmem-fields__type">Current main</span></dt>
<dd>Later v0.9.0aN work</dd>
</div>

<div>
<dt>Default node install</dt>
<dt><span className="stigmem-fields__type">unchanged · opt-in plugins</span></dt>
<dd>Default install remains critical-path only.</dd>
</div>

<div>
<dt>Plugin package loading</dt>
<dt><span className="stigmem-fields__type">entry-point discovery</span></dt>
<dd>Lazy-instruction and time-travel plugin source packages extracted for validation.</dd>
</div>

<div>
<dt>Plugin signing and trust</dt>
<dt><span className="stigmem-fields__type">verified metadata required</span></dt>
<dd>Unsigned loading is development-only. Package publication matures with releases.</dd>
</div>

<div>
<dt>Deferred feature behavior</dt>
<dt><span className="stigmem-fields__type">still gated</span></dt>
<dd>Not promoted by plugin infrastructure alone; lazy instruction and time-travel now require plugin registration/configuration.</dd>
</div>

<div>
<dt>Internal/pre-plugin test flows</dt>
<dt><span className="stigmem-fields__type">retire</span></dt>
<dd>Should be retired unless they test the supported default surface.</dd>
</div>

</div>

## Migration rules

<ol className="stigmem-steps">
<li><strong>Do not rely on dormant code paths for production behavior.</strong> If a feature is listed as experimental or dormant, treat it as unavailable in supported deployments.</li>
<li><strong>Do not assume a plugin exists because hooks exist.</strong> Hook infrastructure is available now; feature plugins are separate packages that land later.</li>
<li><strong>Keep CIDs as core.</strong> Content-addressed IDs are not moving to a plugin.</li>
<li><strong>Pin alpha artifacts.</strong> Pre-1.0 builds do not carry a stability guarantee; pin exact versions and re-test on every upgrade.</li>
<li><strong>Use public docs and specs as the migration source.</strong></li>
</ol>

## Feature destinations

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Migration destination</dd>
</div>

<div>
<dt>Lazy instruction discovery</dt>
<dt><span className="stigmem-fields__type">experimental plugin</span></dt>
<dd>Keep using ordinary typed facts and explicit recall inputs in default installs. Test the plugin only in isolated alpha environments.</dd>
</div>

<div>
<dt>Content-addressed IDs</dt>
<dt><span className="stigmem-fields__type">core</span></dt>
<dd>Continue using core CID/fact-ID behavior; no CID plugin is planned.</dd>
</div>

<div>
<dt>Time-travel <code>as_of</code></dt>
<dt><span className="stigmem-fields__type">experimental plugin</span></dt>
<dd>Default installs return <code>time_travel_plugin_not_loaded</code>. Test only in isolated alpha environments.</dd>
</div>

<div>
<dt>RTBF tombstones</dt>
<dt><span className="stigmem-fields__type">experimental plugin</span></dt>
<dd>Default installs expose access-gated tombstone route contracts but do not enable tombstone behavior. Use ordinary retractions for supported tests.</dd>
</div>

<div>
<dt>Memory Garden advanced ACL</dt>
<dt><span className="stigmem-fields__type">experimental plugin</span></dt>
<dd>Use stable scopes and basic garden behavior for default-surface tests.</dd>
</div>

<div>
<dt>Source attestation</dt>
<dt><span className="stigmem-fields__type">experimental plugin</span></dt>
<dd>Use existing API-key and audit attribution for default-surface tests.</dd>
</div>

<div>
<dt>Multi-tenant isolation</dt>
<dt><span className="stigmem-fields__type">no Spec-X yet</span></dt>
<dd>Wait for the multi-tenant plugin. Do not treat tenant isolation as part of the default install.</dd>
</div>

<div>
<dt>Subscriptions / Decay / Synthesis</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Wait for future reintroduction paths. Use polling or supported federation flows.</dd>
</div>

<div>
<dt>Intent envelope</dt>
<dt><span className="stigmem-fields__type">deferred indefinitely</span></dt>
<dd>Remove dependencies on this behavior.</dd>
</div>

<div>
<dt>Recall graph / vectors / cards</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Wait for the recall-graph reintroduction path.</dd>
</div>

<div>
<dt>Non-OpenClaw adapters</dt>
<dt><span className="stigmem-fields__type">dormant</span></dt>
<dd>Treat as unsupported until each adapter passes the reintroduction gates.</dd>
</div>

<div>
<dt>Helm/Fly/systemd/PaaS/Grafana</dt>
<dt><span className="stigmem-fields__type">experimental</span></dt>
<dd>Use Docker Compose for supported v0.9.0a1 testing.</dd>
</div>

</div>

## What to test now

Use current `main` or the next alpha artifact to test the plugin infrastructure itself:

<div className="stigmem-grid">

<div><h4>Author a minimal plugin</h4><p>Using the <a href="./author-guide.md">Plugin Author Guide</a>.</p></div>
<div><h4>Register documented hooks</h4><p>From the <a href="../../reference/plugin-api/hooks.md">Plugin Hook Reference</a>.</p></div>
<div><h4>Declare capabilities</h4><p>From the <a href="../../reference/plugin-api/capabilities.md">Plugin Capability Reference</a>.</p></div>
<div><h4>Install and inspect</h4><p>Per the <a href="../../operators/plugins/management.md">Operator Plugin Management Guide</a>.</p></div>
<div><h4>Default with no plugins</h4><p>Verify default behavior with no plugins registered.</p></div>
<div><h4>Signing policy</h4><p>Verify production signing/trust policy and development-only unsigned loading.</p></div>

</div>

<div className="stigmem-keypoint">

**Do not test a deferred feature as though it has graduated just because its future hook points now exist.**

</div>

## Retiring pre-plugin tests

<div className="stigmem-fields">

<div>
<dt>Test type</dt>
<dt><span className="stigmem-fields__type">Action</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Default-surface tests</dt>
<dt><span className="stigmem-fields__type">keep</span></dt>
<dd>Remove assumptions about deferred feature behavior.</dd>
</div>

<div>
<dt>Plugin-infrastructure tests</dt>
<dt><span className="stigmem-fields__type">rewrite</span></dt>
<dd>Rewrite them around manifest, hook, capability, signing, CLI, health, and audit behavior.</dd>
</div>

<div>
<dt>Deferred-feature behavior tests</dt>
<dt><span className="stigmem-fields__type">move or block</span></dt>
<dd>Move to the relevant feature's experimental area or mark as blocked until that feature plugin exists.</dd>
</div>

</div>

## Operator checklist

Before enabling tester plugins in a shared environment:

<ol className="stigmem-steps">
<li>Pin the plugin package version.</li>
<li>Keep <code>STIGMEM_PLUGIN_SIGNING_REQUIRED=true</code>.</li>
<li>Set <code>STIGMEM_PLUGIN_TRUSTED_PUBLISHERS</code> to reviewed signing identities.</li>
<li>Use <code>STIGMEM_PLUGIN_TRUST_OVERRIDE_PUBLISHERS</code> only for explicit, short-lived exceptions.</li>
<li>Run <code>stigmem plugins list --json</code> and <code>stigmem plugins describe &lt;name&gt; --json</code> after startup.</li>
<li>Review <code>plugin.registered</code>, <code>plugin.registration_failed</code>, <code>plugin.handler_denied</code>, and <code>plugin.handler_error</code> audit events.</li>
</ol>

## References

<div className="stigmem-grid">

<div><h4><a href="../../concepts/features.md">Features</a></h4></div>
<div><h4><a href="../../reference/experimental-features.md">Experimental Features</a></h4></div>
<div><h4><a href="https://github.com/eidetic-labs/stigmem/blob/main/ROADMAP.md">Roadmap</a></h4></div>
<div><h4><a href="./author-guide.md">Plugin Author Guide</a></h4></div>
<div><h4><a href="../../reference/plugin-api/hooks.md">Plugin Hook Reference</a></h4></div>
<div><h4><a href="../../reference/plugin-api/capabilities.md">Plugin Capability Reference</a></h4></div>
<div><h4><a href="../../operators/plugins/management.md">Operator Plugin Management</a></h4></div>

</div>
