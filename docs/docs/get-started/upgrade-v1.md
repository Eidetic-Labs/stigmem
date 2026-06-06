---
title: Pre-v0.9.0a1 Upgrade Notes
sidebar_label: Pre-v0.9.0a1 notes
---

# Pre-v0.9.0a1 Upgrade Notes

<p className="stigmem-meta"><span>3 min read</span><span>For operators with older checkouts</span><span>Updated 2026-05-19</span></p>

<div className="stigmem-lead">

**Who this is for**

Operators with an older local checkout, a stale dependency pin, or a
pre-reset deployment artifact who need to align with the v0.9.0a1
alpha reset. If you're installing fresh, skip this and read
[Installation](./installation) instead.

</div>

<div className="stigmem-keypoint">

**v0.9.0a1 is the first build.**

No <code>v1.0</code> or <code>v2.0</code> Stigmem release shipped
publicly. Per ADR-001 and ADR-001, treat older <code>v0.x</code>,
<code>v1.x</code>, and <code>v2.0</code> labels in local branches,
old docs, or unpublished artifacts as internal development
checkpoints.

</div>

For source checkouts, the alignment path is still a `git pull` plus
rebuild. The node applies migrations at startup; **take a database
backup first if your local data matters**.

## What changed in the alpha reset

### Multi-tenant isolation (migration `012`)

The storage schema includes `tenant_id` columns on write-bearing tables
for compatibility with the extracted multi-tenant plugin.

<div className="stigmem-grid">

<div>
<h4>Existing rows</h4>
<p>Receive <code>tenant_id = "default"</code> automatically on upgrade.</p>
</div>

<div>
<h4>Existing API keys</h4>
<p>Continue to work in the <code>"default"</code> tenant.</p>
</div>

<div>
<h4>Single-tenant deployments</h4>
<p>Require zero configuration changes.</p>
</div>

<div>
<h4>Default installs</h4>
<p>Collapse tenant resolution to <code>"default"</code> unless the opt-in multi-tenant plugin is registered.</p>
</div>

</div>

See
[Multi-Tenancy](https://github.com/eidetic-labs/stigmem/tree/main/features/multi-tenant)
for the feature record and extracted plugin source package.

### Billing hooks

A new `stigmem_node.billing` module emits a `BillingEvent` after every
fact write and garden creation. The default implementation logs
structured JSON to stderr — no configuration needed unless you want
a custom backend. See
[Billing Hooks](https://github.com/eidetic-labs/stigmem/tree/main/experimental/billing).

### Source attestation

Source attestation remains experimental in the v0.9.0aN line
(`Spec-X6-Source-Attestation`). Default installs keep
source-attestation behavior off; runtime enforcement lives behind
`stigmem-plugin-source-attestation` registration and explicit plugin
configuration. The current alpha plugin validates source claims and related
recall/federation guards, but it does not prove release artifact provenance or
mark accepted facts as locally re-attested. See
[Source Attestation](https://github.com/eidetic-labs/stigmem/tree/main/experimental/source-attestation).

### Conformance test suite

The source tree includes conformance and adversarial suites that drive
the current alpha/beta readiness gates.

<div className="stigmem-keypoint">

**Pre-GA contract.**

The public compatibility contract remains pre-GA. Pin exact versions
and do not assume wire-format stability until the roadmap reaches
<code>v1.0.0</code>.

</div>

## Upgrade procedure

### Docker Compose (recommended)

```bash
git pull
docker compose up --build -d
```

The node runs `apply_migrations()` on startup. Migration
`012_multi_tenant` is idempotent; if it has already run in an older
local checkout, it is skipped.

Verify the node is healthy and the migration applied:

```bash
curl -s http://localhost:8765/healthz
# → {"status": "ok"}

sqlite3 data/stigmem.db "SELECT version FROM schema_migrations ORDER BY version;"
# Should include: 012_multi_tenant
```

### Without Docker (development install)

```bash
git pull
uv sync          # or: pip install -e .
python -m stigmem_node
```

### Persistent service (macOS LaunchAgent)

```bash
git pull
uv sync
launchctl kickstart -k gui/$(id -u)/com.eidetic-labs.stigmem
```

## Verifying existing data after alignment

Facts and gardens from older local checkouts live in
`tenant_id = "default"`. Confirm with any of your existing API keys:

```bash
# Your existing key still works, now in tenant "default"
curl -s -H 'Authorization: Bearer <existing-key>' \
  http://localhost:8765/v1/me
# → {"entity_uri": "...", "permissions": [...], "tenant_id": "default"}

# Facts are still accessible
curl -s -H 'Authorization: Bearer <existing-key>' \
  'http://localhost:8765/v1/facts?limit=5' | jq '.[].id'
```

## Breaking changes

<div className="stigmem-keypoint">

**Not a stable-release upgrade path.**

The alpha reset is not a stable-release upgrade path. The supported
public surface is <code>v0.9.0a1</code> plus current <code>main</code>
changes queued for later alpha artifacts. Breaking changes may occur
until <code>v1.0.0</code>.

</div>

The only behavior difference operators will notice is billing events:
the `LogHookBus` now writes a JSON line to stderr for each fact write
and garden creation. If your log ingestion pipeline is sensitive to
unexpected stderr output, either configure a custom `HookBus` that
discards events or filter the `{"billing": ...}` lines at your log
collector.

## Migration history at a glance

<div className="stigmem-fields">

<div>
<dt>Migration</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>What it adds</dd>
</div>

<div>
<dt><code>001_init</code></dt>
<dt><span className="stigmem-fields__type">baseline</span></dt>
<dd>Facts, api_keys, node_meta.</dd>
</div>

<div>
<dt><code>002_federation</code></dt>
<dt><span className="stigmem-fields__type">federation</span></dt>
<dd>Peers, nonces.</dd>
</div>

<div>
<dt><code>006_agent_keys</code></dt>
<dt><span className="stigmem-fields__type">attestation</span></dt>
<dd>Ed25519 agent key registration. Required for source attestation.</dd>
</div>

<div>
<dt><code>007_fact_audit</code></dt>
<dt><span className="stigmem-fields__type">audit</span></dt>
<dd>End-to-end audit log. Required for audit queries.</dd>
</div>

<div>
<dt><code>011_facts_garden_attested</code></dt>
<dt><span className="stigmem-fields__type">required</span></dt>
<dd><code>garden_id</code> + <code>attested</code> columns.</dd>
</div>

<div>
<dt><code>012_multi_tenant</code></dt>
<dt><span className="stigmem-fields__type">required</span></dt>
<dd><code>tenant_id</code> on all write-bearing tables.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**No rollback mechanism.**

All migrations run automatically at startup in ascending numeric
order. Take a database backup before upgrading if your data is
critical.

</div>

## What's next

<div className="stigmem-next">

<a href="./installation">
<strong>Guide</strong>
<span>Installation</span>
<small>Fresh install with Docker Compose.</small>
</a>

<a href="../security/audit-log">
<strong>Read</strong>
<span>Audit log</span>
<small>Querying the per-principal write trail.</small>
</a>

<a href="https://github.com/eidetic-labs/stigmem/tree/main/features/multi-tenant">
<strong>Experimental</strong>
<span>Multi-tenancy plugin</span>
<small>Tenant isolation model — opt-in package.</small>
</a>

</div>
