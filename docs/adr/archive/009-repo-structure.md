# ADR-009: Repository file structure

> **Superseded by ADR-020.** Content folded into ADR-020 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>9 min read</span><span>Superseded by ADR-020</span><span>Revised 2026-05-07</span></p>

<div className="stigmem-lead">

**What this ADR decides**

How ADR-002's scope contract manifests on disk: where deferred features
live, what the top level looks like, where plugins and adapters
diverge, and how the docs tree reorganizes for the four-tab IA.

</div>

<div className="stigmem-keypoint">

**Top level shrinks from 41 entries to ~22.**

A first-time visitor sees a small, navigable surface. The
`experimental/` directory is clearly labeled. Critical-path code is in
obvious locations. Scope creep requires a friction-producing PR rather
than a one-line change.

</div>

**Date:** 2026-05-06 · revised 2026-05-07 to incorporate ADR-011 plugin architecture, ADR-016 immutability stack, and ADR-017 CIDs-as-core amendment · **Authors:** Eidetic Labs · **Related:** [ADR-002](./002-v1-scope), [ADR-005](./005-docs-ia), [ADR-008](./008-experimental-gates), ADR-011, ADR-016, ADR-017, `stigmem/analyses/repo-structure-review.md`

## Context

The v1.0 release left the repository with structure that reflects the
broader scope question ADR-002 addresses.

<div className="stigmem-grid">

<div><h4>41 entries at root</h4><p>Vs. ~15–20 typical for a well-organized infrastructure project.</p></div>
<div><h4>Three dashboard locations</h4><p><code>apps/dashboard/</code>, <code>dashboards/</code>, <code>deploy/grafana/</code>.</p></div>
<div><h4>Two Helm chart locations</h4><p><code>infra/helm/</code>, <code>deploy/helm/</code>.</p></div>
<div><h4>13 spec versions at root</h4><p>Including the withdrawn v2.0 normative file.</p></div>
<div><h4>12 adapters at peer level</h4><p>Per ADR-002, only 2 (<code>mcp</code>, <code>openclaw</code>) are v1.0 critical-path.</p></div>
<div><h4>3 SDKs at peer level</h4><p>Per ADR-002, only 1 (<code>stigmem-py</code>) is critical-path.</p></div>
<div><h4>9 deploy targets</h4><p>Per ADR-002, only 1 (<code>compose</code>) is critical-path.</p></div>
<div><h4>No <code>experimental/</code> yet</h4><p>ADR-002 and ADR-008 require one.</p></div>

</div>

Internal-only artifacts pollute public-facing surfaces (`dogfood/`,
`tasks/todo.md`, `docs/video-scripts/`, the v1 launch blog post). The
`node/src/stigmem_node/` module itself is well-organized — the sprawl
is at the *repo* level, not inside the node module.

ADR-002 names what's in scope and out of scope. This ADR specifies how
that scope decision manifests on disk. The detailed analysis and
per-directory recommendations live in
`stigmem/analyses/repo-structure-review.md`. This ADR captures the
load-bearing decisions and the rationale.

<div className="stigmem-keypoint">

**ADR-011 changes what "node" contains.**

ADR-011 (revised 2026-05-07) committed to a C1 plugin architecture:
cross-cutting features become plugin packages under
`experimental/<feature>/`, registering against a hook system in core.
ADR-017 moved CIDs from plugin scope to core. ADR-016 added a storage
immutability stack with substantial new core code. The "node/ stays
as-is" framing from this ADR's first revision no longer holds.

</div>

## Decision

### 1 · Top-level shape

Roughly 22 entries (down from 41), organized into five buckets.

<div className="stigmem-fields">

<div>
<dt>Bucket</dt>
<dt><span className="stigmem-fields__type">Contents</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Public adopter surface</dt>
<dt><span className="stigmem-fields__type">root markdown</span></dt>
<dd><code>README.md</code> · <code>LICENSE</code> · <code>LIMITATIONS.md</code> · <code>ROADMAP.md</code> · <code>SECURITY.md</code> · <code>CHANGELOG.md</code> · <code>CONTRIBUTING.md</code> · <code>CODE_OF_CONDUCT.md</code>.</dd>
</div>

<div>
<dt>Build/config</dt>
<dt><span className="stigmem-fields__type">toolchain</span></dt>
<dd><code>pyproject.toml</code> · <code>package.json</code> · <code>pnpm-workspace.yaml</code> · <code>pnpm-lock.yaml</code> · <code>uv.lock</code> · <code>turbo.json</code> · <code>cliff.toml</code> · <code>Makefile</code> · <code>.python-version</code> · <code>.readthedocs.yaml</code> · <code>.mcp.json</code> · <code>.env.example</code> · <code>.gitignore</code>.</dd>
</div>

<div>
<dt>Critical-path code</dt>
<dt><span className="stigmem-fields__type">v1.0 surface</span></dt>
<dd><code>node/</code> (with plugin-infrastructure per ADR-011) · <code>adapters/</code> (mcp + openclaw only) · <code>sdks/</code> (Python only) · <code>deploy/</code> (compose only).</dd>
</div>

<div>
<dt>Critical-path assets</dt>
<dt><span className="stigmem-fields__type">supporting</span></dt>
<dd><code>data/</code> (with <code>data/conformance/adversarial/</code> per ADR-015) · <code>docs/</code> · <code>spec/</code> · <code>site/</code> · <code>eval/</code> · <code>scripts/</code>.</dd>
</div>

<div>
<dt>Deferred work</dt>
<dt><span className="stigmem-fields__type">experimental</span></dt>
<dd><code>experimental/</code> (six plugin packages per ADR-011 plus non-plugin deferred items).</dd>
</div>

</div>

Single canonical demo entry: `docker-compose.yml` (observability
variant consolidated as a Compose profile, not a peer file). Test
config: `conftest.py`. CI: `.github/`.

**Removed from root:** `apps/`, `dashboards/`, `dogfood/`, `infra/`,
`tasks/`, `docker-compose.observability.yml`.

### 2 · `experimental/` is the canonical home for deferred features

Per ADR-002 and ADR-008, every deferred feature lives at
`experimental/<feature>/` with a `STATUS.md` tracking gate progress.

#### 2(a) · Plugin packages

Per ADR-011 C1 architecture. Six cross-cutting features:
`lazy-instruction-discovery`, `time-travel`, `tombstones`,
`memory-garden-acl`, `source-attestation`, `multi-tenant`. Each is a
complete Python package that registers against the core hook system.

```
experimental/<feature>/                          # plugin package root
├── pyproject.toml                               # [project.entry-points."stigmem.plugins"]
├── README.md                                    # plugin overview, install, capability declarations
├── STATUS.md                                    # gate progress per ADR-008
├── src/
│   └── stigmem_plugin_<feature>/                # importable module
│       ├── __init__.py                          # exports register(context) -> PluginManifest
│       ├── handlers.py                          # hook handler implementations
│       └── config.py                            # Pydantic config schema
├── tests/                                       # plugin-specific tests
├── migrations/                                  # plugin's schema migrations (if any)
├── integration/
│   └── README.md                                # hook contract, capability declarations, configuration
└── conformance/                                 # plugin-specific conformance vectors
```

The plugin's distribution is signed via Sigstore (production mode) per
ADR-011 §Plugin trust and security model. Operators install via
`pip install stigmem-plugin-<feature>`.

#### 2(b) · Non-plugin deferred items

Adapters, SDKs, deploy targets, and other deferred code that is not
implemented as a stigmem-plugin package. These preserve their
pre-extraction structure:

```
experimental/<item>/
├── STATUS.md                                    # gate progress per ADR-008
└── ... (code preserved as-is from v1.0)
```

<div className="stigmem-keypoint">

**CIDs do NOT appear under `experimental/`.**

Per ADR-017 (amendment to ADR-011), content-addressed fact IDs were
moved from plugin scope to core because they are load-bearing for
ADR-003's trust boundary and ADR-016's immutability stack (L3). The
CID code lives in `node/src/stigmem_node/cid.py`. The remaining six
cross-cutting features remain plugins.

</div>

### 2a · Plugins are not adapters

The repo distinguishes two kinds of extension code.

<div className="stigmem-fields">

<div>
<dt>Concept</dt>
<dt><span className="stigmem-fields__type">Where it lives</span></dt>
<dd>What it is</dd>
</div>

<div>
<dt>Adapter</dt>
<dt><span className="stigmem-fields__type"><code>adapters/&lt;name&gt;/</code> or <code>experimental/&lt;name&gt;-adapter/</code></span></dt>
<dd>A client of stigmem's recall/assert API. External system consumes stigmem's data. Examples: MCP, OpenClaw, Cognee, Obsidian.</dd>
</div>

<div>
<dt>Plugin</dt>
<dt><span className="stigmem-fields__type"><code>experimental/&lt;feature&gt;/</code></span></dt>
<dd>A stigmem-extension package that registers against the core hook system per ADR-011. Extends what the protocol does. Examples: tombstones, time-travel, multi-tenant.</dd>
</div>

</div>

The Obsidian plugin (`experimental/obsidian-adapter/plugin/`) is named
for Obsidian's plugin system; it is an adapter from stigmem's
perspective. To avoid terminology confusion, this ADR and downstream
docs use **"plugin"** exclusively to mean ADR-011 stigmem plugins, and
**"adapter"** to mean stigmem clients.

### 3 · Adapters: cut to two

`adapters/` contains only `mcp/` and `openclaw/` plus a README. Other
adapters move:

<div className="stigmem-fields">

<div>
<dt>From</dt>
<dt><span className="stigmem-fields__type">To</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>adapters/cognee/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/cognee-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/gemini/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/gemini-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/letta/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/letta-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/obsidian/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/obsidian-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/obsidian-plugin/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/obsidian-adapter/plugin/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/openai-tools/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/openai-tools-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/paperclip/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/paperclip-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/zep/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/zep-adapter/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>adapters/boot-stubs/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/lazy-instruction-discovery/boot-stubs/</code></span></dt>
<dd>Lives under the lazy-instruction-discovery plugin per ADR-011.</dd>
</div>

</div>

The `clawhub-skill/` duplicate inside `adapters/openclaw/` is
consolidated per OpenClaw audit M1; the directory was renamed to
`skill/` in v0.9.0a2 (skill v1.0.8) to remove the `clawhub-` prefix
that was tripping the publish CLI's name/slug-from-directory
inference. See SKILL.md changelog and `.github/workflows/clawhub-publish.yml`
for context.

### 4 · SDKs: cut to one

`sdks/` contains only `stigmem-py/`. Go and TypeScript SDKs move to
`experimental/sdk-go/` and `experimental/sdk-ts/`.

### 5 · Deploy targets: cut to one

`deploy/` contains only `compose/` and `seccomp/` (the latter is used
by Compose hardening). Other targets move:

<div className="stigmem-fields">

<div>
<dt>From</dt>
<dt><span className="stigmem-fields__type">To</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>deploy/helm/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-helm/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>deploy/fly/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-fly/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>deploy/systemd/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-systemd/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>deploy/grafana/</code> + <code>deploy/prometheus/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-grafana/</code></span></dt>
<dd>Consolidated.</dd>
</div>

<div>
<dt><code>deploy/paas/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-paas/</code></span></dt>
<dd></dd>
</div>

</div>

### 6 · Consolidate dashboard and observability

Three current locations consolidate to one experimental directory:

<div className="stigmem-grid">

<div><h4><code>apps/dashboard/</code></h4><p>Next.js curator dashboard → <code>experimental/dashboard/</code>.</p></div>
<div><h4><code>dashboards/grafana/</code> + <code>prometheus/</code></h4><p>JSON definitions → <code>experimental/deploy-grafana/dashboards/</code>.</p></div>
<div><h4><code>deploy/grafana/</code> + <code>prometheus/</code></h4><p>Provisioning → <code>experimental/deploy-grafana/</code>.</p></div>

</div>

After consolidation, `apps/` and `dashboards/` directories are removed.

### 7 · Resolve `infra/`

<div className="stigmem-fields">

<div>
<dt>Path</dt>
<dt><span className="stigmem-fields__type">Destination</span></dt>
<dd>Reasoning</dd>
</div>

<div>
<dt><code>infra/docker-compose.soak.yml</code></dt>
<dt><span className="stigmem-fields__type"><code>eval/soak/</code></span></dt>
<dd>It's a soak-test rig, not a deploy target.</dd>
</div>

<div>
<dt><code>infra/fly.toml</code>, <code>fly.dashboard.toml</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-fly/</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>infra/helm/</code></dt>
<dt><span className="stigmem-fields__type"><code>experimental/deploy-helm/</code></span></dt>
<dd>Merged with <code>deploy/helm/</code> to resolve duplication.</dd>
</div>

<div>
<dt><code>infra/soak/</code></dt>
<dt><span className="stigmem-fields__type"><code>eval/soak/</code></span></dt>
<dd></dd>
</div>

</div>

After moves, `infra/` is removed.

### 8 · Spec reorganization

```
spec/
├── README.md                    # Index pointing at current and listing archive
├── CHANGELOG.md                 # Version history
├── stigmem-spec.md              # The CURRENT spec (one file, no version suffix)
├── archive/                     # All historical and superseded specs
│   ├── stigmem-spec-v0.2.md
│   ├── stigmem-spec-v0.3-draft.md
│   ├── ... (all v0.x drafts)
│   ├── stigmem-spec-v1.0.md     # Superseded; preserved for reference
│   ├── stigmem-spec-v1.1-draft.md
│   └── stigmem-spec-v2.0.md     # Superseded; preserved for reference
├── design/                      # Existing — keep
└── security/                    # Existing — threat-model.md lives here
```

`spec/stigmem-spec-v0.9-section-17-memory-garden-draft.md` moves to
`experimental/17-memory-garden/spec.md` — it's a draft for a deferred
feature.

### 9 · `docs/` reorganization per ADR-005

`docs/docs/` reorganizes into the four-tab IA: Learn / Build / Operate
/ Secure. Sidebars and versioning update accordingly.
`docs/versioned_docs/` adds `version-v0.9.0-preview/` and archives
`version-v0.2/` and `version-v1.1/`.

Top-level `docs/*.md` operational artifacts move:

<div className="stigmem-fields">

<div>
<dt>From</dt>
<dt><span className="stigmem-fields__type">To</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>docs/cursor-reset-recovery.md</code></dt>
<dt><span className="stigmem-fields__type"><code>docs/operate/troubleshooting.md</code></span></dt>
<dd>Or removed.</dd>
</div>

<div>
<dt><code>docs/failure-modes-4node.md</code></dt>
<dt><span className="stigmem-fields__type"><code>docs/operate/runbooks/4node-failure-modes.md</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>docs/soak-report-4node.md</code></dt>
<dt><span className="stigmem-fields__type"><code>eval/soak/reports/4node-2026-XX.md</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>docs/video-scripts/</code></dt>
<dt><span className="stigmem-fields__type">out of docs tree</span></dt>
<dd>Private repo or <code>dogfood/</code>.</dd>
</div>

</div>

The v1.0 launch blog post (`docs/blog/2026-05-03-stigmem-v1-launch.md`)
is **bannered in place** with a pointer to the migration post, not
deleted, to preserve external link history.

### 10 · Add the missing top-level docs and fix LICENSE

<div className="stigmem-grid">

<div><h4><code>LIMITATIONS.md</code></h4><p>Already drafted — operator-facing limitation statement.</p></div>
<div><h4><code>MAINTAINERS.md</code></h4><p>Already drafted at <code>Internal-Comms/stigmem/public/MAINTAINERS.md</code> — current founder + founding-team placeholder.</p></div>
<div><h4><code>ROADMAP.md</code></h4><p>Public roadmap derived from the strengthening plan.</p></div>
<div><h4><code>docs/adr/</code></h4><p>Directory containing all 18 ADRs.</p></div>

</div>

<div className="stigmem-keypoint">

**`LICENSE` — replace.**

Verification 2026-05-07 found ~10 substantive deviations from the
canonical Apache-2.0 SPDX text (§1 definitions, §3 patent grant, §4
NOTICE clause, §4 sublicense wording, §7 word changes, §8 damages list
and "exemplary" vs "consequential", §9 heading). These are not
formatting drift; they are legally distinct text. Canonical replacement
is staged at `Internal-Comms/stigmem/public/LICENSE` with
`Copyright 2026 Eidetic Labs` substituted in the Appendix. Lands during
Phase A PR 1.

</div>

### 11 · Remove or relocate internal-only artifacts

`dogfood/` is split per the founder review (2026-05-07):

<div className="stigmem-fields">

<div>
<dt>File</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt><code>dogfood/migrate_ceo_memory.py</code></dt>
<dt><span className="stigmem-fields__type">genericize → <code>scripts/import_markdown_tree.py</code></span></dt>
<dd>The pattern (markdown index + frontmatter → facts) is useful; original was hardcoded to one personal use case. Genericized version takes <code>--entity</code>, <code>--scope</code>, <code>--source</code>, <code>--relation-prefix</code>, <code>--default-type</code>, <code>--confidence</code>, <code>--index-file</code>.</dd>
</div>

<div>
<dt><code>dogfood/snapshot.sh</code></dt>
<dt><span className="stigmem-fields__type">relocate → <code>scripts/stigmem-snapshot.sh</code></span></dt>
<dd>Genericized version takes <code>--scope</code>, <code>--entities</code>, <code>--output</code>; <code>company:acme</code> placeholder removed; auth via <code>STIGMEM_API_KEY</code>; supports <code>--limit</code> and <code>--no-contradictions</code>.</dd>
</div>

<div>
<dt><code>dogfood/devto-lazy-discovery-tokenomics.md</code></dt>
<dt><span className="stigmem-fields__type">remove or archive</span></dt>
<dd>Already published externally on dev.to. Founder's call.</dd>
</div>

<div>
<dt><code>dogfood/README.md</code></dt>
<dt><span className="stigmem-fields__type">split</span></dt>
<dd>Content splits into operator-doc sections that ship with each script.</dd>
</div>

<div>
<dt><code>tasks/todo.md</code></dt>
<dt><span className="stigmem-fields__type">remove</span></dt>
<dd>Use GitHub Projects or a private repo for in-flight TODOs.</dd>
</div>

<div>
<dt><code>docs/blog/devto-post-v1-launch.txt</code></dt>
<dt><span className="stigmem-fields__type">remove or archive</span></dt>
<dd>Under <code>docs/blog/archive/</code>.</dd>
</div>

</div>

**Net: `dogfood/` directory disappears entirely from the v0.9.0-preview
repo.** Useful patterns extracted; personal/CEO-specific framing
removed.

### 12 · `node/` module gains plugin infrastructure (per ADR-011) and immutability stack (per ADR-016)

`node/src/stigmem_node/` had good internal organization in v1.0. This
ADR does **not** propose a cosmetic restructure. But ADR-011 and
ADR-016 add substantial new core code that needs a home.

**Plugin infrastructure (per ADR-011), added in Phase A:**

```
node/src/stigmem_node/
├── plugins/                    # plugin-system core code (new)
│   ├── registry.py             # HookRegistry, band-based composition
│   ├── manifest.py             # PluginManifest schema and validation
│   ├── context.py              # PluginContext with capability-restricted accessors
│   ├── lifecycle.py            # registration, validation, health monitoring
│   ├── signing.py              # Sigstore verification at registration
│   ├── audit.py                # plugin registration audit events
│   ├── hooks/                  # voting.py, filter_chain.py, score_delta.py, fire_and_forget.py
│   └── capabilities.py         # capability allowlist
├── cid.py                      # CIDs (core per ADR-017, not a plugin)
└── ... (existing modules)
```

**Immutability stack (per ADR-016), added in Phase B:**

```
node/src/stigmem_node/
├── chain/                      # local hash chain (L4)
├── transparency/               # Sigstore Rekor integration (L5)
├── projections/                # projection tables (L1) for previously-mutable fields
└── ... (existing modules)
```

**Conformance-corpus runner (per ADR-015), added in Phase B:**
`scripts/run_adversarial_conformance.py` (not under `node/`; CLI tool
for model certification).

A separate follow-up audit decides which existing individual `*.py`
files in the module correspond to deferred features (`billing.py`,
`instruction_migrate.py`, `fuzzy_resolver.py`, `graph_index.py`,
`card_materializer.py`) and whether they move under
`experimental/<feature>/`. That audit lands after this ADR's PRs
settle. Some (e.g., `instruction_migrate.py`) are likely already
absorbed into the `lazy-instruction-discovery` plugin per ADR-011; the
audit confirms.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Update ADR-002 with file-layout decisions instead of a new ADR</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>ADR-002 is the <em>scope</em> decision; this ADR is the <em>layout</em> decision. They're separable: a reader could agree with one and disagree with the other. Combining obscures which is being challenged.</dd>
</div>

<div>
<dt>Restructure <code>node/src/stigmem_node/</code> in the same pass</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The module is well-organized internally; cosmetic restructuring is not a payoff. A targeted follow-up audit can move deferred-feature files later.</dd>
</div>

<div>
<dt>Delete deferred features rather than moving to <code>experimental/</code></dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>ADR-008 commits to feature reintroduction through gates. Deletion forecloses on that. The <code>experimental/</code> directory is the cost of preserving optionality.</dd>
</div>

<div>
<dt>Land the entire restructure as one large PR</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The change touches workspace configs, CI, docs IA, and ~50 directory moves. A single PR is unreviewable. Three sequential PRs keep diffs reviewable and let CI confirm correctness at each step.</dd>
</div>

<div>
<dt>Wait until v1.0.0 GA to do the structural cleanup</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The current structure actively confuses anyone evaluating the project and makes Phase A deliverables harder to land. Doing it now is the lowest-cost moment.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Top-level reads as a coherent project</h4><p>A first-time visitor sees a small, navigable surface. <code>experimental/</code> is clearly labeled; critical-path code is in obvious locations.</p></div>
<div><h4>Scope contract becomes physically obvious</h4><p>Anyone proposing scope creep has to add a directory to <code>adapters/</code>, <code>sdks/</code>, or <code>deploy/</code> — friction-producing PR rather than a one-line change.</p></div>
<div><h4>Gate progression structurally tracked</h4><p>Each <code>experimental/&lt;feature&gt;/STATUS.md</code> is the single source of truth for that feature's progress.</p></div>
<div><h4>Default builds become well-defined</h4><p>Python workspace, pnpm workspace, and Turbo config exclude <code>experimental/</code>. Clean clone + <code>make demo</code> + <code>pytest</code> runs against the v1.0 critical-path.</p></div>
<div><h4>Future restructuring is structural, not stylistic</h4><p>Any further reorganization happens via amendments to this ADR, not ad-hoc.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Migration cost</h4><p>Three PRs of structural moves, plus updates to imports, workspace configs, CI workflows, and external links. Mitigated by Docusaurus redirects and PR sequencing.</p></div>
<div><h4>Existing operator import paths break</h4><p>Operators of v1.0 who built against <code>adapters/letta/</code> (or any moved adapter) find their installs broken. Mitigated by the migration notice.</p></div>
<div><h4>Discoverability of experimental features</h4><p>A user who wants the Postgres backend can no longer find it at <code>deploy/</code>. Mitigated by <code>experimental/README.md</code> and cross-references.</p></div>
<div><h4>Local checkouts need refresh</h4><p>Existing IDE workspaces and build tooling on contributors' machines assume the current structure. Anyone with a checkout needs to refresh paths.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-STRUCT-1</code> · link rot from external sources</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Docusaurus supports redirects; the migration post explicitly addresses migration; the most-linked-to file (v1 blog post) is bannered in place.</dd>
</div>

<div>
<dt><code>R-STRUCT-2</code> · incomplete cuts</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A subsequent feature could land in the wrong place. Mitigation: PR template asks "does this PR add a file at the top level or under <code>adapters/</code>, <code>sdks/</code>, <code>deploy/</code>? If so, link the ADR-002 amendment that authorized it."</dd>
</div>

<div>
<dt><code>R-STRUCT-3</code> · experimental code rotting</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Code in <code>experimental/</code> that nobody touches develops bugs that emerge years later when reintroduction is attempted. Mitigation: per ADR-008, experimental features are buildable but not part of the test matrix; reintroduction brings them to v1.x quality.</dd>
</div>

</div>

## Implementation plan

Three sequential PRs, all in Phase A of the strengthening plan.

<ol className="stigmem-steps">
<li><strong>PR 1 · Create <code>experimental/</code> and move out-of-scope code.</strong> Create <code>experimental/</code> with <code>README.md</code> and <code>STATUS-TEMPLATE.md</code>. Move adapters, SDKs, deploy targets, dashboard, infra contents. Resolve duplicate Helm chart. Update <code>pyproject.toml</code>, <code>pnpm-workspace.yaml</code>, <code>turbo.json</code> to exclude <code>experimental/</code>. Update CI workflows and Makefile. Run full test suite to confirm v1.0 critical-path still builds. Large but mechanical — most is <code>git mv</code> plus workspace-config updates.</li>
<li><strong>PR 2 · Spec reorganization, top-level cleanup, ADRs.</strong> Move spec drafts to <code>spec/archive/evolution/</code>. Designate canonical spec at <code>spec/stigmem-spec-v0.9.0-preview.md</code>. Move section-17 draft to <code>experimental/memory-garden-acl/spec.md</code>. Remove <code>dogfood/</code>, <code>tasks/</code>, <code>infra/</code>, <code>apps/</code>, <code>dashboards/</code>. Banner the v1 blog post in place. Add <code>docs/adr/</code> with all 17 ADRs plus README. Add <code>LIMITATIONS.md</code>, <code>ROADMAP.md</code>, <code>MAINTAINERS.md</code>.</li>
<li><strong>PR 3 · Docs IA restructure.</strong> Restructure <code>docs/docs/</code> into Learn / Build / Operate / Secure (per ADR-005). Update <code>docs/sidebars.js</code>. Update <code>docs/versioned_docs/</code> to add <code>version-v0.9.0-preview/</code>. Move top-level <code>docs/*.md</code> operational files. Move <code>docs/video-scripts/</code> out. Update <code>docs/blog/</code> to reflect the retraction.</li>
</ol>

### Verification (every PR)

<div className="stigmem-grid">

<div><h4><code>make demo</code> works</h4><p>On a clean machine.</p></div>
<div><h4><code>pytest</code> passes</h4><p>Against v1.0 critical-path.</p></div>
<div><h4>Version consistency</h4><p><code>python scripts/check_version_consistency.py</code> passes.</p></div>
<div><h4>CI green</h4><p>Full workflow suite.</p></div>
<div><h4>Linkrot check</h4><p>Any moved file linked externally has a redirect or the linker is updated.</p></div>

</div>

## Amendment process

Changes to the layout require:

<ol className="stigmem-steps">
<li>A new ADR titled "Amendment to ADR-009: [scope of change]".</li>
<li>Sign-off per ADR-001 §Contributor approval rule (two contributors or the founder alone).</li>
<li>Coordination with ADR-002 if the change reflects a scope-decision change, or with ADR-011 if the change reflects a plugin-architecture change.</li>
</ol>

Routine internal changes within `node/`, `adapters/<existing>/`, or
`experimental/<feature>/` do not require amendments — only changes to
the top-level layout or to which features live where.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
