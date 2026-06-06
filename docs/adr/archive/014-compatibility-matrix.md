# ADR-014: Compatibility matrix

> **Superseded by ADR-020.** Content folded into ADR-020 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>6 min read</span><span>Superseded by ADR-020</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

A single source-of-truth YAML file at
`docs/compatibility-matrix.yaml` declares compatibility relationships
across the node, SDKs, adapters, host connectors, and protocol
versions. CI validates it against actual published versions; a
Docusaurus plugin renders three tables at `Operate → Compatibility`.

</div>

<div className="stigmem-keypoint">

**Cross-package questions are the first questions an integrator asks.**

"Does Python SDK 0.x work against a v0.9.0-preview node?" "Does the
Cursor MCP connector require any specific protocol section?" Without
a compatibility matrix, the answer is to read CHANGELOGs across
multiple packages and infer.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), [ADR-005](./005-docs-ia), [ADR-012](./012-version-aware-feature-exposure), [ADR-013](./013-deprecation-policy)

## Context

Stigmem's surface is multi-package: a node, a Python SDK, a TypeScript
SDK, a Go SDK, an MCP adapter, an OpenClaw adapter, plus a growing
catalog of host connectors (Cursor, Zed, Codex CLI, Continue Dev,
Gemini, Ollama-LiteLLM, Paperclip, Obsidian, Zep). Each ships its own
version. The protocol itself is versioned.

Industry practice:

<div className="stigmem-fields">

<div>
<dt>Project</dt>
<dt><span className="stigmem-fields__type">Pattern</span></dt>
<dd>Fit</dd>
</div>

<div>
<dt>MDN browser compatibility tables</dt>
<dt><span className="stigmem-fields__type">structured source, auto-rendered</span></dt>
<dd>Gold standard. A row per feature, columns per browser/version. Auto-generated from a <code>browser-compat-data</code> JSON source.</dd>
</div>

<div>
<dt>Kubernetes</dt>
<dt><span className="stigmem-fields__type">supported-versions page</span></dt>
<dd>Kubelet/kube-apiserver/etcd compatibility windows per release line.</dd>
</div>

<div>
<dt>AWS SDKs</dt>
<dt><span className="stigmem-fields__type">per-language release notes</span></dt>
<dd>Name minimum SDK versions for each new API.</dd>
</div>

<div>
<dt>Stripe</dt>
<dt><span className="stigmem-fields__type">per-SDK API version compatibility</span></dt>
<dd>Published in each SDK's docs.</dd>
</div>

</div>

The MDN model is the closest fit — feature-rich, generator-driven,
auto-validated. Hand-maintained narrative compatibility prose drifts;
a structured source-of-truth file with build-time rendering does not.

## Decision

A single source-of-truth YAML file at
`docs/compatibility-matrix.yaml` declares compatibility relationships.
The file is committed; CI validates it against actual published
versions; a Docusaurus plugin renders it as the
`Operate → Compatibility` page.

### Source-of-truth schema

```yaml
# docs/compatibility-matrix.yaml
generated_for_protocol_version: 0.9.0-preview

packages:
  node:
    versions:
      - "0.9.0-preview"
    repository: github.com/eidetic-labs/stigmem
  python_sdk:
    name: stigmem-py
    versions:
      - "0.9.0-preview"
  typescript_sdk:
    name: stigmem-ts
    versions:
      - "0.9.0-preview"
  go_sdk:
    name: stigmem-go
    versions: []  # not shipped in v0.9.0-preview; experimental
  mcp_adapter:
    versions:
      - "0.9.0-preview"
  openclaw_adapter:
    versions:
      - "0.9.0-preview"

connectors:
  - id: cursor
    requires:
      mcp_adapter: ">=0.9.0-preview"
      cursor: ">=0.42"
  - id: openclaw
    requires:
      openclaw_adapter: ">=0.9.0-preview"
      openclaw: ">=1.2"

features:
  - id: stigmem-version-header
    spec_section: §3.4
    requires:
      node: ">=0.9.0-preview"
      python_sdk: ">=0.9.0-preview"
      typescript_sdk: ">=0.9.0-preview"
    notes: "Wire-format pinning per ADR-012."
  - id: libsql-backend
    spec_section: §10
    stability: experimental
    requires:
      node: ">=0.9.0-preview"
    notes: "Storage backend trait; alternative backends are opt-in plugins."
  - id: argon2id-key-hashing
    requires:
      node: ">=0.9.0-preview"
    notes: "Per ADR-007."

protocol_compatibility:
  - protocol_version: "0.9.0-preview"
    supported_by:
      node: ">=0.9.0-preview"
      python_sdk: ">=0.9.0-preview"
      typescript_sdk: ">=0.9.0-preview"
    deprecation_window: "supported through 1.x; removable in 2.0 per ADR-013"
```

### Rendered output

The Docusaurus plugin renders three tables on the
`Operate → Compatibility` page.

<div className="stigmem-fields">

<div>
<dt>Table</dt>
<dt><span className="stigmem-fields__type">Rows × columns</span></dt>
<dd>Answers</dd>
</div>

<div>
<dt>Package versions</dt>
<dt><span className="stigmem-fields__type">packages × stability tiers</span></dt>
<dd>Latest stable, beta, experimental version for each package.</dd>
</div>

<div>
<dt>Connector compatibility</dt>
<dt><span className="stigmem-fields__type">connectors × stigmem-side / host-side</span></dt>
<dd>Adapter version requirements and host application version requirements.</dd>
</div>

<div>
<dt>Feature compatibility</dt>
<dt><span className="stigmem-fields__type">features × packages</span></dt>
<dd>Version constraint per package (e.g., <code>&gt;=0.9.0-preview</code>).</dd>
</div>

</div>

Each row links to the relevant feature page (using the `spec_section`
reference where applicable).

### CI validation

A `scripts/check_compatibility_matrix.py` validator runs in CI.

<div className="stigmem-grid">

<div><h4>Tagged releases</h4><p>Every package version in the matrix corresponds to an actual tagged release (or to <code>unreleased</code> with a banner).</p></div>
<div><h4>Feature requirements</h4><p>Every feature's <code>requires</code> references packages that exist in the matrix.</p></div>
<div><h4>Connector requirements</h4><p>Every connector's <code>requires</code> references packages that exist in the matrix.</p></div>
<div><h4>Spec section references</h4><p>Every <code>spec_section</code> reference points to a real spec section.</p></div>
<div><h4>Cross-validation with ADR-012 frontmatter</h4><p>No version in the matrix is below the <code>since:</code> value of the corresponding feature page.</p></div>

</div>

CI fails on any inconsistency. A docs PR cannot land if it changes a
feature's `since` without updating the matrix; a release PR cannot
ship without bumping the matrix.

### Update cadence

The matrix is updated as part of every release.

<div className="stigmem-fields">

<div>
<dt>Event</dt>
<dt><span className="stigmem-fields__type">Matrix change</span></dt>
<dd>Cross-reference</dd>
</div>

<div>
<dt>At deprecation</dt>
<dt><span className="stigmem-fields__type">annotate <code>deprecated_since</code> + <code>removed_in</code></span></dt>
<dd>Per ADR-013.</dd>
</div>

<div>
<dt>At feature removal</dt>
<dt><span className="stigmem-fields__type">move to <code>removed_features</code></span></dt>
<dd>With a final compatibility window.</dd>
</div>

<div>
<dt>At new package release</dt>
<dt><span className="stigmem-fields__type">add to <code>versions</code> list</span></dt>
<dd>Cross-package compatibility for new features is declared.</dd>
</div>

</div>

A `make compatibility-matrix-check` target runs the validator locally
so contributors can pre-flight matrix changes before pushing.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Hand-maintained narrative prose on each feature page</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Compatibility prose drifts; a feature page maintained by one person can't capture the full multi-package picture without reading every other package's CHANGELOG.</dd>
</div>

<div>
<dt>Per-package compatibility sections, no central matrix</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The same compatibility claim ends up duplicated in N places — Python SDK page says "works with node 0.9.0+", node page says "works with Python SDK 0.9.0+" — and these will drift independently.</dd>
</div>

<div>
<dt>GitHub Releases as the source of truth</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Good for binary distribution but bad for cross-package reading. An adopter shouldn't have to read 7 release pages to answer one question.</dd>
</div>

<div>
<dt>MDN-style external <code>browser-compat-data</code> repo</dt>
<dt><span className="stigmem-fields__type">deferred</span></dt>
<dd>Hosting compatibility data in a separate repo is overkill at v0.9.0-preview. Reconsider if community contributions to compatibility data become a real workflow (probably v2.0+).</dd>
</div>

<div>
<dt>Auto-generate matrix from package metadata</dt>
<dt><span className="stigmem-fields__type">deferred</span></dt>
<dd>Considered (e.g., Python SDK declares <code>supports_protocol = "0.9.0-preview"</code> in <code>pyproject.toml</code>). The metadata schema would need to land in every package, and the matrix's value is most useful before package-level metadata exists. The YAML source-of-truth ships first.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Adoption planning</h4><p>Operators and integrators can answer "does X work with Y" from one page.</p></div>
<div><h4>Release discipline</h4><p>The matrix update is a forcing function: a release PR has to think about compatibility explicitly.</p></div>
<div><h4>Cross-package validation</h4><p>CI catches inconsistencies between feature pages, the matrix, and actual package versions.</p></div>
<div><h4>Migration planning</h4><p>When a deprecation lands (per ADR-013), the matrix shows the support window across every package that touches the deprecated feature.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Per-release overhead</h4><p>Every release adds rows to the matrix. ~30 minutes of careful editing per release; non-trivial but bounded.</p></div>
<div><h4>YAML hand-editing risk</h4><p>Hand-edited YAML is error-prone. Mitigation: CI validator catches structural errors; <code>make compatibility-matrix-check</code> for local pre-flight.</p></div>
<div><h4>Initial population cost</h4><p>~1 day to populate the matrix for v0.9.0-preview's release surface.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-CM-1</code> · matrix drift from package reality</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A package ships a breaking change but the matrix still says it's compatible. Mitigation: CI validator cross-checks <code>since</code> declarations on feature pages; release-PR convention requires matrix update; quarterly drift check.</dd>
</div>

<div>
<dt><code>R-CM-2</code> · over-promising compatibility</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A feature declared compatible with a version that wasn't actually tested. Mitigation: matrix entries require evidence — at minimum, a passing CI run against the named version. For non-CI'd combinations, the matrix annotates <code>tested: false</code> and a <code>last-verified: &lt;date&gt;</code> hint.</dd>
</div>

<div>
<dt><code>R-CM-3</code> · matrix complexity outgrows YAML</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>As the package surface grows, the YAML may become too unwieldy to hand-edit. Mitigation: monitor; if the file exceeds ~500 lines, factor into per-package YAML files imported into a root schema. Reconsider auto-generation from package metadata.</dd>
</div>

</div>

## Implementation plan

Lands in master-checklist §4.3a (PR 2.5 — Docs site restructure and
reversion sweep) for the schema, validator, and rendered page. Initial
population uses v0.9.0-preview as the only baseline version.

<ol className="stigmem-steps">
<li>Author the schema in <code>docs/compatibility-matrix.yaml</code> with v0.9.0-preview baseline.</li>
<li>Add <code>scripts/check_compatibility_matrix.py</code> validator.</li>
<li>Add Docusaurus plugin (or remark/rehype hook) that reads the YAML at build time and renders the three tables.</li>
<li>Add <code>Operate → Compatibility</code> page using the rendered output.</li>
<li>Add <code>make compatibility-matrix-check</code> target.</li>
<li>Add CI step running the validator on every PR.</li>
<li>Document the matrix in <code>CONTRIBUTING.md</code> (when to update, how to update).</li>
<li>Wire matrix updates into the release runbook.</li>
</ol>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
