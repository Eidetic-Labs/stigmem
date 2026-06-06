# ADR-020: Feature-owned product structure and projection model

<p className="stigmem-meta"><span>9 min read</span><span>Accepted</span><span>Recorded 2026-05-21</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Make the feature the canonical unit of Stigmem product truth. Every feature has
a stable feature record with the same required files, regardless of whether the
feature is core, plugin-backed, adapter-facing, SDK-facing, deployment-related,
experimental, deprecated, or deferred. Roadmap, release, security, changelog,
compatibility, and protocol-index documents become policy/narrative hubs or
projections over feature records instead of independent duplicate sources.

</div>

<div className="stigmem-keypoint">

**Experimental is a maturity state, not a documentation architecture.**

The current repo gives experimental features a better colocation model than
core features: experimental features often have a colocated spec, status file,
security notes, tests, and implementation package. Core features are spread
across `spec/specs/`, public docs, changelog entries, tests, and security
evidence. This ADR makes the feature record universal.

</div>

**Status:** Accepted · **Date:** 2026-05-21 (accepted 2026-06-06; tooling already ships) · **Authors:** Eidetic Labs · **Folds:** [ADR-005](./archive/005-docs-ia) (docs IA), [ADR-009](./archive/009-repo-structure) (`experimental/`→metadata dissolution), [ADR-010](./archive/010-modular-specs) (modular per-topic specs), [ADR-014](./archive/014-compatibility-matrix) (compatibility-matrix projection), [ADR-018](./archive/018-security-documentation-colocation) (owned-vs-contributed security taxonomy) · **Related:** [ADR-001](./001-versioning), [ADR-002](./002-v1-scope), [ADR-008](./008-experimental-gates), [ADR-011](./011-cross-cutting-extraction)

<div className="stigmem-keypoint">

**Folds in five ADRs (de-contrition consolidation, 2026-06-06).** This ADR is the canonical home for the feature-owned product structure and its projections: it absorbs ADR-009's `experimental/`→metadata dissolution, ADR-010's modular per-topic spec mechanics (independent SemVer per spec + generated `spec/PROTOCOL.md`), ADR-014's compatibility matrix as a projection over feature metadata, ADR-018's owned-vs-contributed security-risk taxonomy, and ADR-005's docs IA (the four-tab Learn / Build / Operate / Secure structure, leading the Secure tab with the risk register). Each folded ADR's full text is retained in `docs/adr/archive/` for history. Status flipped Proposed → Accepted: the feature-record tooling (the `check_feature_*.py` validators + populated `features/`) already ships.

</div>

## Context

Stigmem currently has multiple documentation and implementation patterns for the
same conceptual object: a feature.

<div className="stigmem-grid">

<div><h4>Core features</h4><p>Normative behavior lives in <code>spec/specs/*.md</code>, public summaries in <code>docs/docs/</code>, implementation proof in code/tests/evidence files, release history in <code>CHANGELOG.md</code>, and security in protocol-level files.</p></div>
<div><h4>Experimental features</h4><p>Feature truth often lives together under <code>experimental/&lt;feature&gt;/</code>: <code>spec.md</code>, <code>STATUS.md</code>, optional <code>security.md</code>, tests, conformance, and package code.</p></div>
<div><h4>Release planning</h4><p>Strategic roadmap, release readiness, changelog, Internal-Comms drafts, PR bodies, and security evidence have historically repeated overlapping facts.</p></div>

</div>

This creates three recurring problems:

<div className="stigmem-fields">

<div>
<dt>Problem</dt>
<dt><span className="stigmem-fields__type">Effect</span></dt>
<dd>Why it matters</dd>
</div>

<div>
<dt>Feature identity depends on directory category</dt>
<dt><span className="stigmem-fields__type">structural</span></dt>
<dd>Core and experimental features use different mental models, even though both need a spec, status, evidence, security analysis, and release history.</dd>
</div>

<div>
<dt>Maturity is encoded as location</dt>
<dt><span className="stigmem-fields__type">brittle</span></dt>
<dd>A feature that changes maturity would need either a move or a misleading path. Stability should be metadata, not a directory prefix.</dd>
</div>

<div>
<dt>Top-level docs duplicate feature facts</dt>
<dt><span className="stigmem-fields__type">maintenance</span></dt>
<dd><code>SECURITY.md</code>, <code>CHANGELOG.md</code>, <code>spec/PROTOCOL.md</code>, compatibility tables, and public feature pages can drift when they repeat details maintained elsewhere.</dd>
</div>

<div>
<dt>Roadmap and release docs carry too much detail</dt>
<dt><span className="stigmem-fields__type">planning</span></dt>
<dd>One long roadmap becomes hard to maintain, but over-trimming loses strategic intent and implementation specificity.</dd>
</div>

</div>

The existing ADRs already point toward feature ownership:

- ADR-008 treats the feature as the unit of reintroduction readiness.
- ADR-010 colocates experimental specs with the features they describe.
- ADR-012 says stability and since-version should be visible on feature pages.
- ADR-018 says feature security should live with the feature.

They do not establish a single feature-owned record across core and
experimental features. This ADR fills that gap.

## Decision

Adopt a feature-owned product structure and projection model.

### 1 · Feature records are the canonical product truth

Every Stigmem feature has one canonical feature record:

```text
features/<feature-slug>/
├── README.md
├── spec.md
├── status.md
├── evidence.md
├── security.md
└── changelog.md
```

Feature slugs use lowercase kebab case and name the capability, not the
implementation mode:

```text
features/content-addressed-ids/
features/federation-trust/
features/time-travel/
features/openclaw-adapter/
```

Do not encode maturity or implementation type in the path:

```text
features/plugins/time-travel/      # no
features/core/content-addressed-ids/ # no
features/experimental/time-travel/ # no
```

### 2 · Required feature files have fixed roles

<div className="stigmem-fields">

<div>
<dt>File</dt>
<dt><span className="stigmem-fields__type">Owner</span></dt>
<dd>Purpose</dd>
</div>

<div>
<dt><code>README.md</code></dt>
<dt><span className="stigmem-fields__type">orientation</span></dt>
<dd>Feature overview, owner, maturity, implementation mode, package/import paths, and links to the other feature files.</dd>
</div>

<div>
<dt><code>spec.md</code></dt>
<dt><span className="stigmem-fields__type">normative behavior</span></dt>
<dd>Protocol, API, CLI, config, storage, plugin, or adapter behavior the feature promises.</dd>
</div>

<div>
<dt><code>status.md</code></dt>
<dt><span className="stigmem-fields__type">state and lifecycle</span></dt>
<dd>Current maturity, gate status, release history, known gaps, and what changed when.</dd>
</div>

<div>
<dt><code>evidence.md</code></dt>
<dt><span className="stigmem-fields__type">proof</span></dt>
<dd>Implementation paths, migrations, tests, conformance vectors, validators, release evidence, and coverage gaps.</dd>
</div>

<div>
<dt><code>security.md</code></dt>
<dt><span className="stigmem-fields__type">risk</span></dt>
<dd>Feature-specific threat-model deltas, mitigations, residual risks, safe/unsafe deployment modes, and advisory links.</dd>
</div>

<div>
<dt><code>changelog.md</code></dt>
<dt><span className="stigmem-fields__type">feature history</span></dt>
<dd>Detailed feature-local change history by release. Root <code>CHANGELOG.md</code> remains the curated project-level release ledger.</dd>
</div>

</div>

All six files are required for every feature. If a file has no feature-specific
content yet, it states that explicitly. Missing files are not used to imply "not
applicable."

### 3 · Feature metadata carries maturity and implementation mode

Feature maturity and type are metadata, not directory placement.

The feature `README.md` frontmatter defines the canonical metadata:

```yaml
---
feature_id: time-travel
title: Time-travel queries
status: active
stability: experimental
since: 0.9.0a1
owner: maintainers
feature_type: plugin
default_surface: opt-in
canonical_spec: Spec-X3-Time-Travel-Queries
package: stigmem-plugin-time-travel
implementation_path: features/time-travel/src/stigmem_plugin_time_travel
adr_refs:
  - ADR-008
  - ADR-011
security_refs:
  - R-17
release_lines:
  - v0.9.0aN
---
```

Allowed values:

| Field | Values |
|---|---|
| `status` | `proposed`, `active`, `shipped`, `deferred`, `superseded` |
| `stability` | `stable`, `beta`, `experimental`, `deprecated` |
| `feature_type` | `core`, `plugin`, `adapter`, `sdk`, `deployment`, `protocol`, `tooling`, `docs` |
| `default_surface` | `default`, `opt-in`, `experimental`, `internal`, `external` |

`stability` follows ADR-012. `status` describes implementation and planning
state. A feature can be `status: shipped` and `stability: experimental`.

### 4 · Core and plugin implementation modes are both valid

This ADR does not require every feature to be a separate package. It defines
feature ownership and the canonical record.

Core/default implementation may live inside the importable core package:

```text
node/src/stigmem_node/features/<feature_name>/
```

Plugin or opt-in implementation may live directly in the feature directory when
the feature is a real Python distribution:

```text
features/<feature-slug>/
├── pyproject.toml
├── src/
│   └── stigmem_plugin_<feature_name>/
└── tests/
```

Adapters, SDKs, deployment surfaces, and tooling may keep their established
package roots when moving code would add packaging or import risk. Their
feature records still live under `features/<feature-slug>/` and point to the
implementation path.

Feature-specific implementation should move toward the feature-owned package or
`stigmem_node.features.<feature_name>` form when that move is technically safe.
Routine helpers and shared infrastructure do not become features only because
they are imported by features.

### 5 · Experimental is metadata, not a permanent feature category

`experimental/` is not a canonical feature documentation category after this
ADR. Experimental maturity is represented by feature metadata:

```yaml
stability: experimental
default_surface: opt-in
```

Existing `experimental/<feature>/` directories may remain during migration to
avoid unnecessary moves, packaging churn, or broken links. During transition,
they link to the canonical `features/<feature-slug>/` record.

### 6 · Existing high-level documents become hubs or projections

Feature files own feature facts. Higher-level documents own policy, narrative,
or projections:

| Artifact | Role after this ADR |
|---|---|
| `ROADMAP.md` | Strategic horizon and version-line sequencing. Links to feature records and release roadmaps; does not own feature detail. |
| `docs/internal/releases/<version>-roadmap.md` | Release contract: in/out scope, artifacts, evidence gates, feature changes, release-note candidates. |
| `CHANGELOG.md` | Curated user/operator-facing project release ledger, promoted from feature changelogs during release prep. |
| `SECURITY.md` | Reporting policy, supported versions, disclosure policy, current release posture, advisory index, and feature-security projection. |
| `spec/PROTOCOL.md` | Protocol index/projection over feature specs and protocol specs. |
| `spec/specs/*.md` | Compatibility/generated views during migration, not independent feature truth once migrated. |
| `docs/docs/concepts/features.md` | Public feature matrix projection over feature metadata. |
| `docs/compatibility-matrix.yaml` | Compatibility projection over feature metadata, package surfaces, and release support. |
| `spec/security/threat-model.md` | Protocol-level security hub and unified risk register; links to feature `security.md` files for feature-specific analysis. |

Generated or curated projections must not duplicate full feature content. They
link to the feature record for detail.

### 7 · CI validates feature records

The feature record contract is enforceable. CI validates:

- every feature directory has the required six files;
- every feature `README.md` has required frontmatter;
- enum values are valid;
- `feature_id` values are unique;
- `canonical_spec` values are unique when present;
- projection files are regenerated once generation tooling exists.

Transition allowlists may exist while legacy features are migrated, but the
allowlist is not a permanent exception mechanism.

### 8 · Migration planning lives outside the ADR

This ADR defines the target product/documentation architecture. Migration
sequence, pilot features, wrappers, tooling rollout, and PR slicing are tracked
outside the ADR in internal planning documents and release roadmaps.

## Folded mechanics

The sections below carry the load-bearing mechanics absorbed from the
folded ADRs. They are retained verbatim-in-substance so the surviving
ADR is self-sufficient; the original ADRs remain in `docs/adr/archive/`.

### 9 · Modular per-topic specs (folds ADR-010)

The protocol is not a single monolithic document. Each topic gets its
own spec file with its own version and its own status track; a
generated meta-document names which combination of specs constitutes a
release.

<div className="stigmem-grid">

<div><h4>Naming + stable numbers</h4><p>Specs use <code>Spec-NN-Topic-Name</code>; <code>NN</code> is a stable two-digit identifier (X-prefix for experimental specs, e.g. <code>Spec-X3-Time-Travel-Queries</code>). The number is stable across renames; numbers are never reused.</p></div>
<div><h4>Independent SemVer per spec</h4><p>Each spec follows SemVer 2.0.0 <em>for itself</em>. <code>Spec-01-Core</code> can be at v1.2.0 while <code>Spec-13-Capability-Instructions</code> is at v0.4.0-draft. A breaking change bumps only that spec's major. The protocol release version (per ADR-001) is a separate, higher-level commitment naming a specific combination of spec versions.</p></div>
<div><h4>Per-spec status track</h4><p><code>Draft · Experimental · Stable · Superseded · Deprecated</code>, independent per spec. A spec can be Stable while a sibling is Experimental.</p></div>
<div><h4>Per-spec frontmatter</h4><p><code>spec_id</code>, <code>version</code>, <code>status</code>, <code>applies_to</code>, <code>supersedes</code>, <code>deprecated_by</code>, <code>depends_on</code> (with version ranges). Parseable; the meta-document is generated from it.</p></div>

</div>

<div className="stigmem-keypoint">

**`spec/PROTOCOL.md` is generated, not hand-written.**

`scripts/generate_protocol_md.py` reads spec frontmatter and produces
`spec/PROTOCOL.md` (the index + release-composition document). A CI
step runs the generator and fails on diff — only the generator can
write it. A core spec MUST NOT have a hard dependency on an
experimental spec; experimental specs may depend on core specs, and
circular dependencies are CI-blocked. In the feature-owned model,
`spec/PROTOCOL.md` is a projection over feature specs and protocol
specs (see §6); `spec/specs/*.md` are compatibility/generated views
during migration, not independent feature truth once migrated.

</div>

### 10 · Compatibility matrix as a projection (folds ADR-014)

`docs/compatibility-matrix.yaml` is the single source of truth for
compatibility relationships across the node, SDKs, adapters, host
connectors, and protocol versions — and, in the feature-owned model, a
**projection over feature metadata, package surfaces, and release
support** (per §6). It declares `packages`, `connectors`, `features`
(each with a `requires` map and optional `spec_section` / `stability`),
and `protocol_compatibility` (with deprecation windows). A Docusaurus
plugin renders three tables at `Operate → Compatibility`: package
versions, connector compatibility, feature compatibility.

`scripts/check_compatibility_matrix.py` validates in CI that every
package version corresponds to a real tagged release (or
`unreleased` with a banner), every `requires`/`spec_section` reference
resolves, and no matrix version is below the corresponding feature's
`since:`. A release PR cannot ship without updating the matrix;
`make compatibility-matrix-check` runs the validator locally.

### 11 · Owned-vs-contributed security taxonomy (folds ADR-018)

Security documentation is two-tiered, mirroring the spec model.
Cross-cutting risks live at protocol level in `spec/security/`
(unified risk register, architecture, disclosure, advisories,
scenarios); per-feature security analysis colocates with the feature
— in the feature-owned model, in the feature record's `security.md`
(per §2).

<div className="stigmem-keypoint">

**A risk has exactly one owning feature and zero or more contributing features.**

The owning feature's `security.md` carries the canonical analysis
(Risk ID, STRIDE category, description, likelihood, impact, severity,
control, status, mitigation). Contributing features carry brief
cross-listings that link to the canonical entry. Cross-cutting risks
(those with no single owning feature — e.g. HLC, embedding poisoning,
supply chain, admin storage tampering, the worm vector) live
exclusively at protocol level. Risk status tracks independently
(`Mitigated / Residual / Open / Accepted`); a risk owned by an
experimental feature can be `Open` without affecting other features.

</div>

`scripts/check_security_documentation.py` validates in CI that every
protocol-level `R-XX` resolves to full analysis or a per-feature
`security.md`, every "owned risk" in a per-feature doc has a
protocol-level entry, status is consistent across canonical entry and
cross-listings, frontmatter validates, and no cross-reference is
broken. This taxonomy supplies the `security.md` half of the feature
record and the feature-security projection in root `SECURITY.md`
(per §6).

### 12 · Docs information architecture (folds ADR-005)

The docs site at `docs.stigmem.dev` is organized into four top-level
tabs — **Learn · Build · Operate · Secure** — each self-contained for
its audience. The `audience` frontmatter taxonomy is five values
aligned with the tabs (`Evaluator → Learn`, `Integrator → Build`,
`Operator → Operate`, `Security → Secure`, `Spec → Secure`); the
`validate-audience` plugin enforces it. The Reference and Community
tabs dissolve into the four canonical homes (API Reference → Build;
Specification → Secure; Release Notes → top-level; etc.).

<div className="stigmem-keypoint">

**Secure is a peer tab, and it leads with the risk register.**

For a category where trust *is* the product, demoting security to a
sub-section sends the wrong signal — Secure is one of the four ways you
engage with the product, not an appendix. The Secure tab leads with the
current Mitigated / Residual / Open / Accepted risk register at the top
of the Threat Model page; the protocol specification lives under Secure
because the spec *is* a security artifact. This decision is load-bearing
and is not dropped by the fold.

</div>

In the feature-owned model these tabs are docs **projections**: public
feature pages (`docs/docs/concepts/features.md`) project over feature
metadata, and the Secure tab's risk register projects over the
protocol-level register plus per-feature `security.md` files (per §6).
One canonical page per topic; retired URLs get `client-redirects`.

### 13 · `experimental/` dissolves into metadata (folds ADR-009)

ADR-009's repository structure stands for the top-level shape (the
public adopter surface, build/config, critical-path code, and the
distinction between adapters — clients of stigmem's API — and plugins —
packages registering against the core hook system per ADR-011). What
this ADR changes is the treatment of `experimental/` as a documentation
category: maturity is metadata (`stability: experimental` +
`default_surface: opt-in` on the feature record), not directory
placement (per §1, §3, §5). Existing `experimental/<feature>/`
directories may persist during migration as wrappers linking to the
canonical `features/<feature-slug>/` record, but they are no longer the
canonical home for feature truth. CIDs remain core (not under
`experimental/`) per ADR-011's folded ADR-017 decision.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Keep the current core vs experimental split</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The split gives experimental features a better ownership model than core features and makes maturity depend on location.</dd>
</div>

<div>
<dt>Use <code>features/plugins/&lt;feature&gt;</code> and <code>features/core/&lt;feature&gt;</code></dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Implementation mode can change. Paths should name the capability and remain stable; metadata classifies implementation mode.</dd>
</div>

<div>
<dt>Collapse spec, status, evidence, security, and changelog into one feature file</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Those artifacts answer different questions and have different review triggers. Collapsing them creates large documents that rot.</dd>
</div>

<div>
<dt>Put all feature detail in <code>ROADMAP.md</code></dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The roadmap should preserve strategic horizon and sequencing, not become a giant checklist or feature dossier.</dd>
</div>

<div>
<dt>Move all Python runtime code into top-level <code>features/</code> immediately</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Python packaging and import stability remain hard constraints. Feature-owned package roots are valid, but moving code requires deliberate package and compatibility work.</dd>
</div>

</div>

## Consequences

### Positive

- Every feature has one canonical record.
- Core, plugin-backed, adapter, SDK, deployment, and experimental features use
  the same file contract.
- Root docs become smaller and less duplicative.
- Feature maturity is visible through metadata and history, not inferred from
  directory placement.
- Release roadmaps can identify changed features without owning all feature
  detail.
- Root `SECURITY.md`, `CHANGELOG.md`, `spec/PROTOCOL.md`, feature matrix, and
  compatibility matrix can become projections instead of hand-maintained
  duplicates.

### Costs

- Existing feature docs must be migrated.
- Spec and docs generators need to learn the feature record model.
- Compatibility wrappers may be required for existing `spec/specs/*` and
  `experimental/*` links.
- Feature-impacting PRs gain a new maintenance requirement: update the feature
  record, not only code/tests.

### Risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Mitigation</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Feature directories become a new sprawl surface</dt>
<dt><span className="stigmem-fields__type">standard contract</span></dt>
<dd>Every feature uses the same six-file contract and metadata. Validators reject partial records.</dd>
</div>

<div>
<dt>Generated projections drift</dt>
<dt><span className="stigmem-fields__type">CI</span></dt>
<dd>Projection checks fail when generated or curated indexes are stale.</dd>
</div>

<div>
<dt>Public links break during migration</dt>
<dt><span className="stigmem-fields__type">wrappers</span></dt>
<dd>Existing paths remain as wrappers or redirects until tooling and public docs are updated.</dd>
</div>

<div>
<dt>Feature changelogs and root changelog diverge</dt>
<dt><span className="stigmem-fields__type">release gate</span></dt>
<dd>Release prep reconciles feature changelogs into root <code>CHANGELOG.md</code>.</dd>
</div>

</div>

## Repository contracts

This ADR does not replace ADR-009's full repository structure. It amends the
parts that define feature ownership:

```text
features/<feature-slug>/
  README.md
  spec.md
  status.md
  evidence.md
  security.md
  changelog.md

node/src/stigmem_node/features/<feature_name>/
  # core/default implementation when shipped inside stigmem-node

features/<feature-slug>/src/
  # plugin or opt-in implementation when the feature is its own package

spec/specs/
  # compatibility/generated views over feature specs during migration

docs/docs/
  # public projections and narrative docs

docs/internal/releases/
  # release contracts
```

## Acceptance criteria

This ADR is implemented when:

- `features/README.md` defines the feature record registry.
- A feature template contains all required files and metadata examples.
- CI validates required feature files and frontmatter for migrated features.
- At least one core feature and one plugin-backed feature have complete feature
  records.
- High-level docs link to feature records instead of duplicating feature detail
  where practical.
- Migration sequencing is tracked outside the ADR.
