# ADR-018: Per-feature security documentation colocation

> **Superseded by ADR-020.** Content folded into ADR-020 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>7 min read</span><span>Superseded by ADR-020</span><span>Recorded 2026-05-07</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Restructure security documentation into two tiers, mirroring ADR-010's
modular-specs model. Cross-cutting risks live at protocol level in
`spec/security/`. Per-feature security analysis colocates with the
feature at `experimental/<feature>/security.md`. The threat model
becomes a hub that focuses on cross-cutting risks and references
per-feature analysis.

</div>

<div className="stigmem-keypoint">

**A feature's spec migrates with the feature; its security analysis should too.**

ADR-010 colocates specs with features. ADR-008's reintroduction
process (threat-model delta required at Gate 1) has a natural home for
the delta only if security analysis lives with the feature.

</div>

**Date:** 2026-05-07 · **Authors:** Eidetic Labs · **Related:** [ADR-008](./008-experimental-gates), [ADR-009](./009-repo-structure), [ADR-010](./010-modular-specs), [ADR-011](./011-cross-cutting-extraction), [ADR-015](./015-adversarial-conformance-and-model-certification), [ADR-016](./016-storage-immutability-enforcement), [ADR-017](./017-amendment-to-adr-011-cids-as-core)

## Context

ADR-010 commits the project to modular per-topic specs that
**colocate with features**: experimental specs live at
`experimental/<feature>/spec.md`, alongside the feature's code,
tests, migrations, integration docs, and conformance vectors. The
pattern produces clear ownership.

Security documentation does not follow that pattern.

<div className="stigmem-grid">

<div><h4>Protocol-level lives at <code>spec/security/</code></h4><p>Unified risk register, scenarios, hardening guide, advisories, disclosure policy.</p></div>
<div><h4>Per-feature analysis is scattered</h4><p>R-15 is about §21 lazy instruction discovery, but its content lives in the protocol-level threat model. R-16/R-17 are about §23 RTBF tombstones; same pattern. R-21 (worm vector) is cross-cutting. R-23 (admin storage tampering) is cross-cutting at protocol level.</p></div>

</div>

Four consequences:

<div className="stigmem-fields">

<div>
<dt>Problem</dt>
<dt><span className="stigmem-fields__type">Effect</span></dt>
<dd>Why it matters</dd>
</div>

<div>
<dt>Asymmetry with ADR-010</dt>
<dt><span className="stigmem-fields__type">structural</span></dt>
<dd>A spec migrates with the feature it specifies; the security analysis for that same feature does not. This breaks the "feature self-contained at <code>experimental/&lt;feature&gt;/</code>" principle.</dd>
</div>

<div>
<dt>Discoverability</dt>
<dt><span className="stigmem-fields__type">user-facing</span></dt>
<dd>Reading the lazy-instruction-discovery directory tells you what the feature does and how it's tested but not what its risks are.</dd>
</div>

<div>
<dt>Reintroduction friction</dt>
<dt><span className="stigmem-fields__type">workflow</span></dt>
<dd>When a feature graduates per ADR-008's gates, its security analysis must be located, evaluated, and updated. Locating is harder than it should be.</dd>
</div>

<div>
<dt>Threat-model bloat</dt>
<dt><span className="stigmem-fields__type">readability</span></dt>
<dd>As experimental features accumulate, their entries in the protocol-level threat model accumulate too. Cross-cutting risks become buried.</dd>
</div>

</div>

## Decision

We restructure security documentation into two tiers, mirroring the
ADR-010 spec model.

### Tier 1 · Protocol-level security artifacts (the hub)

Live at `spec/security/` (canonical source) and render in `docs/Secure/`
per ADR-005 IA.

<div className="stigmem-fields">

<div>
<dt>Artifact</dt>
<dt><span className="stigmem-fields__type">Scope</span></dt>
<dd>Content</dd>
</div>

<div>
<dt><code>spec/security/threat-model.md</code></dt>
<dt><span className="stigmem-fields__type">unified risk register</span></dt>
<dd>All R-XX entries with status (Mitigated / Residual / Open / Accepted). Cross-cutting risks (R-19 HLC, R-20 embedding poisoning, R-22 supply chain, R-23 admin storage tampering) include full analysis here. Per-feature risks include a brief summary and link to <code>experimental/&lt;feature&gt;/security.md</code>.</dd>
</div>

<div>
<dt><code>spec/security/architecture.md</code></dt>
<dt><span className="stigmem-fields__type">protocol architecture</span></dt>
<dd>Capability tokens, audit log, federation trust, mTLS, key rotation. Cross-cutting; not feature-specific.</dd>
</div>

<div>
<dt><code>spec/security/disclosure.md</code></dt>
<dt><span className="stigmem-fields__type">policy</span></dt>
<dd>Security disclosure policy and procedures.</dd>
</div>

<div>
<dt><code>spec/security/advisories/</code></dt>
<dt><span className="stigmem-fields__type">per-disclosure</span></dt>
<dd>Per-disclosure advisory artifacts.</dd>
</div>

<div>
<dt><code>spec/security/scenarios.md</code></dt>
<dt><span className="stigmem-fields__type">operator narratives</span></dt>
<dd>Plain-English narratives. May reference per-feature scenarios; does not duplicate them.</dd>
</div>

</div>

### Tier 2 · Per-feature security artifacts (colocated)

Each `experimental/<feature>/` gains a `security.md` with YAML
frontmatter:

```yaml
---
feature: <feature-name>
spec_id: Spec-X<N>-<Topic>
status: Experimental | Stable | Deprecated
applies_to: stigmem v0.9.0-preview
last_updated: YYYY-MM-DD
---
```

Followed by sections:

<div className="stigmem-grid">

<div><h4>Owned risks</h4><p>Risks for which this feature is the primary subject. Mirrors the protocol-level threat-model format (Risk ID, STRIDE category, description, likelihood, impact, severity, control, status, mitigation).</p></div>
<div><h4>Contributed risks</h4><p>Risks for which this feature is a contributor but not the primary subject. Cross-link to the canonical entry.</p></div>
<div><h4>Threat model delta</h4><p>For ADR-008 Gate 1. If this feature graduates back to core, what changes about the protocol's threat surface?</p></div>
<div><h4>Operator scenarios</h4><p>Plain-English narratives where this feature creates risk for operators.</p></div>
<div><h4>Conformance pointers</h4><p>Which categories of the ADR-015 adversarial corpus exercise this feature's security properties.</p></div>
<div><h4>Reintroduction gates</h4><p>Specific evidence required for this feature's security work to pass each ADR-008 gate. Owners check these off as gates are met.</p></div>
<div><h4>Cross-references</h4><p>Spec (<code>experimental/&lt;feature&gt;/spec.md</code>), ADRs, master-checklist sections.</p></div>

</div>

### Owned vs contributed risks

<div className="stigmem-keypoint">

**A risk has exactly one owning feature and zero or more contributing features.**

The owning feature's <code>security.md</code> carries the canonical
analysis; contributors carry brief cross-listings that link to the
canonical entry. Cross-cutting risks (those with no single owning
feature) live exclusively at protocol level: R-01 through R-04, R-09,
R-10–R-14, R-19, R-20, R-22, R-23.

</div>

Initial per-feature owned-risk mapping:

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Owning feature</span></dt>
<dd>Per-feature location</dd>
</div>

<div>
<dt>R-15 (instruction-scope injection)</dt>
<dt><span className="stigmem-fields__type">lazy-instruction-discovery</span></dt>
<dd><code>experimental/lazy-instruction-discovery/security.md</code></dd>
</div>

<div>
<dt>R-16 (RTBF compliance gap)</dt>
<dt><span className="stigmem-fields__type">tombstones</span></dt>
<dd><code>experimental/tombstones/security.md</code></dd>
</div>

<div>
<dt>R-17 (RTBF propagation drift)</dt>
<dt><span className="stigmem-fields__type">tombstones</span></dt>
<dd><code>experimental/tombstones/security.md</code></dd>
</div>

<div>
<dt>R-18 (CID integrity)</dt>
<dt><span className="stigmem-fields__type">none — CID is core per ADR-017</span></dt>
<dd><code>spec/security/threat-model.md</code> (cross-cutting)</dd>
</div>

<div>
<dt>R-21 (agent feedback-loop worm)</dt>
<dt><span className="stigmem-fields__type">cross-cutting</span></dt>
<dd><code>spec/security/threat-model.md</code> (cross-cutting; touches lazy-instruction-discovery + memory-garden-acl)</dd>
</div>

</div>

R-18 belongs to core (CIDs are core per ADR-017); R-21 is structurally
cross-cutting (the worm vector spans multiple features by design).

### Status track for risks

Risks track status independently per the existing threat-model format:
**Mitigated / Residual / Open / Accepted**. A risk owned by an
experimental feature can be `Open` in the protocol composition without
affecting other features' status.

### Cross-reference conventions

Mirroring ADR-010's spec cross-references:

<div className="stigmem-fields">

<div>
<dt>Direction</dt>
<dt><span className="stigmem-fields__type">Convention</span></dt>
<dd>Example</dd>
</div>

<div>
<dt>Protocol → per-feature</dt>
<dt><span className="stigmem-fields__type">link to canonical</span></dt>
<dd><em>R-15 — see <code>experimental/lazy-instruction-discovery/security.md</code> for canonical analysis. <strong>Status:</strong> Open in v0.9.0-preview.</em></dd>
</div>

<div>
<dt>Per-feature → protocol</dt>
<dt><span className="stigmem-fields__type">registration note</span></dt>
<dd><em>This risk is registered as R-15 in <code>spec/security/threat-model.md</code>. The canonical risk-register entry is here.</em></dd>
</div>

<div>
<dt>Cross-feature contribution</dt>
<dt><span className="stigmem-fields__type">contributor note</span></dt>
<dd><em>This feature contributes to R-21 (worm vector); the canonical analysis is in <code>spec/security/threat-model.md</code>. This feature's contribution: the lazy-instruction-discovery code path is one of the writer-key escalation paths the worm vector exploits.</em></dd>
</div>

</div>

### CI validation

A `scripts/check_security_documentation.py` validator runs in CI.

<div className="stigmem-grid">

<div><h4>Risk entries resolve</h4><p>Every R-XX in <code>spec/security/threat-model.md</code> has full analysis at protocol level OR points at an existing <code>experimental/&lt;feature&gt;/security.md</code>.</p></div>
<div><h4>Per-feature security.md is anchored</h4><p>Every <code>experimental/&lt;feature&gt;/security.md</code> exists for a feature that exists in <code>experimental/</code>.</p></div>
<div><h4>Owned risks are registered</h4><p>Every "owned risk" in a per-feature doc has a corresponding entry in the protocol-level threat model.</p></div>
<div><h4>Cross-references resolve</h4><p>No broken file paths or risk IDs.</p></div>
<div><h4>Frontmatter validates</h4><p>Schema-checked at CI time.</p></div>

</div>

### What this ADR does NOT change

<div className="stigmem-grid">

<div><h4>Risk register format unchanged</h4><p>Per-risk status, STRIDE category, etc. This ADR moves <em>where</em> risk analyses live, not how they're structured.</p></div>
<div><h4>ADRs are not relocated</h4><p>ADR-003, ADR-016, etc. stay in the ADR sequence; they reference per-feature security docs as needed.</p></div>
<div><h4>Protocol-level primitives stay protocol-level</h4><p>Audit log, capability model, other protocol-level security primitives.</p></div>
<div><h4>Disclosure / advisory templates stay</h4><p>Protocol-level.</p></div>

</div>

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Keep all security analysis at protocol level (status quo)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Asymmetric with ADR-010; per-feature analysis becomes harder to find as features accumulate. Threat model bloats with per-feature noise.</dd>
</div>

<div>
<dt>Keep protocol-level but improve organization (per-feature subsections)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Improves discoverability but doesn't solve colocation. When a feature is in <code>experimental/</code>, its security analysis still doesn't travel with it.</dd>
</div>

<div>
<dt>Split security entirely per-feature (no protocol-level threat model)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Cross-cutting risks (R-19, R-22, R-23) don't decompose to a single feature. A forest of per-feature docs without a hub is unreadable.</dd>
</div>

<div>
<dt>Auto-generate the protocol-level threat model from per-feature docs</dt>
<dt><span className="stigmem-fields__type">deferred</span></dt>
<dd>Cross-cutting risks need authored prose that doesn't decompose; partial auto-generation is more complex than worthwhile. Reconsider if the threat model becomes large enough.</dd>
</div>

<div>
<dt>Use ADRs themselves as per-feature security documents</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>ADRs document decisions; security documents are living analysis that evolves. ADRs are immutable once accepted; security docs must be updatable. Conflating them breaks both.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Per-feature self-containment</h4><p>A reader of <code>experimental/lazy-instruction-discovery/</code> sees spec, code, tests, <em>and</em> security analysis. No fishing.</p></div>
<div><h4>Reintroduction discipline</h4><p>ADR-008's Gate 1 (threat-model delta) has a natural home — drafted in the per-feature <code>security.md</code> and merged into the protocol-level threat model on graduation.</p></div>
<div><h4>Threat model stays focused</h4><p>Concentrates on cross-cutting risks and architecture. Per-feature noise lives with the feature.</p></div>
<div><h4>Cross-references are first-class</h4><p>CI validates risk IDs and file paths; tooling can build a dependency graph between cross-feature contributions.</p></div>
<div><h4>Symmetric with ADR-010</h4><p>"Open the feature directory; everything is there" applies to spec and security alike.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Migration cost</h4><p>Existing per-feature R-XX entries need to be relocated. ~1–2 days mechanical work.</p></div>
<div><h4>Cross-cutting analysis discipline</h4><p>Authors must decide whether a new risk is feature-owned or cross-cutting. Mistakes are easy. Mitigation: protocol-level is the default home for ambiguous cases.</p></div>
<div><h4>Two-place updates for contributed risks</h4><p>A risk contributed-to by multiple features requires updates in the canonical location plus brief notes in each contributor's <code>security.md</code>. Mitigation: contribution notes are short by convention; CI catches broken cross-refs.</p></div>
<div><h4>Tooling overhead</h4><p>CI validator needs to be written. ~3–5 days. Same approach as ADR-010's spec generator.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-SEC-DOC-1</code> · per-feature drifts from protocol threat model</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A per-feature <code>security.md</code> could record an R-XX as Mitigated while protocol-level still says Open. Mitigation: CI validator checks risk status consistency across the canonical entry and any cross-listings.</dd>
</div>

<div>
<dt><code>R-SEC-DOC-2</code> · cross-cutting risk misclassified as feature-owned</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A risk that should be at protocol level lands in a per-feature doc; cross-cutting analysis is lost. Mitigation: ADR-008 gate review checks for this; security maintainer catches misclassifications during quarterly review.</dd>
</div>

<div>
<dt><code>R-SEC-DOC-3</code> · feature deprecation orphans security analysis</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A feature deprecated per ADR-013 may have unresolved risks. Mitigation: deprecated features' <code>security.md</code> remains with a Deprecated banner; risks reviewed for migration to protocol level if still relevant.</dd>
</div>

<div>
<dt><code>R-SEC-DOC-4</code> · empty or stale per-feature docs</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A new feature might land with <code>security.md</code> that's just frontmatter. Mitigation: ADR-008 gate 1 requires populated security.md before reintroduction; new experimental features must ship with at least an "Owned risks: none identified" + "Open questions" section.</dd>
</div>

</div>

## Implementation plan

Phase B deliverable, sequenced after ADR-010's spec migration (so the
layout is stable) and after ADR-016's threat additions land (so R-23
and related are in place).

<ol className="stigmem-steps">
<li><strong>Step 1 · Author per-feature <code>security.md</code> files (~1–2 days).</strong> For each <code>experimental/&lt;feature&gt;/</code>: identify owned risks from the protocol-level threat model, extract entries into <code>security.md</code> with frontmatter, replace the protocol-level entry with a brief summary + cross-link, add Threat-model-delta, Conformance pointers, Reintroduction gates sections.</li>
<li><strong>Step 2 · Refactor protocol-level threat model (~3–5 days).</strong> Update <code>spec/security/threat-model.md</code> to reflect the new structure: full content for cross-cutting risks; brief summaries for feature-owned risks with cross-links. Update <code>docs/Secure/Threat-model/</code> Docusaurus pages to render the same structure.</li>
<li><strong>Step 3 · CI validator (~3–5 days).</strong> Write <code>scripts/check_security_documentation.py</code>. Validate frontmatter, cross-references, status consistency. Add CI step on every PR.</li>
<li><strong>Step 4 · Documentation (~1–2 days).</strong> Update <code>CONTRIBUTING.md</code> on where security analysis goes for new features. Update ADR-008 (or note in the gate-1 process) that gate-1 deliverable lands in per-feature <code>security.md</code>. Update master-checklist §3 (artifact mapping). Operator-facing <code>docs/Secure/where-security-analysis-lives.md</code>.</li>
</ol>

**Total:** ~1–2 weeks across Phase B, parallel with other security work.

## Open questions

<div className="stigmem-fields">

<div>
<dt>Question</dt>
<dt><span className="stigmem-fields__type">Recommendation</span></dt>
<dd>Reasoning</dd>
</div>

<div>
<dt>Should <code>security.md</code> be required or optional for new experimental features?</dt>
<dt><span className="stigmem-fields__type">required</span></dt>
<dd>ADR-008 gate 1 is required for graduation; the natural place for the delta is <code>security.md</code>. Empty/stub is acceptable at experimental status; populated is required for graduation.</dd>
</div>

<div>
<dt>Should per-feature <code>security.md</code> use the same YAML frontmatter as <code>spec.md</code>?</dt>
<dt><span className="stigmem-fields__type">similar shape, different fields</span></dt>
<dd>Both carry <code>feature</code>, <code>status</code>, <code>applies_to</code>, <code>last_updated</code>. Spec has <code>spec_id</code>, <code>version</code>, <code>depends_on</code>. Security has <code>reviewed_by</code>, <code>risk_count</code>, etc.</dd>
</div>

<div>
<dt>Does this pattern extend to operator runbooks, performance benchmarks, compliance evidence?</dt>
<dt><span className="stigmem-fields__type">probably yes; out of scope here</span></dt>
<dd>ADR-018 establishes the precedent; future ADRs can apply the same pattern to other artifact classes if the symmetry helps.</dd>
</div>

</div>

## Amendment process

Changes to this ADR require sign-off per ADR-001 §Contributor approval
rule. Common amendment cases: changing the per-feature schema (e.g.,
adding new sections); adding new artifact classes that follow the
colocation pattern; changing what's classified as cross-cutting vs
feature-owned.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
