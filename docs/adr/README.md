# Architecture Decision Records (ADRs)

<p className="stigmem-meta"><span>4 min read</span><span>Reference</span><span>Updated 2026-06-06</span></p>

<div className="stigmem-lead">

**What you'll find here**

The full ADR index, the format Stigmem ADRs follow, the lifecycle
rules, and when to write a new one. ADRs are living documents — git
holds the full history, and a material decision change is recorded as
a visible dated amendment (or a superseding ADR), never a silent
overwrite.

</div>

<div className="stigmem-keypoint">

**One decision per ADR. Revise in the open — never silently overwrite a decision.**

Editorial changes (framing, folding, fixing stale references) are made
in place; git holds the full history. A material *decision* change is
recorded visibly — a dated `## Amendments` entry in the ADR, or a new
superseding ADR for a large reversal. This is the same model Stigmem
applies to facts: revisable, but supersession always leaves a record.

</div>

## What is an ADR?

**ADR** stands for **Architecture Decision Record** (sometimes
"Architectural Decision Record" — the terms are interchangeable).

An ADR is a short, dated, versioned document that captures **a single
significant decision**, why we made it, what alternatives we
considered, and what the consequences are. ADRs live in the repo
under `docs/adr/`, are numbered sequentially (`ADR-001`, `ADR-002`,
...), and form a versioned record of how the project's architecture
evolved.

The format was popularized by Michael Nygard in a 2011 blog post and
has become standard practice in infrastructure and platform projects.

## Why we use them

<div className="stigmem-grid">

<div>
<h4>Decisions get re-litigated</h4>
<p>Six months from now someone will ask "why did we move tombstones to experimental?" Without an ADR the answer lives in chat history. With one it lives in a versioned document with the reasoning intact.</p>
</div>

<div>
<h4>Contract for scope discipline</h4>
<p>When <code>ADR-002</code> says "v1 critical-path scope is exactly this list," any proposal to add something must either accept the constraint or write an amendment. The amendment requirement is productive friction.</p>
</div>

<div>
<h4>External adopters read them</h4>
<p>Threat models tell evaluators what we're worried about; ADRs tell them what we've decided and why. The combination is what credibility looks like in infrastructure projects.</p>
</div>

</div>

## Standard structure

Every ADR follows the same template:

```markdown
# ADR-NNN: Short noun phrase

**Status:** Proposed | Accepted | Superseded by ADR-NNN | Deprecated
**Date:** YYYY-MM-DD
**Authors:** name(s)
**Supersedes:** (if applicable) ADR-NNN
**Related:** (if applicable) ADR-NNN, links to other artifacts

## Context

What is the situation? What forces are at play? Why are we deciding this now?
Be specific. Name the constraints, the prior art, the deadline if there is one.

## Decision

The call we made, in active voice. "We will..."
Be specific. "We will use a federated architecture" is a slogan, not a decision.
"We will use mTLS-default federation with capability tokens scoped to
verb+object pairs" is a decision.

## Alternatives considered

What else did we look at, and why didn't we pick it?
This section is the institutional memory; future maintainers will thank you.

## Consequences

What becomes easier? What becomes harder? What new risks emerge?
Be honest about the costs. ADRs that only list benefits are marketing docs.
```

## Rules

<ol className="stigmem-steps">
<li><strong>ADRs are living; decisions are never silently overwritten.</strong> Editorial edits are made in place (git is the history). A material decision change is recorded as a dated <code>## Amendments</code> entry in the ADR, or a superseding ADR for a large reversal.</li>
<li><strong>One decision per ADR.</strong> Two related decisions get two ADRs that reference each other.</li>
<li><strong>Specific over abstract.</strong> ADRs that describe a <em>concrete</em> decision survive contact with implementation. ADRs that describe a <em>direction</em> don't.</li>
<li><strong>Numbered sequentially, never reused.</strong> If <code>ADR-005</code> is rejected, the number is still retired. Future ADRs are <code>ADR-006</code> onwards.</li>
<li><strong>Status and decision changes are recorded, not silent.</strong> When an ADR is superseded, the new ADR captures that with a <code>Supersedes:</code> reference; when a living ADR's decision changes in place, it gets a dated <code>## Amendments</code> entry.</li>
<li><strong>Approval: two contributors or the founder alone.</strong> Founder solo-approval exists because the project has a small team. When the founder signs off alone, they take responsibility for the validation discipline that two-person review otherwise provides. See ADR-001 § <em>Contributor approval rule</em> for the full statement.</li>
</ol>

## Lifecycle

```text
Proposed → discussion/review → Accepted → (later) Superseded by ADR-NNN
 ↘ (rare) Deprecated
```

Most ADRs are merged in `Accepted` status after pair review.
`Proposed` is used when a decision is in flight and not yet committed
— useful for getting feedback before locking in.

## When to write an ADR

<div className="stigmem-decision">

<div>
<h4>Write one when</h4>
<ul>
<li><strong>Architectural blast radius</strong> — affects more than one module, surface, or team.</li>
<li><strong>Non-obvious</strong> — a future reader might reasonably ask "why did they do it this way?"</li>
<li><strong>Has alternatives</strong> — a real choice between two or more options existed.</li>
<li><strong>Affects external contracts</strong> — wire format, API surface, security model, deployment story.</li>
<li><strong>Closes a documented gap</strong> — resolves a specific issue from an audit, threat model, or operator report.</li>
</ul>
</div>

<div>
<h4>Don't write one for</h4>
<ul>
<li>Routine implementation choices ("we used a Python <code>dict</code> here").</li>
<li>Library version bumps.</li>
<li>Bug fixes.</li>
<li>Local style or naming preferences.</li>
</ul>
</div>

</div>

## Cross-references

Stigmem ADRs frequently reference:

<div className="stigmem-grid">

<div>
<h4>Threat model</h4>
<p><a href="../../spec/security/threat-model.md">spec/security/threat-model.md</a> — for security decisions.</p>
</div>

<div>
<h4>Strengthening plan</h4>
<p><a href="../plans/strengthening-plan.md">docs/plans/strengthening-plan.md</a> — for delivery-timeline decisions.</p>
</div>

<div>
<h4>Audit findings</h4>
<p>e.g. <code>stigmem/openclaw/audit.md</code> — for ADRs that close specific issues.</p>
</div>

<div>
<h4>Other ADRs</h4>
<p>For decisions that build on or supersede earlier ones.</p>
</div>

</div>

When referencing, use relative links from the ADR's location.

## Index

<div className="stigmem-adr-grid">

<a className="stigmem-adr-card" href="./001-versioning">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-001</span>
<strong>Versioning, phases, and stability commitments</strong>
<span>The phased delivery model and how stability commitments map onto pre-1.0 alpha / beta / RC labels.</span>
</a>

<a className="stigmem-adr-card" href="./002-v1-scope">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-002</span>
<strong>v1 critical-path scope</strong>
<span>The exact list of features on the v1 critical path. Any addition requires an amendment.</span>
</a>

<a className="stigmem-adr-card" href="./003-prompt-injection">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-003</span>
<strong>Capability-based prompt-injection handling</strong>
<span><code>interpret_as: content | instruction</code> at the storage layer, capability tokens for cross-org instructions.</span>
</a>

<a className="stigmem-adr-card" href="./004-federation-observability">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-004</span>
<strong>Federation observability and incident response</strong>
<span>Per-peer drift tracking, pull-loop visibility, and the incident-response surface federation operators need.</span>
</a>

<a className="stigmem-adr-card" href="./006-batch-assert">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-006</span>
<strong>Batch-assert API for transactional multi-fact writes</strong>
<span>Atomic multi-fact write semantics. All-or-nothing commit, single audit entry.</span>
</a>

<a className="stigmem-adr-card" href="./008-experimental-gates">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-008</span>
<strong>Feature lifecycle, version exposure &amp; deprecation</strong>
<span>The five graduation gates (Gate 4 is an internal-quality bar), the <code>&lt;Stability/&gt;</code> + version-header exposure model (folds ADR-012), and the <code>stable→deprecated→removed</code> policy (folds ADR-013).</span>
</a>

<a className="stigmem-adr-card" href="./011-cross-cutting-extraction">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-011</span>
<strong>Plugin architecture &amp; CIDs-as-core (C1)</strong>
<span>Six cross-cutting plugins with a stable registration surface, plus CIDs as unconditional core (folds ADR-017).</span>
</a>

<a className="stigmem-adr-card" href="./015-adversarial-conformance-and-model-certification">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-015</span>
<strong>Adversarial conformance corpus and model certification</strong>
<span>The adversarial fixture suite plus model-certification framework that gates pre-stable releases.</span>
</a>

<a className="stigmem-adr-card" href="./016-storage-immutability-enforcement">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-016</span>
<strong>Storage immutability enforcement</strong>
<span>L1–L5 stack (append-only journal · SQLite triggers · CIDs · local hash chain · Sigstore Rekor) to mitigate admin-level tampering.</span>
</a>

<a className="stigmem-adr-card" href="./020-feature-owned-product-structure">
<span className="stigmem-adr-card__status">Accepted</span>
<span className="stigmem-adr-card__id">ADR-020</span>
<strong>Feature-owned product structure and projection model</strong>
<span>Feature records become the canonical source for specs, status, evidence, security, and feature changelogs; high-level docs become projections or hubs. Folds the docs IA (ADR-005), modular specs (ADR-010), compatibility matrix (ADR-014), and per-feature security taxonomy (ADR-018).</span>
</a>

</div>

## Archived / superseded

These ADRs were consolidated during the de-contrition pass
(2026-06-06). Their full text is retained in
[`docs/adr/archive/`](./archive/) as the historical record. Folded
ADRs point to the surviving ADR that now carries their substance;
ADR-007 is an archived settled migration with no fold target.

<div className="stigmem-adr-grid">

<a className="stigmem-adr-card" href="./archive/005-docs-ia">
<span className="stigmem-adr-card__status">Superseded by ADR-020</span>
<span className="stigmem-adr-card__id">ADR-005</span>
<strong>Documentation information architecture</strong>
<span>Four-tab IA + risk-register-first Secure tab. Folded into ADR-020 §12.</span>
</a>

<a className="stigmem-adr-card" href="./archive/007-argon2id">
<span className="stigmem-adr-card__status">Archived</span>
<span className="stigmem-adr-card__id">ADR-007</span>
<strong>Argon2id migration for API key hashing</strong>
<span>Settled one-time SHA-256→Argon2id migration. Durable fact lives in the security feature record.</span>
</a>

<a className="stigmem-adr-card" href="./archive/009-repo-structure">
<span className="stigmem-adr-card__status">Superseded by ADR-020</span>
<span className="stigmem-adr-card__id">ADR-009</span>
<strong>Repository file structure</strong>
<span>Top-level layout + adapter/plugin distinction. <code>experimental/</code>→metadata dissolution folded into ADR-020 §13.</span>
</a>

<a className="stigmem-adr-card" href="./archive/010-modular-specs">
<span className="stigmem-adr-card__status">Superseded by ADR-020</span>
<span className="stigmem-adr-card__id">ADR-010</span>
<strong>Modular per-topic specs with independent versioning</strong>
<span>Independent-SemVer-per-spec + generated <code>spec/PROTOCOL.md</code>. Folded into ADR-020 §9.</span>
</a>

<a className="stigmem-adr-card" href="./archive/012-version-aware-feature-exposure">
<span className="stigmem-adr-card__status">Superseded by ADR-008</span>
<span className="stigmem-adr-card__id">ADR-012</span>
<strong>Version-aware feature exposure</strong>
<span><code>&lt;Stability/&gt;</code> frontmatter + <code>Stigmem-Version</code>/<code>Stigmem-Beta</code> headers. Folded into ADR-008 §Version exposure.</span>
</a>

<a className="stigmem-adr-card" href="./archive/013-deprecation-policy">
<span className="stigmem-adr-card__status">Superseded by ADR-008</span>
<span className="stigmem-adr-card__id">ADR-013</span>
<strong>Deprecation policy</strong>
<span>The <code>stable→deprecated→removed</code> version-distance policy. Folded into ADR-008 §Deprecation policy.</span>
</a>

<a className="stigmem-adr-card" href="./archive/014-compatibility-matrix">
<span className="stigmem-adr-card__status">Superseded by ADR-020</span>
<span className="stigmem-adr-card__id">ADR-014</span>
<strong>Compatibility matrix</strong>
<span><code>docs/compatibility-matrix.yaml</code> as a projection over feature metadata. Folded into ADR-020 §10.</span>
</a>

<a className="stigmem-adr-card" href="./archive/017-amendment-to-adr-011-cids-as-core">
<span className="stigmem-adr-card__status">Superseded by ADR-011</span>
<span className="stigmem-adr-card__id">ADR-017</span>
<strong>Amendment: CIDs as core (not plugin)</strong>
<span>CIDs are unconditional core. Folded into ADR-011's plugins-vs-core scope.</span>
</a>

<a className="stigmem-adr-card" href="./archive/018-security-documentation-colocation">
<span className="stigmem-adr-card__status">Superseded by ADR-020</span>
<span className="stigmem-adr-card__id">ADR-018</span>
<strong>Per-feature security documentation colocation</strong>
<span>Owned-vs-contributed risk taxonomy. Folded into ADR-020 §11.</span>
</a>

<a className="stigmem-adr-card" href="./archive/019-amendment-to-adr-001-prerelease-version-strings">
<span className="stigmem-adr-card__status">Superseded by ADR-001</span>
<span className="stigmem-adr-card__id">ADR-019</span>
<strong>Amendment: PEP 440 / semver alpha-beta-rc convention</strong>
<span>Per-ecosystem pre-release spelling. Folded into ADR-001 as the canonical convention.</span>
</a>

</div>

Numbering is not reused: the gaps left by consolidation (005, 007,
009, 010, 012, 013, 014, 017, 018, 019) stay retired. New ADRs
continue from ADR-021.

---

*Reference: Michael Nygard, "Documenting Architecture Decisions"
(2011). The format has been refined by many open-source projects; we
use the standard five-section variant with a sixth "Alternatives
considered" section because it materially improves institutional
memory.*
