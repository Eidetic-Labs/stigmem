# ADR-005: Documentation information architecture

> **Superseded by ADR-020.** Content folded into ADR-020 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>5 min read</span><span>Superseded by ADR-020</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The docs site at `docs.stigmem.dev` is organized into four top-level
tabs — **Learn · Build · Operate · Secure**. Secure leads with the
risk register. The Reference and Community tabs dissolve into the
four canonical homes. The `audience` frontmatter taxonomy extends to
five values aligned with the tabs.

</div>

<div className="stigmem-keypoint">

**Status: Superseded by ADR-020.**

For a category where trust *is* the product, demoting security to a
sub-section sends the wrong signal. Secure is a peer tab.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-002](./002-v1-scope), [ADR-012](./012-version-aware-feature-exposure), [ADR-013](./013-deprecation-policy), [ADR-014](./014-compatibility-matrix); `stigmem/plans/master-checklist.md` §4.3a; `stigmem/analyses/docs-structure-review-2026-05-06.md`

## Context

The retracted v1.0 / v2.0 docs site organized content under five
top-level tabs (Learn / Build / Operate / Reference / Community)
with security buried as a sub-category under both Build and Operate.
The threat model — the project's strongest engineering artifact — sat
under Reference → Specification, two clicks deep.

<div className="stigmem-keypoint">

**The old structure communicated the wrong thing.**

> *Security is a thing to remember.*

The right structure for a federated agent-memory product
communicates:

> *Security is one of the four ways you engage with this product.*

</div>

Two further problems compounded the IA issue:

<div className="stigmem-grid">

<div>
<h4>Content duplication</h4>
<p>Many topics had parallel pages in <code>concepts/</code>, <code>security/</code>, and <code>spec/</code> with no canonical owner — three voices on Memory Garden, four on Recall, five on Federation.</p>
</div>

<div>
<h4>Post-retraction calibration</h4>
<p>Docusaurus config defaulted to <code>v1.1</code>, current was labeled <code>v2.0-draft</code>, and release notes covered only the retracted version. The site lied about project state.</p>
</div>

</div>

The reversion direction (master-checklist §4) declares
**v0.9.0-preview as the first build**. Prior version markers (v0.2
through v2.0) labeled development checkpoints, not tagged releases.
The spec *content* under those markers is real product specification
— it is reviewed and migrated forward into v0.9.0-preview, not
archived. The IA migration is therefore both a structural restructure
and a calibration to the actual canonical version, in parallel with
the section-by-section spec review.

## Decision

The docs site is organized into four top-level tabs.

<div className="stigmem-fields">

<div>
<dt>Tab</dt>
<dt><span className="stigmem-fields__type">Audience</span></dt>
<dd>Question it answers</dd>
</div>

<div>
<dt>Learn</dt>
<dt><span className="stigmem-fields__type">Evaluator · Integrator</span></dt>
<dd>"What is stigmem and why would I use it?"</dd>
</div>

<div>
<dt>Build</dt>
<dt><span className="stigmem-fields__type">Integrator</span></dt>
<dd>"How do I integrate with stigmem from my code?"</dd>
</div>

<div>
<dt>Operate</dt>
<dt><span className="stigmem-fields__type">Operator</span></dt>
<dd>"How do I run a stigmem node in production?"</dd>
</div>

<div>
<dt>Secure</dt>
<dt><span className="stigmem-fields__type">Security · Spec</span></dt>
<dd>"Can I trust this with my data and my federation peers?"</dd>
</div>

</div>

Each tab is self-contained — a reader can stay within one tab
without crossing to another for routine tasks.

### Tab content distribution

<div className="stigmem-grid">

<div>
<h4>Learn</h4>
<p>Overview · key concepts · quickstart · use cases · roadmap.</p>
</div>

<div>
<h4>Build</h4>
<p>API reference (auto-generated from OpenAPI) · SDK guides (Python / TypeScript / Go) · connector guides (MCP host adapters, runtime adapters, agent platforms, vault/note-taking) · integration patterns · tutorials · how-it-works data-flow pages.</p>
</div>

<div>
<h4>Operate</h4>
<p>Deployment guides · configuration reference · runbooks (per ADR-004) · storage backends · observability · CLI reference · compatibility matrix (per ADR-014).</p>
</div>

<div>
<h4>Secure</h4>
<p>Overview · threat model with risk register at the top · scenarios · specification (the protocol contract — moved here because spec <em>is</em> the security artifact) · security architecture · hardening guide · disclosure policy · advisories · compatibility commitment (per ADR-013) · deprecated features.</p>
</div>

</div>

### What dissolves

<div className="stigmem-fields">

<div>
<dt>Dissolved</dt>
<dt><span className="stigmem-fields__type">Redistribution</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Reference tab</dt>
<dt><span className="stigmem-fields__type">distributed</span></dt>
<dd>API Reference → Build · Specification → Secure · Experimental Features → auto-generated index of pages with <code>stability: experimental</code> (per ADR-012) · Release Notes → top-level surface · Architecture → split: deployment to Operate, data-flow to Build · Glossary → top-nav or footer.</dd>
</div>

<div>
<dt>Community sidebar</dt>
<dt><span className="stigmem-fields__type">distributed</span></dt>
<dd><code>security-disclosure.md</code> → Secure · <code>project-resources.md</code> → top-nav or footer.</dd>
</div>

<div>
<dt>Blog</dt>
<dt><span className="stigmem-fields__type">retained as top-nav</span></dt>
<dd>Stays alongside Docs / GitHub / Discord. Standard Docusaurus pattern.</dd>
</div>

</div>

### Frontmatter `audience` taxonomy

The `validate-audience` plugin extends from three to five accepted
values:

<div className="stigmem-fields">

<div>
<dt>Value</dt>
<dt><span className="stigmem-fields__type">Tab</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>Evaluator</code></dt>
<dt><span className="stigmem-fields__type">Learn</span></dt>
<dd>First-time visitor assessing whether stigmem fits their problem.</dd>
</div>

<div>
<dt><code>Integrator</code></dt>
<dt><span className="stigmem-fields__type">Build</span></dt>
<dd>Developer writing code against stigmem.</dd>
</div>

<div>
<dt><code>Operator</code></dt>
<dt><span className="stigmem-fields__type">Operate</span></dt>
<dd>Running a node in production.</dd>
</div>

<div>
<dt><code>Security</code></dt>
<dt><span className="stigmem-fields__type">Secure</span></dt>
<dd>Security engineer or compliance team auditing the design.</dd>
</div>

<div>
<dt><code>Spec</code></dt>
<dt><span className="stigmem-fields__type">Secure</span></dt>
<dd>Protocol contributor or spec implementer.</dd>
</div>

</div>

Backfill on every page is part of the docs-restructure PR
(master-checklist §4.3a).

### Cross-cutting principles

<ol className="stigmem-steps">
<li><strong>Lead Secure with the risk register.</strong> The most useful artifact for a security-minded evaluator is the current Mitigated / Residual / Open / Accepted status by version. That table goes at the top of the Threat Model page.</li>
<li><strong>Empty stubs are honest signaling.</strong> Pages like "Bug bounty" or "Compliance notes" can ship as stubs marked "coming in vX.Y" rather than be hidden until ready. An empty stub at a stable URL is more honest than a missing page.</li>
<li><strong>Every page in Operate and Secure lists the version it applies to</strong> via the <code>since</code> and <code>applies_to_version</code> frontmatter (per ADR-012).</li>
<li><strong>Security and operations cross-reference, but each is complete from its own audience's perspective.</strong> An operator should be able to deploy stigmem from Operate alone; a security engineer should be able to evaluate it from Secure alone.</li>
<li><strong>One canonical page per topic.</strong> Content deduplication pass resolves the existing 2-, 3-, and 4-way duplicates with <code>client-redirects</code> from retired URLs.</li>
</ol>

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Keep five tabs (Learn / Build / Operate / Secure / Reference)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Reference becomes a kitchen sink that re-creates the retracted v2.0 problem — content lives there because it doesn't fit anywhere else, accumulating until the IA collapses.</dd>
</div>

<div>
<dt>Three tabs (Learn / Build / Operate) with security under Operate</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>This is the conventional structure and it's what the retracted docs effectively did. For a category where trust <em>is</em> the product, demoting security to a sub-section sends the wrong signal.</dd>
</div>

<div>
<dt>Audience-named tabs ("For Operators," "For Security Engineers")</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Verb-named tabs (Learn, Build, Operate, Secure) parallel each other grammatically and signal action. Audience-named tabs imply rigid role boundaries; a developer might genuinely need both Build and Secure for the same feature. The audience field captures audience metadata at the page level instead.</dd>
</div>

<div>
<dt>Spec under Build</dt>
<dt><span className="stigmem-fields__type">considered</span></dt>
<dd>Spec is normative and developers do read it. Rejected because security engineers also read it (often more carefully), and the Build tab's primary audience is integration developers, not protocol implementers. Putting spec under Secure makes the protocol's normative status peer to threat-model and security architecture.</dd>
</div>

<div>
<dt>Versioned sidebar per tab from day one</dt>
<dt><span className="stigmem-fields__type">accepted (was rejected in earlier draft)</span></dt>
<dd>With <code>v0.9.0-preview</code> as the first build and the "snapshot every release" policy, activating Docusaurus versioning from the start is correct. Discipline on day one is cheaper than retrofitting at v1.0 stable.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Reader navigation matches reading intent</h4><p>Each audience finds their content in one tab.</p></div>
<div><h4>Security content has room to grow</h4><p>Threat-model versions, scenario docs, advisories, hardening guides, runbooks, post-mortems all have a natural home.</p></div>
<div><h4>Recruiting beacon</h4><p>Security-minded engineers — exactly the people we want as contributors — navigate to Secure first when they find the docs.</p></div>
<div><h4>Documentation discipline</h4><p>Every new feature has to answer "what does this add to each tab?" before it ships.</p></div>
<div><h4>Spec is no longer hidden</h4><p>Promoting Specification to Secure surfaces the protocol's normative content where evaluators look first.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Cross-references multiply</h4><p>"Hardening" appears in both Operate and Secure with different framings; the two pages must stay synchronized. Mitigation: one canonical page per topic, cross-linked.</p></div>
<div><h4>IA migration is expensive</h4><p>~1 day of structural moves, ~1 day of redirect setup, ~1 day of cross-link sweeps. Lands in master-checklist §4.3a.</p></div>
<div><h4>Stub maintenance</h4><p>A stub that says "coming in v1.0" but still says so two years later is a credibility leak. Mitigation: dated placeholder headers; remove or backfill on each release.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-IA-1</code> · tab content drifts in scope</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>The Operate tab might accumulate security content that should live in Secure. Mitigation: tab-ownership via <code>audience</code> frontmatter; PR review checks tab fit; <code>validate-audience</code> plugin enforces vocabulary.</dd>
</div>

<div>
<dt><code>R-IA-2</code> · nav crowding</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Each tab can hold roughly 10–15 visible items in the sidebar before navigation collapses. Mitigation: nest sub-pages under topics once a tab approaches that bound; do not add new top-level tabs to relieve pressure.</dd>
</div>

<div>
<dt><code>R-IA-3</code> · external links to retired URLs</dt>
<dt><span className="stigmem-fields__type">mitigated</span></dt>
<dd>Anyone who linked to <code>/v0.2/</code>, <code>/v1.1/</code>, <code>/reference/</code>, or <code>/community/</code> URLs gets a 404 unless redirected. Mitigation: <code>client-redirects</code> plugin already installed; every retired URL redirects to the closest canonical equivalent.</dd>
</div>

</div>

## Implementation plan

This ADR ships in Phase A of the strengthening plan, owned by the
team. Operationalized in master-checklist §4.3a (PR 2.5 — docs-site
restructure and reversion sweep).

<ol className="stigmem-steps">
<li>Restructure <code>docs/sidebars.js</code> for the four-tab navigation.</li>
<li>Move all <code>security/</code> pages into the unified Secure tab.</li>
<li>Move spec pages into Secure under "Specification."</li>
<li>Distribute Reference content per the table above.</li>
<li>Distribute Community content per the table above.</li>
<li>Extend <code>validate-audience</code> plugin to the five-value taxonomy; backfill <code>audience</code> on every page.</li>
<li>Set up <code>client-redirects</code> for every retired URL.</li>
<li>Activate <code>versioned_docs/</code> with <code>v0.9.0-preview</code> as the canonical default (per ADR-001 + ADR-012).</li>
</ol>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
