# ADR-013: Deprecation policy

> **Superseded by ADR-008.** Content folded into ADR-008 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>5 min read</span><span>Superseded by ADR-008</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

A feature's lifecycle is `stable → deprecated → removed`. Deprecation
in vX.Y means the feature is supported through all subsequent vX.*
releases and may be removed no earlier than vX+1.0 stable. Every
deprecation ships a defined artifact set: stability banner, migration
note, CHANGELOG entry, aggregate index row, and (for wire-format
deprecations) a documented `Stigmem-Version` upgrade path.

</div>

<div className="stigmem-keypoint">

**"Soon" is not a deprecation policy.**

The retraction of v1.0 / v2.0 was effectively a deprecation event with
no policy infrastructure behind it — features were announced as
stable, then removed without a defined notice window, replacement
path, or compatibility commitment. A written policy is part of
credibility, not an extra.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), [ADR-005](./005-docs-ia), [ADR-008](./008-experimental-gates), [ADR-012](./012-version-aware-feature-exposure), [ADR-014](./014-compatibility-matrix)

## Context

Three things have to be true for federation infrastructure to attract
serious operators.

<div className="stigmem-grid">

<div><h4>Predictable change</h4><p>Operators need to know how long they have to adapt to a deprecation before code stops working.</p></div>
<div><h4>Replacement clarity</h4><p>Every deprecated surface must point at what replaces it. Deprecating without a replacement is just a removal with extra steps.</p></div>
<div><h4>Compatibility commitment</h4><p>A written commitment about what stigmem will not break, scaled to project resources.</p></div>

</div>

Industry practice in the closest analogues:

<div className="stigmem-fields">

<div>
<dt>Project</dt>
<dt><span className="stigmem-fields__type">Policy</span></dt>
<dd>Fit for stigmem</dd>
</div>

<div>
<dt>Kubernetes</dt>
<dt><span className="stigmem-fields__type">12 months / 3 releases (stable), 9 / 3 (beta)</span></dt>
<dd>Right scale: predictable, explicit, decoupled from calendar dates.</dd>
</div>

<div>
<dt>Python</dt>
<dt><span className="stigmem-fields__type"><code>Deprecated since version X.Y</code></span></dt>
<dd>Removed typically two minor releases later; documented in PEPs.</dd>
</div>

<div>
<dt>Stripe</dt>
<dt><span className="stigmem-fields__type">indefinite support; warnings via response headers</span></dt>
<dd>Unattainable for a small team.</dd>
</div>

<div>
<dt>Node.js</dt>
<dt><span className="stigmem-fields__type">DEP-XXX codes; runtime warnings</span></dt>
<dd>Overkill for v0.9.0-preview.</dd>
</div>

<div>
<dt>AWS SDKs</dt>
<dt><span className="stigmem-fields__type">announcement → minor deprecation → next-major removal</span></dt>
<dd>Scheduled with explicit dates.</dd>
</div>

</div>

Kubernetes' version-distance approach is the right scale.

## Decision

### The policy

A feature in stigmem follows this lifecycle:

```
stable → deprecated → removed
                        (no earlier than next major)
```

<div className="stigmem-fields">

<div>
<dt>Stability tier</dt>
<dt><span className="stigmem-fields__type">Promise</span></dt>
<dd>Removal window</dd>
</div>

<div>
<dt>Stable</dt>
<dt><span className="stigmem-fields__type">no breaks in vX.*</span></dt>
<dd>Deprecated in vX.Y → supported through all vX.* → removable no earlier than vX+1.0.</dd>
</div>

<div>
<dt>Beta</dt>
<dt><span className="stigmem-fields__type">shorter commitment</span></dt>
<dd>Deprecated in vX.Y → removable in vX.Y+1. Beta features are not stable promises.</dd>
</div>

<div>
<dt>Experimental</dt>
<dt><span className="stigmem-fields__type">no commitment</span></dt>
<dd>May be removed without notice in the next release. Ship behind flags so users can try them, but no compatibility commitment applies.</dd>
</div>

</div>

### Required artifacts at deprecation

When a feature is marked `stability: deprecated` (per ADR-012), the
same PR ships:

<div className="stigmem-grid">

<div><h4>Updated banner</h4><p><code>&lt;Stability level="deprecated" /&gt;</code> with <code>removed_in:</code> and <code>replacement:</code> frontmatter values present.</p></div>
<div><h4>Migration note</h4><p>A section on the feature page describing how to move to the replacement.</p></div>
<div><h4>CHANGELOG entry</h4><p>Under <code>### Deprecated</code> for the release that introduces the deprecation.</p></div>
<div><h4>Aggregate index row</h4><p>In <code>Reference → Deprecated features</code> (auto-generated from frontmatter).</p></div>
<div><h4>Wire-format upgrade path</h4><p>If wire-format implications, a documented <code>Stigmem-Version</code> upgrade path per ADR-012.</p></div>

</div>

The PR cannot land if any of these artifacts are missing. CI validator
(extended from ADR-012's plugin) enforces.

### Compatibility commitment doc

A canonical `docs/docs/secure/compatibility-commitment.md` page states
the commitment in plain language.

<div className="stigmem-fields">

<div>
<dt>What's promised</dt>
<dt><span className="stigmem-fields__type">For which tier</span></dt>
<dd>Scope</dd>
</div>

<div>
<dt>No wire-format breaking changes through v1.x</dt>
<dt><span className="stigmem-fields__type">stable</span></dt>
<dd>Features in v1.0 honor this through the v1.x line.</dd>
</div>

<div>
<dt>Supported through the rest of the major version</dt>
<dt><span className="stigmem-fields__type">deprecated</span></dt>
<dd>Removed no earlier than the next major.</dd>
</div>

<div>
<dt>Subject to breaking changes in next minor</dt>
<dt><span className="stigmem-fields__type">beta</span></dt>
<dd>CHANGELOG entry per change.</dd>
</div>

<div>
<dt>Subject to breaking changes any release</dt>
<dt><span className="stigmem-fields__type">experimental</span></dt>
<dd>Use behind feature flags is at-your-own-risk.</dd>
</div>

<div>
<dt>Honored across at least one major version</dt>
<dt><span className="stigmem-fields__type">wire-format pinning</span></dt>
<dd>Per <code>Stigmem-Version</code> header in ADR-012.</dd>
</div>

</div>

The commitment doc is reviewed at every major release. Any tightening
or loosening goes through an ADR amendment.

### Aggregate `Deprecated features` page

A page at `Reference → Deprecated features` (or `Build → Deprecated
features` post-IA-restructure) is auto-generated from frontmatter and
lists, per release:

<div className="stigmem-grid">

<div><h4>Feature name</h4><p>With link to its current page.</p></div>
<div><h4><code>since</code></h4><p>When introduced.</p></div>
<div><h4><code>deprecated_since</code></h4><p>When marked deprecated.</p></div>
<div><h4><code>removed_in</code></h4><p>Planned removal version.</p></div>
<div><h4><code>replacement</code></h4><p>Link to replacement, if any.</p></div>
<div><h4>Migration summary</h4><p>One-line summary of the migration.</p></div>

</div>

Operators planning an upgrade have a single place to audit.

### Deprecation kinds

Three kinds, each with slightly different artifact requirements.

<div className="stigmem-fields">

<div>
<dt>Kind</dt>
<dt><span className="stigmem-fields__type">Example</span></dt>
<dd>Extra artifacts beyond the standard set</dd>
</div>

<div>
<dt>Wire-format deprecation</dt>
<dt><span className="stigmem-fields__type">spec section</span></dt>
<dd>Old wire format still accepted but warned. Plus: <code>Stigmem-Version</code> header behavior + spec amendment.</dd>
</div>

<div>
<dt>API surface deprecation</dt>
<dt><span className="stigmem-fields__type">SDK method</span></dt>
<dd>Method replaced in favor of a new one. Plus: SDK release note + runtime deprecation warning (where idiomatic for the language).</dd>
</div>

<div>
<dt>Operational deprecation</dt>
<dt><span className="stigmem-fields__type">env var / config key</span></dt>
<dd>Configuration replaced. Plus: startup log warning when the deprecated config is in use.</dd>
</div>

</div>

For wire-format deprecations specifically, the server emits a
`Stigmem-Deprecation: feature-name` response header on requests that
exercise the deprecated surface. SDKs surface this as a logged
warning.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Time-based deprecation ("supported for 12 months")</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Couples to calendar; conflicts with phase-gated convention; assumes a release cadence the project hasn't committed to. Version-distance is the right unit.</dd>
</div>

<div>
<dt>One-version-warning policy (vX.Y → vX.Y+1)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Too short. One-minor-version window is not enough for serious adopters to plan migrations.</dd>
</div>

<div>
<dt>Indefinite support (Stripe-style)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Accumulates dead surface and complexity; a small team cannot sustain it. The Kubernetes-style commitment is the right balance.</dd>
</div>

<div>
<dt>No formal policy; release notes only</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The retraction is existence proof that ad-hoc communication is insufficient. A written policy is part of credibility.</dd>
</div>

<div>
<dt>DEP-XXX-style numbered deprecations (Node.js)</dt>
<dt><span className="stigmem-fields__type">considered, rejected for v0.9</span></dt>
<dd>Overkill — the surface is small enough that named deprecations are more readable than numbered codes. Reconsider if deprecations exceed ~20 active items.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Operators plan upgrades</h4><p>With a clear contract about what will and won't break.</p></div>
<div><h4>Contributors have a clear bar</h4><p>For when to mark something deprecated and what to ship with it.</p></div>
<div><h4>Trust signaling</h4><p>A written deprecation policy is what credible infrastructure projects have. Its absence was part of what made retraction necessary.</p></div>
<div><h4>Aggregate auditability</h4><p>The auto-generated deprecated-features page is one source of truth for upgrade-planning audits.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>One-major-version support tail</h4><p>Every deprecated feature must continue working through the rest of its major-version line. Code complexity accumulates; mitigation is the version-distance bound (vs. indefinite).</p></div>
<div><h4>CI validator complexity</h4><p>Enforcing the artifact-set on every deprecation PR adds plugin logic. ~1 day to implement; small ongoing maintenance cost.</p></div>
<div><h4>Commitment doc as contract</h4><p>Once written and accepted, the doc binds the project. Mitigation: ADR amendment process exists; the commitment can be tightened or loosened with explicit reasoning.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-DEP-1</code> · deprecation backlog</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Features get marked deprecated but the team doesn't have capacity to actually remove them at vX+1. The queue grows. Mitigation: the deprecated-features page is a visible queue; phase-exit checklists at major releases include "deprecation queue review."</dd>
</div>

<div>
<dt><code>R-DEP-2</code> · deprecation-without-replacement</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A feature is deprecated for legitimate reasons but no replacement exists yet. Mitigation: policy requires <code>replacement:</code> to be set; if no replacement exists, the feature is <code>removed</code>, not <code>deprecated</code>. Hard removal is honest; deprecation-without-replacement is theater.</dd>
</div>

<div>
<dt><code>R-DEP-3</code> · third-party dependencies on experimental features</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Even though experimental features carry no commitment, third parties may build on them and complain when they break. Mitigation: feature-flag default-off (per ADR-002 + ADR-011) means third parties opt in explicitly; experimental status is a banner the user has to dismiss; policy documented at multiple levels.</dd>
</div>

</div>

## Implementation plan

Lands in master-checklist §4.3a (PR 2.5 — Docs site restructure and
reversion sweep) as the policy doc and CI infrastructure. Per-feature
deprecation tracking begins immediately and applies to the retraction.

<ol className="stigmem-steps">
<li>Write <code>docs/docs/secure/compatibility-commitment.md</code> with the commitment text.</li>
<li>Extend the ADR-012 frontmatter validator to require <code>removed_in:</code> and <code>replacement:</code> when <code>stability: deprecated</code>.</li>
<li>Add the auto-generated <code>Deprecated features</code> page (Docusaurus plugin extending the ADR-012 index generator).</li>
<li>Add <code>Stigmem-Deprecation</code> response-header support to the node (Phase B, slot near ADR-012's <code>Stigmem-Version</code> work).</li>
<li>Document the policy in <code>CONTRIBUTING.md</code> so contributors know what artifacts a deprecation PR requires.</li>
<li>Apply the policy retroactively: every v1.0 / v2.0 feature not making it to v0.9.0-preview gets either a <code>removed</code> entry in CHANGELOG or a <code>deprecated</code> annotation if preserved in <code>experimental/</code> for future reintroduction.</li>
</ol>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
