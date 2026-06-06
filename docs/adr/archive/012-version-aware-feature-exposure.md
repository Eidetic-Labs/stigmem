# ADR-012: Version-aware feature exposure

> **Superseded by ADR-008.** Content folded into ADR-008 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>5 min read</span><span>Superseded by ADR-008</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Every feature page carries inline stability + since-version frontmatter
rendered by a `<Stability />` banner; the wire format supports
Stripe-style `Stigmem-Version` and `Stigmem-Beta` headers so clients
can pin to a declared protocol version and opt into experimental wire
features per call.

</div>

<div className="stigmem-keypoint">

**Readers should never have to parse a CHANGELOG to know what they can rely on.**

The retracted v1.0 / v2.0 docs had no inline signal of feature
stability or version-introduced state on most pages. The information
existed in <code>CHANGELOG.md</code>, <code>spec/CHANGELOG.md</code>,
and an <code>experimental-features.md</code> page — never inline where
readers actually looked.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), [ADR-005](./005-docs-ia), [ADR-008](./008-experimental-gates), [ADR-013](./013-deprecation-policy), [ADR-014](./014-compatibility-matrix); `stigmem/analyses/docs-structure-review-2026-05-06.md`

## Context

A reader on `concepts/federation/federation-trust.md`, `security/mtls.md`,
or `sdks/connectors/cursor.md` could not tell:

<div className="stigmem-grid">

<div><h4>When introduced</h4><p>What version first shipped the feature.</p></div>
<div><h4>Stability tier</h4><p>Stable, beta, experimental, deprecated.</p></div>
<div><h4>Normative spec</h4><p>Which spec section governs the feature.</p></div>
<div><h4>Version coupling</h4><p>Which node, SDK, and adapter versions are required.</p></div>

</div>

The version-aware exposure pattern *did* exist on `spec/` pages —
`**Status:** Stable (v1.0; v1.1 §2.8)` plus a `<details>Revisions</details>`
accordion. The pattern was correct and sophisticated; it was just
applied in only one directory.

Industry practice in the closest analogous projects:

<div className="stigmem-fields">

<div>
<dt>Project</dt>
<dt><span className="stigmem-fields__type">Pattern</span></dt>
<dd>What stigmem learns</dd>
</div>

<div>
<dt>Node.js</dt>
<dt><span className="stigmem-fields__type">stability header + "Added in"</span></dt>
<dd>Inline annotation + history table per API.</dd>
</div>

<div>
<dt>Kubernetes</dt>
<dt><span className="stigmem-fields__type">alpha/beta/stable tiers</span></dt>
<dd>Maturity tiers baked into API names; per-version docs.</dd>
</div>

<div>
<dt>Python stdlib</dt>
<dt><span className="stigmem-fields__type"><code>New in version X.Y</code></span></dt>
<dd>Inline blocks for new, changed, deprecated.</dd>
</div>

<div>
<dt>Stripe</dt>
<dt><span className="stigmem-fields__type">opt-in beta header</span></dt>
<dd>Version pinning via header; per-call beta opt-in.</dd>
</div>

<div>
<dt>MDN</dt>
<dt><span className="stigmem-fields__type">compatibility tables</span></dt>
<dd>Compatibility info on every API page.</dd>
</div>

</div>

## Decision

Adopt a Node.js-style inline pattern with Stripe-style protocol-level
versioning headers.

### Frontmatter convention

Every concept, feature, SDK, operator, security, and spec page carries:

```yaml
---
stability: stable | beta | experimental | deprecated
since: 0.9.0-preview
applies_to_version: 0.9.0+
spec_section: §17 (optional, for spec-bound features)
removed_in: 2.0.0 (only on deprecated entries)
replacement: ./new-feature-page.md (only on deprecated entries)
---
```

### Stability tier values

<div className="stigmem-fields">

<div>
<dt>Tier</dt>
<dt><span className="stigmem-fields__type">Promise</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>stable</code></dt>
<dt><span className="stigmem-fields__type">no breaks within major</span></dt>
<dd>Spec section normative. In production. Eval-covered. No breaking changes planned within the major version.</dd>
</div>

<div>
<dt><code>beta</code></dt>
<dt><span className="stigmem-fields__type">minor breaks possible</span></dt>
<dd>Spec normative. Feature-flagged or in early adopters. Minor breaking changes possible before next major.</dd>
</div>

<div>
<dt><code>experimental</code></dt>
<dt><span className="stigmem-fields__type">breaks expected</span></dt>
<dd>Implemented behind a flag. Spec section may be <code>draft</code>. Breaking changes expected. Use in production at your own risk.</dd>
</div>

<div>
<dt><code>deprecated</code></dt>
<dt><span className="stigmem-fields__type">marked for removal</span></dt>
<dd>Still operational; replacement available. See ADR-013 for removal timeline.</dd>
</div>

</div>

The `planned` value used in `concepts/features.md` does not become a
stability tier. Planned features live in `experimental/` or in
`ROADMAP.md`; they don't have feature pages yet.

### `<Stability />` Docusaurus component

A custom React component renders a colored banner at the top of every
feature page from frontmatter:

```tsx
<Stability level="experimental" since="0.9.0-preview" specSection="§21" />
```

Rendered as an inline alert with the stability label, the
since-version, and (when applicable) a link to the spec section. For
deprecated features, the banner additionally surfaces `removed_in` and
a link to the `replacement` page.

### Generalized revisions accordion

The pattern from spec pages — `<details><summary>Revisions before vX.Y</summary>...</details>` —
generalizes to any feature page that has version-introduced changes.
When a page's content changes meaningfully across versions, prior text
is preserved in a collapsed accordion sourced from the page's git
history or the canonical CHANGELOG entry.

Tooling: a small Docusaurus plugin that, given a page's frontmatter
`since`, can render an "earlier text from version-N" accordion when
the markdown source contains a `:::revisions vX.Y` directive.

### Stripe-pattern wire-format pinning

Two HTTP headers operate at the protocol level, parallel to inline
page-level annotations.

<div className="stigmem-fields">

<div>
<dt>Header</dt>
<dt><span className="stigmem-fields__type">Purpose</span></dt>
<dd>Behavior</dd>
</div>

<div>
<dt><code>Stigmem-Version: 0.9.0-preview</code></dt>
<dt><span className="stigmem-fields__type">client version pinning</span></dt>
<dd>Clients lock to a declared protocol version. Server honors it; future server versions stay backward-compatible to declared versions for at least one major release (per ADR-013).</dd>
</div>

<div>
<dt><code>Stigmem-Beta: feature-name</code></dt>
<dt><span className="stigmem-fields__type">per-call opt-in</span></dt>
<dd>Clients opt into experimental wire-level features per-call. Equivalent to a server-side feature flag at the protocol level. Supported beta names live at <code>/v1/.well-known/stigmem</code> in a <code>betas</code> field.</dd>
</div>

</div>

These map to Stripe's `Stripe-Version` and beta-gate headers and serve
the same purpose: per-client stability isolation without forcing
server-side state on every flag combination.

### CI validator

The `validate-audience` plugin extends to also validate:

<div className="stigmem-grid">

<div><h4><code>stability:</code> present</h4><p>On every page in <code>concepts/</code>, <code>sdks/</code>, <code>operators/</code>, <code>security/</code>, <code>spec/</code>.</p></div>
<div><h4><code>since:</code> matches SemVer</h4><p>Present and well-formed.</p></div>
<div><h4>Enum values</h4><p>Match the allowed enum (<code>stable | beta | experimental | deprecated</code>).</p></div>
<div><h4><code>removed_in:</code> iff deprecated</h4><p>Present iff <code>stability: deprecated</code>.</p></div>
<div><h4><code>replacement:</code> resolves</h4><p>Points to an existing page.</p></div>

</div>

CI fails on any violation. New pages cannot land without correct
stability metadata.

### Auto-generated experimental-features index

The standalone `experimental-features.md` page is replaced by an
auto-generated landing under Build that lists every page with
`stability: experimental`, sorted by spec section or since-version.
Hand-maintenance retires.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Per-page badges only, no protocol-level headers</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Page badges answer "what stability is this feature?" Headers answer "how do I lock my client to a version?" Different questions; the protocol-level answer can't live in docs alone.</dd>
</div>

<div>
<dt>Full Stripe-style calendar versioning (e.g., <code>2026-05-06</code>)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Too heavy for a v0.9.0-preview project. SemVer is sufficient until API-surface complexity warrants calendar versioning.</dd>
</div>

<div>
<dt>Separate stability site (e.g., <code>stability.stigmem.dev</code>)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Splitting the stability story from feature docs forces context-switching. Inline is the right model.</dd>
</div>

<div>
<dt>Markdown badges instead of a React component</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The component carries dynamic behavior (spec section links, replacement page lookups) that markdown badges can't do. The component is a one-time cost; markdown badges would be a permanent maintenance tax.</dd>
</div>

<div>
<dt>Source <code>since</code> from git history automatically</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Git history reflects when the <em>page</em> was created, not when the <em>feature</em> was introduced. Authors must declare <code>since</code> explicitly; CI can't infer it.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Reader trust</h4><p>Every feature page tells the reader the stability tier and since-version. No external lookup required.</p></div>
<div><h4>Stripe-style pinning</h4><p>Clients adopt newer server versions at their own pace without breaking. Reduces upgrade friction.</p></div>
<div><h4>Beta features ship faster</h4><p>Per-call opt-in via header lets experimental wire features reach early adopters without a server-side feature-flag config burden.</p></div>
<div><h4>Index auto-generates</h4><p>Retires the hand-maintained experimental-features page; one less surface to drift.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Every-release audit</h4><p>Stability and <code>since</code> annotations are now part of release discipline. Master-checklist §8.6 captures this as cross-phase ongoing work.</p></div>
<div><h4>Component implementation cost</h4><p>~1 day for <code>&lt;Stability /&gt;</code> + frontmatter validator + auto-gen index. Plugin tests are part of docs CI.</p></div>
<div><h4>Protocol-level header support</h4><p><code>Stigmem-Version</code> and <code>Stigmem-Beta</code> headers must be honored in the node. ~2 days, plus SDK pass-through, plus backward-compat tests. Slots in Phase B.</p></div>
<div><h4>Backfill cost</h4><p>~117 existing pages need stability metadata. ~3 days of mechanical sweep work.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-VAFE-1</code> · stability declarations rot</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A page marked <code>stable</code> may quietly become <code>beta</code> in practice if implementation drifts. Mitigation: stability-badge audit at every minor release; CI catches missing/invalid metadata but cannot detect semantic drift; quarterly drift check at the human-review level.</dd>
</div>

<div>
<dt><code>R-VAFE-2</code> · <code>Stigmem-Version</code> pinning creates implementation tail</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Supporting older protocol versions indefinitely accumulates complexity. Mitigation: ADR-013 deprecation policy bounds support to one major version after deprecation; older pinned versions hard-fail with explicit error after that.</dd>
</div>

<div>
<dt><code>R-VAFE-3</code> · <code>Stigmem-Beta</code> headers grow without bound</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>If every experimental wire feature gets a beta header that lives forever, the protocol surface bloats. Mitigation: when an experimental feature reaches <code>stable</code> per ADR-008 gates, the beta header retires (returns <code>410 Gone</code>); client-side use produces a deprecation warning header.</dd>
</div>

</div>

## Implementation plan

Lands in master-checklist §4.3a (PR 2.5 — Docs site restructure and
reversion sweep) as the docs-side adoption. Protocol-level header
support lands in Phase B (master-checklist §5.x).

<ol className="stigmem-steps">
<li>Add <code>&lt;Stability /&gt;</code> Docusaurus component under <code>docs/src/components/</code>.</li>
<li>Extend <code>validate-audience</code> plugin to validate <code>stability:</code>, <code>since:</code>, <code>applies_to_version:</code>, <code>removed_in:</code>, <code>replacement:</code>.</li>
<li>Backfill stability frontmatter on every page in <code>concepts/</code>, <code>sdks/</code>, <code>operators/</code>, <code>security/</code>, <code>spec/</code>.</li>
<li>Generalize the <code>&lt;details&gt;Revisions&lt;/details&gt;</code> accordion pattern; document the <code>:::revisions vX.Y</code> directive convention.</li>
<li>Replace <code>experimental-features.md</code> with an auto-generated index page.</li>
<li>Add <code>Stigmem-Version</code> and <code>Stigmem-Beta</code> header support to the node (Phase B).</li>
<li>Add SDK pass-through of both headers (Phase B).</li>
<li>Add <code>betas</code> field to <code>/v1/.well-known/stigmem</code> response (Phase B).</li>
<li>Document headers in spec §3 Wire Format and <code>Operate → Compatibility</code>.</li>
</ol>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
