# ADR-008: Feature lifecycle, version exposure & deprecation

<p className="stigmem-meta"><span>7 min read</span><span>Accepted</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The full feature lifecycle: the five sequential gates a feature in
`experimental/` passes to reach a default-on, supported state
(threat-model delta, ADR, conformance vectors, an internal-quality
bar, documentation parity); how stability and version are exposed
inline and on the wire (the `<Stability/>` frontmatter convention plus
the `Stigmem-Version` / `Stigmem-Beta` headers); and the
`stable → deprecated → removed` deprecation policy.

</div>

<div className="stigmem-keypoint">

**Status: Accepted.**

Folds in ADR-012 (version-aware feature exposure) and ADR-013
(deprecation policy) as the "version exposure" and "deprecation"
halves of one feature-lifecycle decision (de-contrition consolidation,
2026-06-06). The process is costly enough that scope-creep is real
friction, but not so costly that legitimately-ready features get
permanently stuck.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), [ADR-002](./002-v1-scope), `stigmem/plans/version-prioritization.md`

## Context

ADR-002 cuts the v1.0 critical-path scope to a defensible minimum and
moves the rest of the codebase to `experimental/`. The cut features
are not deleted — they are in the codebase, importable with explicit
opt-in, ready to return.

The question this ADR answers: **what does it take for an experimental
feature to come back?**

<div className="stigmem-keypoint">

**A structured process keeps surface area from outrunning correctness.**

Without structure, surface area accumulates faster than correctness
can keep up. With a structured process, every feature's return is a
deliberate decision with measurable gates, and the v1.0 critical-path
stability is preserved.

</div>

The five gates below are calibrated to that balance: each produces a
concrete artifact, none requires more than ~1 week of focused work,
and all five together represent the cost of bringing a feature to v1.x
quality.

## Decision

A feature in `experimental/` returns to a default-on, supported state
only after passing all five gates in order.

### Gate 1 · Threat-model delta

The feature's author writes a delta document at
`spec/security/deltas/<feature>-threat-model.md` that addresses:

<div className="stigmem-grid">

<div><h4>New trust boundaries</h4><p>Introduced or modified by the feature.</p></div>
<div><h4>New STRIDE entries</h4><p>Per affected boundary.</p></div>
<div><h4>New risks</h4><p>R-XX entries · likelihood · impact · priority · mitigations.</p></div>
<div><h4>Existing risks affected</h4><p>e.g. does it widen R-05 prompt-injection surface?</p></div>

</div>

The delta is reviewed and accepted (two contributors or the founder
alone, per ADR-001 §Contributor approval rule), then merged into the
threat model. A feature without a threat-model delta does not pass
Gate 1.

### Gate 2 · ADR drafted and merged

A new ADR captures:

<div className="stigmem-grid">

<div><h4>Design decision</h4><p>The feature's shape in v1.x.</p></div>
<div><h4>Migration story</h4><p>Which APIs change · which deprecations apply.</p></div>
<div><h4>Alternatives considered</h4></div>
<div><h4>Consequences</h4><p>Including new risks.</p></div>

</div>

The ADR may explicitly supersede or amend earlier ADRs (most often
ADR-002, the scope contract). Amendments follow the ADR-001
§Contributor approval rule.

### Gate 3 · Conformance vectors

The feature's wire-format and behavioral contract are encoded at
`data/conformance/<feature>/`:

<div className="stigmem-fields">

<div>
<dt>Vector kind</dt>
<dt><span className="stigmem-fields__type">Path</span></dt>
<dd>What it covers</dd>
</div>

<div>
<dt>Positive</dt>
<dt><span className="stigmem-fields__type"><code>data/conformance/&lt;feature&gt;/</code></span></dt>
<dd>Correct behavior.</dd>
</div>

<div>
<dt>Negative</dt>
<dt><span className="stigmem-fields__type"><code>data/conformance/&lt;feature&gt;/</code></span></dt>
<dd>Validation failures, error responses.</dd>
</div>

<div>
<dt>Adversarial</dt>
<dt><span className="stigmem-fields__type"><code>data/conformance/&lt;feature&gt;/adversarial/</code></span></dt>
<dd>Malformed inputs, injected payloads, edge cases the threat-model delta identified.</dd>
</div>

</div>

Vectors are wired into CI as a blocking job. PRs that break the
conformance suite fail to merge.

### Gate 4 · Internal-quality bar

The feature meets a demonstrable internal-quality bar before it
graduates. No external sign-off is a precondition here.

<div className="stigmem-keypoint">

**Green against the internal harness, with the invariants intact.**

</div>

<div className="stigmem-grid">

<div><h4>Eval / regression harness</h4><p>The feature runs green in the internal eval-harness / regression suite against a representative workload.</p></div>
<div><h4>Structural CI guards</h4><p>All structural CI guards pass (writer-coverage, auth-coverage, transitive-reachability, and the other guards in <code>check.sh</code>).</p></div>
<div><h4>Invariants preserved</h4><p>The immutability, provenance, and audit invariants are demonstrably preserved — these are the properties that actually protect the product.</p></div>

</div>

<div className="stigmem-keypoint">

**External operator soak is a 1.0 GA criterion, not a per-feature gate.**

External operator validation was relocated to the 1.0 GA stability
gate in [ADR-001](./001-versioning) (de-contrition consolidation,
2026-06-06). Gating every pre-1.0 graduation on external testers
deadlocks the roadmap; gating 1.0 stability on external validation is
legitimate. See ADR-001 §1.0 GA stability gate.

</div>

### Gate 5 · Documentation parity

The feature has documentation across all four tabs (per
[ADR-020](./020-feature-owned-product-structure) §12, docs IA).

<div className="stigmem-fields">

<div>
<dt>Tab</dt>
<dt><span className="stigmem-fields__type">Required content</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Learn</dt>
<dt><span className="stigmem-fields__type">conceptual</span></dt>
<dd>If the feature affects the conceptual model, an explanation appears under Key Concepts.</dd>
</div>

<div>
<dt>Build</dt>
<dt><span className="stigmem-fields__type">integration</span></dt>
<dd>API reference · SDK examples · integration patterns.</dd>
</div>

<div>
<dt>Operate</dt>
<dt><span className="stigmem-fields__type">production</span></dt>
<dd>Configuration reference · hardening guidance · runbook updates if observability is affected.</dd>
</div>

<div>
<dt>Secure</dt>
<dt><span className="stigmem-fields__type">trust</span></dt>
<dd>Scenarios under <code>docs/security/scenarios.md</code> covering the feature's risks · threat-model delta linked.</dd>
</div>

</div>

If the feature doesn't need a presence in a given tab (e.g., a backend
driver doesn't need Learn coverage), that's documented in the ADR
(Gate 2).

### Order matters

<div className="stigmem-keypoint">

**Sequential, not parallel.**

Gate 1 (threat model) before Gate 2 (ADR), because the design decision
should be informed by the security analysis. Gate 3 (conformance)
before Gate 4 (internal-quality bar), because the harness verifies
against a behaviorally-defined contract, not a moving target. Gate 5
(docs) at the end, because docs against a still-changing implementation
rot before they ship.

</div>

### Reduced-gate paths

Some experimental features may not warrant the full process — for
example, a build-tooling improvement that's experimental only because
it wasn't tested on enough operating systems.

<ol className="stigmem-steps">
<li>The author proposes a reduced-gate path in their ADR (Gate 2).</li>
<li>Two contributors sign off explicitly on which gates are skipped and why.</li>
<li>The reduced-gate path is documented in the ADR for institutional memory.</li>
</ol>

**The default is all five gates. Skipping is exception, not rule.**

## Version exposure (folds ADR-012)

Stability and version-introduced state are visible inline on every
feature page and on the wire, so readers never have to parse a
CHANGELOG to know what they can rely on.

### Frontmatter convention

Every concept, feature, SDK, operator, security, and spec page carries:

```yaml
---
stability: stable | beta | experimental | deprecated
since: 0.9.0a1
applies_to_version: 0.9.0+
spec_section: §17 (optional, for spec-bound features)
removed_in: 2.0.0 (only on deprecated entries)
replacement: ./new-feature-page.md (only on deprecated entries)
---
```

The four stability tiers carry concrete promises:

<div className="stigmem-fields">

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
<dd>Still operational; replacement available. See the deprecation policy below for the removal timeline.</dd>
</div>

</div>

### `<Stability />` component

A custom Docusaurus React component renders a colored banner at the top
of every feature page from frontmatter:

```tsx
<Stability level="experimental" since="0.9.0a1" specSection="§21" />
```

For deprecated features, the banner additionally surfaces `removed_in`
and a link to the `replacement` page. A CI validator (the
`validate-audience` plugin, extended) asserts `stability:` is present,
`since:` matches SemVer, enum values are valid, `removed_in:` is
present iff `stability: deprecated`, and `replacement:` resolves. New
pages cannot land without correct stability metadata. The standalone
`experimental-features.md` page is replaced by an auto-generated index
of every page with `stability: experimental`.

### Stripe-pattern wire-format pinning

Two HTTP headers operate at the protocol level, parallel to the inline
page-level annotations.

<div className="stigmem-fields">

<div>
<dt><code>Stigmem-Version: 0.9.0a1</code></dt>
<dt><span className="stigmem-fields__type">client version pinning</span></dt>
<dd>Clients lock to a declared protocol version. Server honors it; future server versions stay backward-compatible to declared versions for at least one major release (per the deprecation policy below).</dd>
</div>

<div>
<dt><code>Stigmem-Beta: feature-name</code></dt>
<dt><span className="stigmem-fields__type">per-call opt-in</span></dt>
<dd>Clients opt into experimental wire-level features per-call — a server-side feature flag at the protocol level. Supported beta names live at <code>/v1/.well-known/stigmem</code> in a <code>betas</code> field. When a beta feature reaches <code>stable</code>, the header retires (returns <code>410 Gone</code>).</dd>
</div>

</div>

These map to Stripe's `Stripe-Version` and beta-gate headers and serve
the same purpose: per-client stability isolation without forcing
server-side state on every flag combination. SDKs pass both headers
through.

## Deprecation policy (folds ADR-013)

A feature's lifecycle is `stable → deprecated → removed`. A written
deprecation policy is part of credibility for infrastructure that
expects serious operators.

```
stable → deprecated → removed
                        (no earlier than next major)
```

<div className="stigmem-fields">

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

The version-distance model (Kubernetes-style) couples removal to
release distance, not calendar dates — consistent with phase-gated
conventions.

### Required artifacts at deprecation

When a feature is marked `stability: deprecated`, the same PR ships:
the updated `<Stability level="deprecated" />` banner with `removed_in:`
and `replacement:` set; a migration note on the feature page; a
CHANGELOG entry under `### Deprecated`; an auto-generated row in the
aggregate `Deprecated features` index; and, for wire-format
deprecations, a documented `Stigmem-Version` upgrade path. The CI
validator (extended from the version-exposure plugin) fails the PR if
any artifact is missing.

### Deprecation kinds

<div className="stigmem-fields">

<div>
<dt>Wire-format deprecation</dt>
<dt><span className="stigmem-fields__type">spec section</span></dt>
<dd>Old wire format still accepted but warned. The server emits a <code>Stigmem-Deprecation: feature-name</code> response header on requests exercising the deprecated surface; SDKs surface it as a logged warning. Plus spec amendment.</dd>
</div>

<div>
<dt>API surface deprecation</dt>
<dt><span className="stigmem-fields__type">SDK method</span></dt>
<dd>Method replaced. Plus SDK release note + runtime deprecation warning where idiomatic for the language.</dd>
</div>

<div>
<dt>Operational deprecation</dt>
<dt><span className="stigmem-fields__type">env var / config key</span></dt>
<dd>Configuration replaced. Plus a startup log warning when the deprecated config is in use.</dd>
</div>

</div>

A canonical compatibility-commitment page states the commitment in
plain language; it is reviewed at every major release, and any
tightening or loosening goes through an ADR amendment. The
deprecation-without-replacement case is not allowed: if no replacement
exists, the feature is `removed`, not `deprecated` — hard removal is
honest; deprecation-without-replacement is theater.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>No gates; let maintainer judgment decide</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Unstructured judgment lets surface area outrun correctness. The gates exist precisely to provide structure that survives the temptation to "just include this one feature."</dd>
</div>

<div>
<dt>Make per-feature graduation depend on an external operator soak</dt>
<dt><span className="stigmem-fields__type">rejected (relocated to 1.0 GA)</span></dt>
<dd>An external precondition on every pre-1.0 graduation deadlocks: nothing graduates until external testers exist, but external testers won't engage a product whose features are all held pre-graduation. The internal-quality bar (Gate 4) protects the invariants that matter; external validation moves to the 1.0 GA stability gate in ADR-001.</dd>
</div>

<div>
<dt>More gates (add an external auditor review)</dt>
<dt><span className="stigmem-fields__type">considered for v1.0.0 GA, not per feature</span></dt>
<dd>External auditing is a fit for major version releases; individual features get the threat-model delta plus conformance suite plus the internal-quality bar.</dd>
</div>

<div>
<dt>Time-based gates ("a feature can re-enter after 6 months")</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Time alone proves nothing; a feature that sat untouched for 6 months is no closer to ready. The gates are about evidence of readiness, not duration of waiting.</dd>
</div>

<div>
<dt>Combine all gates into a single "feature readiness review"</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Five distinct gates each produce a distinct artifact. A combined review tends to compress into a single conversation that ends in "looks good" — which is what we're trying to avoid.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Adopter clarity</h4><p>"Is feature X supported?" has a clean answer: either it has passed all five gates (supported) or it hasn't (experimental). No middle ground.</p></div>
<div><h4>Maintainer focus</h4><p>Re-introduction work is a known process with known artifacts. Authors of experimental features have a roadmap.</p></div>
<div><h4>Trust accumulation</h4><p>Each feature that passes the gates demonstrates the project's discipline. Over time, the gate process itself becomes a credibility signal.</p></div>
<div><h4>Resistance to scope-creep</h4><p>When someone proposes "let's just turn on §23 tombstones," the answer is "great, here are the five artifacts you need to produce." Most proposals don't survive Gate 1.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Per-feature re-introduction is real work</h4><p>Authors who shipped quickly into experimental will find the path to v1.x slower. This is a feature.</p></div>
<div><h4>Some features may never pass</h4><p>If a feature can't produce a credible threat-model delta, or no operator wants to soak it, that's information. Some experimental features will live in <code>experimental/</code> indefinitely.</p></div>
<div><h4>PR review overhead</h4><p>Every feature-promotion PR triggers gate-checking. Mitigation: gate status tracked in <code>experimental/&lt;feature&gt;/STATUS.md</code>; PR templates ask "does this PR change gate status?"</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-GATE-1</code> · gate gaming</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>An author who wants to ship faster might produce a perfunctory threat-model delta or wave the feature through the internal-quality bar without a representative workload. Mitigation: contributors' sign-off on each gate; the eval-harness and structural CI guards are machine-checked, not self-attested; community can call out perfunctory artifacts publicly.</dd>
</div>

<div>
<dt><code>R-GATE-2</code> · features stuck behind one gate</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A feature with clear threat model and ADR but a thin eval workload can't credibly clear Gate 4. Mitigation: the internal-quality bar is reachable by the author directly — building a representative workload and wiring the invariants into CI is in-scope work, not a dependency on an external party.</dd>
</div>

<div>
<dt><code>R-GATE-3</code> · gate inflation</dt>
<dt><span className="stigmem-fields__type">mitigated</span></dt>
<dd>Future ADRs might add more gates, making the process unsustainable. This ADR fixes the gates at five; adding requires an ADR-008 amendment with contributors' sign-off.</dd>
</div>

</div>

## Implementation plan

This ADR takes effect immediately on acceptance. No code changes are
required for v0.9.x — the gates apply to features attempting
re-introduction, of which there are none until at least v1.0.0 GA.

After v1.0.0 GA, the first feature to attempt re-introduction will
road-test the process. Lessons learned from that road-test feed an
ADR-008 amendment if needed.

## Amendments

- **2026-06-06 — de-contrition consolidation.** Gate 4 changed from a mandatory
  30-day external-operator soak to an internal-quality bar (eval/regression
  harness green + structural CI guards + immutability/provenance/audit
  invariants preserved); external-operator validation relocated to the 1.0 GA
  stability gate in ADR-001. Folded in ADR-012 (version-aware feature exposure)
  and folded in ADR-013 (deprecation policy). Rationale: the external-soak precondition
  deadlocked pre-1.0 graduation — nothing could graduate until an external
  tester existed, and testers won't engage features held in `experimental/`.
  The `0.x` version line is the pre-stability signal.

- **2026-06-07 — memory-garden-acl graduated to core (F-CONF-1).** The advanced
  garden ACL behavior moved from the experimental plugin into core: recall
  filtering is core/default-on (`settings.memory_garden_acl_recall_filter`,
  closing the cross-garden read leak) and the OIDC permission ceiling is a core
  opt-in setting (`settings.oidc_permission_ceiling`, default off — it caps
  permissions by garden membership, a hardened-profile posture). The
  `stigmem-plugin-memory-garden-acl` package is deprecated to a no-op and added
  to the discovery `GRADUATED_PLUGINS` denylist, so installed copies are ignored.
  This reverses the experimental-plugin status for these features per the
  "graduation = hardening" principle. (PRs #713, #714, and the package-retirement PR.)

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
