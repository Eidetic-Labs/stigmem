# ADR-010: Modular per-topic specs with independent versioning

> **Superseded by ADR-020.** Content folded into ADR-020 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>6 min read</span><span>Superseded by ADR-020</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The protocol stops being a single monolithic document. Each topic gets
its own spec file with its own version number and its own status
track. A meta-document names which combination of specs constitutes a
release.

</div>

<div className="stigmem-keypoint">

**A single version number cannot represent content with different maturity levels.**

The v1.0 spec marked §21–§25 Normative because shipping a single-
version spec required it. In reality those sections were experimental.
Modular specs let each section's status track independently.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Supersedes:** implicit monolithic spec model (`spec/stigmem-spec-vN.md`) · **Related:** [ADR-001](./001-versioning), [ADR-002](./002-v1-scope), [ADR-008](./008-experimental-gates), [ADR-009](./009-repo-structure)

## Context

The stigmem specification is currently maintained as a monolithic
document — `spec/stigmem-spec-v1.0.md`, `spec/stigmem-spec-v2.0.md`,
and so on — each version a single file containing all sections (§1
through §25). When the protocol moves forward, the entire document gets
a new version number, regardless of whether the change touched §3
(core fact model) or §23 (RTBF tombstones).

<div className="stigmem-grid">

<div><h4>§1–§20 were solid</h4><p>Federation primitives, capability tokens, manifests, audit log — genuinely production-ready in the v1.0 cut.</p></div>
<div><h4>§21–§25 were experimental</h4><p>§21 had a Critical/High security risk (R-15) with no structural mitigation; §23–§25 had operational gaps that hadn't been operator-validated.</p></div>
<div><h4>Single label, mixed content</h4><p>The monolithic version label can't selectively scope the maturity claim. Repositioning required reverting the whole document.</p></div>

</div>

The same pattern affects every draft: the entire spec churns when one
section changes, cross-references shift, and reviewers must distinguish
substantive protocol changes from incidental rewrites of unrelated
sections. The spec's version number is meaningful at the document
level but not at the granularity of individual features.

<div className="stigmem-keypoint">

**IETF, W3C, and MCP all solved this problem the same way.**

Modular specs, each independently versioned, composed via a
meta-document that names which combination of specs constitutes a
release. This ADR adopts that model.

</div>

## Decision

We restructure the spec from a single monolithic versioned document
into a set of modular specs, each covering a single topic, each
independently versioned, each with its own status track.

### Naming convention

Specs use the format `Spec-NN-Topic-Name` where `NN` is a stable
two-digit identifier and `Topic-Name` is descriptive:

<div className="stigmem-grid">

<div><h4><code>Spec-01-Core</code></h4></div>
<div><h4><code>Spec-05-Federation-Trust</code></h4></div>
<div><h4><code>Spec-09-Audit-Log</code></h4></div>
<div><h4><code>Spec-X1-Lazy-Instruction-Discovery</code></h4><p>X-prefix for experimental specs.</p></div>

</div>

**The number is stable across renames.** If a spec's topic name
changes, the number stays. New specs get the next available number;
numbers are never reused.

### Per-spec metadata

Every spec carries a YAML frontmatter block:

```yaml
---
spec_id: Spec-05-Federation-Trust
version: 1.0.0
status: Stable | Draft | Experimental | Superseded | Deprecated
applies_to: stigmem v0.9.0-preview
last_updated: 2026-05-06
supersedes: (if applicable) Spec-05-Federation-Trust v0.9.0
deprecated_by: (if applicable) Spec-NN-Replacement v1.0.0
depends_on:
  - Spec-01-Core >= 1.0.0
  - Spec-04-Manifests >= 1.0.0
---
```

This metadata is parseable; the meta-document (`spec/PROTOCOL.md`) is
generated from it.

### Status track per spec

Independent of any other spec's status.

<div className="stigmem-fields">

<div>
<dt>Status</dt>
<dt><span className="stigmem-fields__type">Meaning</span></dt>
<dd>What it implies for adopters</dd>
</div>

<div>
<dt>Draft</dt>
<dt><span className="stigmem-fields__type">in development</span></dt>
<dd>Under active development; contents may change incompatibly.</dd>
</div>

<div>
<dt>Experimental</dt>
<dt><span className="stigmem-fields__type">code exists, gates not passed</span></dt>
<dd>Implementation exists but has not passed ADR-008 gates; not for production federation.</dd>
</div>

<div>
<dt>Stable</dt>
<dt><span className="stigmem-fields__type">committed contract</span></dt>
<dd>Backwards compatibility guaranteed within the spec's major version.</dd>
</div>

<div>
<dt>Superseded</dt>
<dt><span className="stigmem-fields__type">replaced</span></dt>
<dd>Replaced by a newer version of the same spec; old version preserved for reference.</dd>
</div>

<div>
<dt>Deprecated</dt>
<dt><span className="stigmem-fields__type">slated for removal</span></dt>
<dd>An end-of-life date is published.</dd>
</div>

</div>

A given spec can be Stable while a sibling spec is Experimental. The
protocol release is the union of specs at their current versions.

### Independent semantic versioning per spec

Each spec follows SemVer 2.0.0 *for itself*. Spec-01-Core might be at
v1.2.0 while Spec-13-Capability-Instructions is at v0.4.0-draft.
Breaking changes within a spec require a major-version bump on that
spec only. The protocol release version (per ADR-001) is a separate,
higher-level commitment that names a specific combination of spec
versions.

### The meta-document

`spec/PROTOCOL.md` is the index and release-composition document:

```markdown
# Stigmem Protocol — v0.9.0-preview

## Core specs (v1.0 candidates)

| Spec                                            | Version    | Status           | Applies to       |
|-------------------------------------------------|------------|------------------|------------------|
| [Spec-01-Core](specs/01-core.md)                | 1.0.0-rc.0 | Stable candidate | v0.9.0-preview   |
| [Spec-04-Manifests](specs/04-manifests.md)      | 1.0.0-rc.0 | Stable candidate | v0.9.0-preview   |
| [Spec-05-Federation-Trust](specs/05-federation-trust.md) | 1.0.0-rc.0 | Stable candidate | v0.9.0-preview |

## Experimental specs (per ADR-008)

| Spec                                  | Version       | Status        | Located at                                                |
|---------------------------------------|---------------|---------------|-----------------------------------------------------------|
| Spec-X1-Lazy-Instruction-Discovery    | 0.4.0-draft   | Experimental  | experimental/21-lazy-instruction-discovery/spec.md        |
| Spec-X2-RTBF-Tombstones               | 0.6.0-draft   | Experimental  | experimental/23-rtbf-tombstones/spec.md                   |

## Protocol release composition

A stigmem protocol release is the named combination of specs at
specific versions.
```

This document is auto-generated from spec frontmatter on every commit.

### Initial decomposition

The current monolithic v1.0 spec decomposes into approximately 14 core
specs:

<div className="stigmem-fields">

<div>
<dt>Number</dt>
<dt><span className="stigmem-fields__type">Topic</span></dt>
<dd>Maps from</dd>
</div>

<div>
<dt>Spec-01</dt>
<dt><span className="stigmem-fields__type">Core data model</span></dt>
<dd>§1–§5</dd>
</div>

<div>
<dt>Spec-02</dt>
<dt><span className="stigmem-fields__type">Scopes and ACL</span></dt>
<dd>§3.5, §17 (core ACL only; advanced features in Spec-X5)</dd>
</div>

<div>
<dt>Spec-03</dt>
<dt><span className="stigmem-fields__type">HTTP API contract</span></dt>
<dd>API surface across §§</dd>
</div>

<div>
<dt>Spec-04</dt>
<dt><span className="stigmem-fields__type">Manifests and Rekor</span></dt>
<dd>§19.1–§19.2</dd>
</div>

<div>
<dt>Spec-05</dt>
<dt><span className="stigmem-fields__type">Federation trust</span></dt>
<dd>§19 (peer auth, replication)</dd>
</div>

<div>
<dt>Spec-06</dt>
<dt><span className="stigmem-fields__type">Capability tokens</span></dt>
<dd>§19.3</dd>
</div>

<div>
<dt>Spec-07</dt>
<dt><span className="stigmem-fields__type">Recall pipeline</span></dt>
<dd>§6, §20</dd>
</div>

<div>
<dt>Spec-08</dt>
<dt><span className="stigmem-fields__type">Quarantine garden</span></dt>
<dd>quarantine semantics</dd>
</div>

<div>
<dt>Spec-09</dt>
<dt><span className="stigmem-fields__type">Audit log</span></dt>
<dd>§22.3</dd>
</div>

<div>
<dt>Spec-10</dt>
<dt><span className="stigmem-fields__type">Hardening</span></dt>
<dd>§22.1, §22.2, §22.4, §22.6</dd>
</div>

<div>
<dt>Spec-11</dt>
<dt><span className="stigmem-fields__type">Replay protection</span></dt>
<dd>§22.5</dd>
</div>

<div>
<dt>Spec-12</dt>
<dt><span className="stigmem-fields__type">HLC bounded skew</span></dt>
<dd>new; per R-19</dd>
</div>

<div>
<dt>Spec-13</dt>
<dt><span className="stigmem-fields__type">Capability-based instructions</span></dt>
<dd>new; per ADR-003</dd>
</div>

<div>
<dt>Spec-14</dt>
<dt><span className="stigmem-fields__type">Batch assert</span></dt>
<dd>new; per ADR-006</dd>
</div>

</div>

Experimental specs map directly to deferred features in `experimental/`:

<div className="stigmem-fields">

<div>
<dt>Number</dt>
<dt><span className="stigmem-fields__type">Topic</span></dt>
<dd>Located at</dd>
</div>

<div>
<dt>Spec-X1</dt>
<dt><span className="stigmem-fields__type">Lazy instruction discovery</span></dt>
<dd><code>experimental/21-lazy-instruction-discovery/spec.md</code></dd>
</div>

<div>
<dt>Spec-X2</dt>
<dt><span className="stigmem-fields__type">RTBF tombstones</span></dt>
<dd><code>experimental/23-rtbf-tombstones/spec.md</code></dd>
</div>

<div>
<dt>Spec-X3</dt>
<dt><span className="stigmem-fields__type">Time-travel queries</span></dt>
<dd><code>experimental/24-time-travel/spec.md</code></dd>
</div>

<div>
<dt>Spec-X4</dt>
<dt><span className="stigmem-fields__type">Content-addressed IDs</span></dt>
<dd><code>experimental/25-cids/spec.md</code></dd>
</div>

<div>
<dt>Spec-X5</dt>
<dt><span className="stigmem-fields__type">Memory garden (advanced ACL)</span></dt>
<dd><code>experimental/17-memory-garden/spec.md</code></dd>
</div>

<div>
<dt>Spec-X6</dt>
<dt><span className="stigmem-fields__type">Source attestation</span></dt>
<dd><code>experimental/18-source-attestation/spec.md</code></dd>
</div>

<div>
<dt>Spec-X7</dt>
<dt><span className="stigmem-fields__type">Subscriptions</span></dt>
<dd><code>experimental/subscriptions/spec.md</code></dd>
</div>

</div>

The `Spec-X*` prefix marks experimental specs; they live alongside the
experimental code, not under `spec/specs/`.

### Cross-references

Specs reference each other by ID and version range:

> *This recall response format depends on `interpret_as` from Spec-13 ≥ 1.0.0.*

Cross-references that span the core/experimental boundary are tracked:
**a core spec MUST NOT have a hard dependency on an experimental spec.**
Experimental specs may depend on core specs.

### Layout on disk

```
spec/
├── README.md                                 # overview; points at PROTOCOL.md
├── PROTOCOL.md                               # auto-generated index of specs and release composition
├── CHANGELOG.md                              # changelog at the protocol-release level
├── specs/
│   ├── 01-core.md
│   ├── 02-scopes-and-acl.md
│   ├── ... (through Spec-14)
│   └── archive/                              # superseded versions of individual specs
│       └── 05-federation-trust-v0.9.md
├── design/                                   # existing — design docs and rationale
├── security/                                 # existing — threat model, scenarios
└── archive/
    ├── stigmem-spec-v0.2.md                  # historical monolithic specs
    ├── stigmem-spec-v1.0.md                  # superseded; preserved
    └── stigmem-spec-v2.0.md                  # superseded; preserved

experimental/
├── 21-lazy-instruction-discovery/
│   ├── STATUS.md
│   └── spec.md                               # Spec-X1 lives here, alongside the feature
├── 23-rtbf-tombstones/
│   ├── STATUS.md
│   └── spec.md                               # Spec-X2
└── ...
```

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Keep the monolithic versioned spec; just be more careful about Normative marking</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The v1.0 experience showed careful-marking-within-a-monolith is not a stable discipline. Modular specs make discipline structural rather than cultural.</dd>
</div>

<div>
<dt>Numbered specs only (Spec-001, Spec-002), no descriptive names</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>RFC-style opaque numbers are stable but require an index for orientation. The hybrid format gets both stability and readability.</dd>
</div>

<div>
<dt>Named specs only (Spec-Federation, Spec-Recall), no numbers</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Renames become painful; cross-references break. The number is the stable identifier.</dd>
</div>

<div>
<dt>One spec per section (one for §3.5, one for §3.6, etc.)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Too granular. Specs should correspond to coherent topics that evolve together; section numbers within the monolith are mostly artifacts of monolith-author convenience.</dd>
</div>

<div>
<dt>Defer the spec restructure until v1.0.0 GA</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The v0.9.0-preview reset is the natural inflection point. Doing it later means the monolithic v0.9.0-preview spec exists as an interim artifact that has to be migrated separately.</dd>
</div>

<div>
<dt>Adopt an existing spec-management framework (RFC tooling, W3C tooling)</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Each adds significant tooling overhead. The hand-rolled approach — markdown files with YAML frontmatter, a generated meta-document — is the lowest-overhead path. Revisit at v1.x if volume justifies it.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Selective experimental marking</h4><p>A new feature ships its own spec at status Experimental without affecting any other spec's status. No need to re-version the whole protocol.</p></div>
<div><h4>Selective rollback</h4><p>If an experimental spec turns out flawed, only that spec rolls back. Dramatically smaller scope than repositioning a whole monolith.</p></div>
<div><h4>Reviewable diffs</h4><p>Changes to Spec-22-Hardening don't churn the same file as unrelated Spec-17-Memory-Garden work. PR review focuses on actual semantic change.</p></div>
<div><h4>Spec colocates with feature</h4><p>Experimental specs live in <code>experimental/&lt;feature&gt;/spec.md</code> alongside the code that implements them. Reintroduction brings spec and code back together.</p></div>
<div><h4>Independent versioning communicates real maturity</h4><p>"Core specs are at v1.x; instruction discovery is at v0.4-draft" — information the monolithic version label couldn't carry.</p></div>
<div><h4>Cross-references become first-class</h4><p>Tooling can verify that <code>Spec-13 depends_on Spec-01 &gt;= 1.0.0</code> is satisfied; the meta-document fails generation if a dependency isn't met.</p></div>
<div><h4>Future experiments don't re-version the protocol</h4><p>Adding Spec-X8 doesn't require a v2.0 announcement; it just appears in the meta-document at its own version.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Migration effort</h4><p>Decomposing the current monolithic spec into ~14 core specs plus ~7 experimental specs is real work. Estimate: 1 week of focused effort by one contributor.</p></div>
<div><h4>Cross-reference discipline</h4><p>Internal references like "see §22.4" become "see Spec-10-Hardening section 4." Mechanical but ubiquitous; needs a sweep.</p></div>
<div><h4>Tooling overhead</h4><p>The auto-generated PROTOCOL.md needs a generator script; YAML frontmatter validation needs a CI check.</p></div>
<div><h4>External link rot</h4><p>Anyone who has linked to <code>spec/stigmem-spec-v1.0.md#section-22</code> has to update. Mitigation: redirects; v1 spec stays in <code>archive/</code>.</p></div>
<div><h4>Cognitive shift for contributors</h4><p>"Open the spec and grep" becomes "find the right spec, then read it." Slightly slower for casual lookup; meaningfully faster for focused work.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-SPEC-1</code> · spec sprawl</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Once it's easy to add a new spec, the project might end up with 30 specs covering tiny topics. Mitigation: each spec needs a clear thematic boundary; PR template asks "is this a new spec or an addition?" New specs with narrow scope require ADR justification.</dd>
</div>

<div>
<dt><code>R-SPEC-2</code> · dependency tangles</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Specs developing circular or deep dependencies become hard to evolve. Mitigation: dependency graph auto-generated and reviewed periodically; circular dependencies are CI-blocked.</dd>
</div>

<div>
<dt><code>R-SPEC-3</code> · PROTOCOL.md drift</dt>
<dt><span className="stigmem-fields__type">mitigated</span></dt>
<dd>If auto-generation breaks or stops running, the meta-document gets stale. Mitigation: PROTOCOL.md is generated as a CI step; non-trivially modified PROTOCOL.md fails CI (only the generator can write it).</dd>
</div>

<div>
<dt><code>R-SPEC-4</code> · status-track inflation</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Operators might find five status levels confusing. Mitigation: keep semantics tight; document each status explicitly with examples.</dd>
</div>

</div>

## Implementation plan

Early Phase B deliverable, sequenced after ADR-009's repo-structure
cuts land. ADR-009 creates `experimental/` and moves features there;
the spec restructure populates each `experimental/<feature>/` with its
`spec.md` and decomposes the core monolith.

<ol className="stigmem-steps">
<li><strong>Decompose (Day 1–2).</strong> Create <code>spec/specs/</code>. For each of the 14 core specs, extract relevant content from <code>stigmem-spec-v1.0.md</code> into <code>spec/specs/NN-topic-name.md</code> with frontmatter. For each experimental feature, place its spec at <code>experimental/&lt;feature&gt;/spec.md</code> with frontmatter.</li>
<li><strong>Cross-reference sweep (Day 3).</strong> Replace all internal <code>§N.M</code> references with <code>Spec-NN-Topic-Name section M.N</code>. Update threat model, scenarios.md, ADRs, and code docstrings.</li>
<li><strong>Tooling (Day 4).</strong> Write <code>scripts/generate_protocol_md.py</code> that reads spec frontmatter and produces <code>spec/PROTOCOL.md</code>. Add a CI step that runs the generator and fails on diff. Add YAML frontmatter validation.</li>
<li><strong>Archive (Day 5).</strong> Move <code>stigmem-spec-v0.2.md</code> through <code>stigmem-spec-v2.0.md</code> to <code>spec/archive/</code>. Banner archived monolithic specs with pointers to the new modular structure.</li>
<li><strong>Documentation (Day 5).</strong> Update <code>spec/README.md</code> to introduce the modular model. Update <code>docs/learn/</code> (per ADR-005) for new spec navigation.</li>
</ol>

## Open questions

<div className="stigmem-fields">

<div>
<dt>Question</dt>
<dt><span className="stigmem-fields__type">Recommendation</span></dt>
<dd>Reasoning</dd>
</div>

<div>
<dt>Should patch-level versioning (e.g., Spec-01@1.0.1) be permitted, or only major.minor?</dt>
<dt><span className="stigmem-fields__type">full SemVer per spec</span></dt>
<dd>Patch versions cover editorial fixes and clarifications; minor versions cover additions; major versions cover breaking changes.</dd>
</div>

<div>
<dt>What's the right granularity for "compatible spec versions" in the meta-document?</dt>
<dt><span className="stigmem-fields__type">exact for releases, ranges for development</span></dt>
<dd>Protocol release names exact versions today (<code>Spec-01@1.0.0</code>); development branches can name compatibility ranges (<code>Spec-01 &gt;= 1.0.0, &lt; 2.0.0</code>).</dd>
</div>

<div>
<dt>Should each spec carry its own changelog?</dt>
<dt><span className="stigmem-fields__type">yes, plus protocol-level</span></dt>
<dd>Per-spec changelog inside each spec file (<code>## Changelog</code> at the bottom); protocol-level CHANGELOG records release-composition events.</dd>
</div>

<div>
<dt>Does this affect publication to docs.stigmem.dev?</dt>
<dt><span className="stigmem-fields__type">slightly</span></dt>
<dd>Each spec gets its own docs page under the Build tab (per ADR-005). The auto-generated PROTOCOL.md is the spec section's index page. Mostly mechanical Docusaurus configuration.</dd>
</div>

</div>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
