# ADR-001: Versioning, phases, and stability commitments

<p className="stigmem-meta"><span>6 min read</span><span>Accepted</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The versioning scheme for Stigmem: SemVer for externally-facing labels
using the PEP 440 / semver alpha-beta-rc convention as the canonical
pre-release spelling (`v0.9.0a1` → `v0.9.0b1` → `v1.0.0rc1` → `v1.0.0`
→ `v1.x` → `v2.0.0-experimental.N`), internal phase markers kept out of
public surfaces, and a CI gate (`scripts/check_version_consistency.py`)
that fails any PR introducing version drift. External operator
validation is the 1.0 GA stability gate (see §1.0 GA stability gate).

</div>

<div className="stigmem-keypoint">

**Status: Accepted.**

Folds in ADR-019 (de-contrition consolidation, 2026-06-06): the PEP 440 / semver alpha-beta-rc convention is the canonical pre-release spelling — `v0.9.0a1` (alpha) → `v0.9.0b1` (beta) → `v1.0.0rc1` (release candidate) → `v1.0.0` (GA). Git tags use the `v`-prefixed PEP 440 shorthand; tooling emits the bare PEP 440 string (PyPI/pyproject) and the hyphenated semver string (npm/Helm). A normalizer maps both spellings to one canonical key in `scripts/check_version_consistency.py`. The surface inventory lives in `release/version-surfaces.yaml` (validated by `scripts/validate_version_surfaces.py`), not in this ADR. The original [ADR-019](./archive/019-amendment-to-adr-001-prerelease-version-strings) text is retained in `docs/adr/archive/` for history.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** `stigmem/plans/strengthening-plan.md`, `LIMITATIONS.md`, migration post

## Context

In the first week of public release, the project shipped under five
different version states simultaneously:

<div className="stigmem-fields">

<div>
<dt>Source</dt>
<dt><span className="stigmem-fields__type">Version label</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt><code>README.md</code></dt>
<dt><span className="stigmem-fields__type">v1.0 stable</span></dt>
<dd>"Phase 7 (substrate)"</dd>
</div>

<div>
<dt><code>pyproject.toml</code></dt>
<dt><span className="stigmem-fields__type"><code>1.0.0rc1</code></span></dt>
<dd></dd>
</div>

<div>
<dt><code>SECURITY.md</code></dt>
<dt><span className="stigmem-fields__type">v1.0-rc</span></dt>
<dd></dd>
</div>

<div>
<dt><code>spec/security/threat-model.md</code></dt>
<dt><span className="stigmem-fields__type">v1.1-draft</span></dt>
<dd></dd>
</div>

<div>
<dt>Recent commits</dt>
<dt><span className="stigmem-fields__type">v2.0 migration</span></dt>
<dd>Migration guide and release notes</dd>
</div>

</div>

This inconsistency was the visible symptom of a deeper issue. The
"v1.0" label was withdrawn because several controls our threat model
identified as required for that release — mTLS, audit log, rate
limits, key expiry, capability validation — were still in flight.

The follow-up review surfaced an even more fundamental problem:
stigmem had never had a real release. The version labels v0.2 through
v2.0 that appeared in `spec/`, `versioned_docs/`, and CHANGELOG
entries described internal development checkpoints, not tagged
releases anyone deployed in production. The project was carrying a
multi-version history it hadn't earned. Naming those checkpoints as
"previous releases" overstated project maturity in the same way the
v1.0 announcement did.

<div className="stigmem-keypoint">

**Important distinction.**

The spec *content* under those labels is real product specification —
it is reviewed and migrated forward into `v0.9.0-preview`, not
deleted. Only the implied release chronology is being corrected.

</div>

**v0.9.0-preview is therefore declared as the *first build* of
stigmem.** The canonical version line begins here. Prior version
*markers* (v0.2 through v2.0) labeled development checkpoints, not
tagged releases — they are not part of the SemVer chronology. The
spec *content* under those markers is real protocol specification; it
is reviewed section by section against actual implementation and
migrated forward into the v0.9.0-preview canonical spec (per
master-checklist §4.3a). Earlier evolutionary spec files move to
`spec/archive/evolution/` as reference material *after* their content
has been reviewed and forward-migrated, with header pointers to the
canonical equivalents. The spec is preserved and improved, not
archived as history.

We also adopted internal "phase" markers (Phase 7, Phase 12) for
sprint planning, and these appeared in externally-facing documents —
README, threat model, SECURITY.md. Adopters do not know what "Phase
12" means, and the inconsistency made the project look like an
internal initiative rather than a public release.

A federated agent-memory protocol earns trust over years, not weeks.
We want version labels that mean what they say, enforceable in CI,
with a clean separation between externally-facing version names and
internally-facing sprint markers — and a clean starting point that
doesn't carry imaginary release history.

## Decision

We adopt the following versioning scheme.

### Externally-facing version names — SemVer

We will use [Semantic Versioning 2.0.0](https://semver.org/) for all
externally-facing version labels.

<div className="stigmem-fields">

<div>
<dt>Label</dt>
<dt><span className="stigmem-fields__type">Wire-format</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>v0.9.0a1</code> … <code>v0.9.0aN</code></dt>
<dt><span className="stigmem-fields__type">unstable</span></dt>
<dd>Alpha series — the first build line. Pre-stable; not for adversarial deployment. Breaking changes during the window are expected and called out in the changelog.</dd>
</div>

<div>
<dt><code>v0.9.0b1</code> … <code>v0.9.0bN</code></dt>
<dt><span className="stigmem-fields__type">unstable</span></dt>
<dd>Beta series as hardened-core work lands.</dd>
</div>

<div>
<dt><code>v1.0.0rc1</code> … <code>v1.0.0rcN</code></dt>
<dt><span className="stigmem-fields__type">frozen at v1.0</span></dt>
<dd>Release candidates after the beta line is feature-complete. RC is announced alongside the 1.0 GA external-operator validation (see §1.0 GA stability gate). Bug-fixes only.</dd>
</div>

<div>
<dt><code>v1.0.0</code></dt>
<dt><span className="stigmem-fields__type">stable</span></dt>
<dd>General availability. Wire-format committed. Backwards compatibility guaranteed within the v1.x line.</dd>
</div>

<div>
<dt><code>v1.x.x</code></dt>
<dt><span className="stigmem-fields__type">stable</span></dt>
<dd>Patches and additive changes that preserve v1.0 wire format.</dd>
</div>

<div>
<dt><code>v2.0.0-experimental.N</code></dt>
<dt><span className="stigmem-fields__type">forward-compat with v1.x</span></dt>
<dd>Re-introduction of cut features, one at a time, behind feature flags. Defaults off.</dd>
</div>

<div>
<dt><code>v2.0.0</code></dt>
<dt><span className="stigmem-fields__type">stable</span></dt>
<dd>Future major release. Wire-format breaking changes permitted; will not happen until at least three external operators are running v1.x in production.</dd>
</div>

</div>

### Internally-facing sprint markers — phases

Phases (Phase 7, Phase 12, etc.) remain valid as internal sprint
markers and may appear in commit messages, internal planning docs, and
the strengthening plan. They **must not** appear in:

<div className="stigmem-grid">

<div><h4>Top-level public files</h4><p>README · LICENSE · LIMITATIONS · SECURITY · ROADMAP.</p></div>
<div><h4>Released package metadata</h4><p><code>pyproject.toml</code> · <code>package.json</code>.</p></div>
<div><h4>The docs site</h4><p><code>docs.stigmem.dev</code>.</p></div>
<div><h4>Threat-model surfaces</h4><p>Threat model · scenarios · operator-facing security documents.</p></div>
<div><h4>Release notes</h4><p>Or any changelog entries.</p></div>
<div><h4>External announcements</h4><p>Blog posts, social media, talks.</p></div>

</div>

### Stability commitments per release

<div className="stigmem-fields">

<div>
<dt>Line</dt>
<dt><span className="stigmem-fields__type">Promise</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Pre-1.0 (<code>v0.9.x</code>, <code>v1.0.0-rc.N</code>)</dt>
<dt><span className="stigmem-fields__type">no guarantee</span></dt>
<dd>Breaking changes documented in the changelog under a <code>BREAKING</code> section. Operators pin to specific versions; auto-upgrade is not safe.</dd>
</div>

<div>
<dt><code>v1.0.0</code> and <code>v1.x</code></dt>
<dt><span className="stigmem-fields__type">stable</span></dt>
<dd>Wire format and public Python API are stable. Removing a public API requires a deprecation in v1.x followed by removal in v2.0. New features are additive.</dd>
</div>

<div>
<dt><code>v2.0.0-experimental.N</code></dt>
<dt><span className="stigmem-fields__type">independent</span></dt>
<dd>Each experimental feature has its own lifecycle. May be promoted to v1.x as additive (no breaking change) or wait for v2.0.0 stable.</dd>
</div>

</div>

### 1.0 GA stability gate — external operator validation

External operator validation is a precondition for declaring **1.0
stability**, not for pre-1.0 feature graduation. Pre-1.0 feature
graduation is governed by the internal-quality bar in
[ADR-008](./008-experimental-gates); external soak was relocated here
during the de-contrition consolidation (2026-06-06) because external
validation gating 1.0 is legitimate, whereas gating every pre-1.0
graduation deadlocks the roadmap (nothing graduates until external
testers exist, but external testers won't engage a product whose
features are all held pre-graduation).

<div className="stigmem-keypoint">

**Declaring `v1.0.0` GA requires external operator validation.**

</div>

<div className="stigmem-grid">

<div><h4>Independent operators</h4><p>At least one external operator (not a stigmem contributor) runs the candidate in a real workload during the RC window, with public bug reporting in the stigmem GitHub issues.</p></div>
<div><h4>RC-gated</h4><p>The external-operator validation runs against the <code>v1.0.0rcN</code> series — a behaviorally-frozen candidate, not a moving target. GA (<code>v1.0.0</code>) does not ship until the validation closes.</p></div>
<div><h4>Wire-format freeze</h4><p>The wire format is committed at GA; the external validation is the evidence that the committed surface holds under a workload the authors did not write.</p></div>

</div>

This gate is a **stability-tier** gate: it scales the rigor of
external sign-off to the version line that actually carries a
backwards-compatibility promise. Pre-1.0 lines carry no such promise
(see §Stability commitments per release), so they do not carry the
external precondition.

### Version-consistency enforcement

A CI check (`scripts/check_version_consistency.py`) reads the canonical
version from `pyproject.toml` and asserts that every other version
string in the repository agrees.

<div className="stigmem-grid">

<div><h4><code>README.md</code></h4><p>Release banner, install instructions.</p></div>
<div><h4><code>package.json</code></h4></div>
<div><h4>Docusaurus config</h4><p><code>docs/docusaurus.config.js</code>.</p></div>
<div><h4>All spec frontmatter</h4></div>
<div><h4><code>SECURITY.md</code></h4><p>"Applies to" line.</p></div>
<div><h4>Threat model</h4><p>"Applies to" line.</p></div>
<div><h4>Scenarios</h4><p>"Applies to" line.</p></div>
<div><h4><code>LIMITATIONS.md</code></h4><p>"Applies to" line.</p></div>

</div>

The check fails the PR on any disagreement.

### Contributor approval rule (project-wide)

The team is two contributors, including the founder. The approval rule
for ADRs, ADR amendments, and PRs is:

<div className="stigmem-keypoint">

**Sign-off on any ADR (or amendment) and on any PR through Phase B requires *either* two contributors *or* the founder alone.**

</div>

Founder solo-approval exists because the project has a small team and
one contributor's unavailability would otherwise stop work entirely.
The founder takes responsibility for the validation discipline
whenever they sign off alone — the guardrail that two-person review
provides against AI-velocity-outrunning-validation (per the v1.0
retraction narrative) lives with the founder when they approve solo.
This is a deliberate exchange: review surface is reduced to the
founder's individual judgment in those cases; the founder owns the
consequences.

This rule applies to:

<div className="stigmem-grid">

<div><h4>ADR acceptance</h4><p>Proposed → Accepted.</p></div>
<div><h4>ADR amendments</h4><p>Any changes after acceptance, per each ADR's Amendment process.</p></div>
<div><h4>PR review through Phase B</h4><p>The strengthening-plan period during which review discipline is most acute.</p></div>
<div><h4>Threat-model deltas</h4><p>Per ADR-008 Gate 1.</p></div>
<div><h4>Any other process step</h4><p>That requires "two contributors' sign-off."</p></div>

</div>

Documents that reference "two contributors" sign-off should be read as
"two contributors or the founder alone."

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why rejected</dd>
</div>

<div>
<dt>Keep the v1.0 / v2.0 dual-track and clarify with banners</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The migration post commits to repositioning v1.0 publicly; continuing to advertise both labels would re-create the original confusion. The v0.9.0-preview reset is the cleanest correction.</dd>
</div>

<div>
<dt>Use CalVer (<code>2026.05.0</code>) instead of SemVer</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>CalVer works for projects whose meaningful unit is "what shipped this month." Stigmem's meaningful unit is "what's the wire-format compatibility surface." SemVer maps to that question; CalVer doesn't.</dd>
</div>

<div>
<dt>Skip the <code>-preview</code> suffix and version <code>v0.9.0</code> directly</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The suffix is deliberate signal: it tells package managers (PyPI, npm) to treat this as a pre-release that pinned upgrades won't auto-pick up. Bare <code>v0.9.0</code> would silently upgrade installs that haven't pinned.</dd>
</div>

<div>
<dt>Drop phase markers entirely</dt>
<dt><span className="stigmem-fields__type">rejected for internal use</span></dt>
<dd>Phases are useful sprint-tracking shorthand internally and there's no harm in them as long as they don't leak. The leakage is the problem, not the existence.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Single source of truth</h4><p>Anyone reading the project knows exactly what <code>v0.9.0-preview</code> means, what it commits to, and what it doesn't.</p></div>
<div><h4>External communication</h4><p>Adopters share a vocabulary. "When does mTLS-default ship?" has a single answer (<code>v0.9.x</code>); "when is wire format stable?" has a single answer (<code>v1.0.0</code>).</p></div>
<div><h4>CI enforcement</h4><p>Version drift becomes a hard error, not a culture norm. Future releases cannot accidentally re-create the five-version-state problem.</p></div>
<div><h4>Roadmap clarity</h4><p>The public roadmap can use version labels that match what gets shipped.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Discipline cost</h4><p>Every pull request now checks version-string consistency. Mechanical, but real.</p></div>
<div><h4>No "we'll just call it v1.0 for the announcement"</h4><p>This ADR commits the project to version labels that match validation status.</p></div>
<div><h4>Phase markers in internal docs require care</h4><p>Anyone writing a doc that <em>might</em> end up externally visible must check whether phase references are appropriate.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-DOC-1</code></dt>
<dt><span className="stigmem-fields__type">accepted</span></dt>
<dd>Version strings exist in places not enumerated above (e.g. embedded as Python module constants, in test fixtures). The CI check must be expanded as new locations are introduced. Mitigation: keep the check's grep patterns broad and run it on every PR.</dd>
</div>

<div>
<dt><code>R-DOC-2</code></dt>
<dt><span className="stigmem-fields__type">accepted</span></dt>
<dd>External documentation hosted off-repo (blog posts, slide decks, talks) can drift from the canonical version. Mitigation: announce the convention in the migration post; add a one-line "Versioning conventions" section to the docs front page.</dd>
</div>

</div>

### Migration

This ADR is effective immediately. Phase A of the strengthening plan
includes the version-sweep PR that brings every file into alignment
with the canonical version (`0.9.0`). The CI check ships in the same
PR.

## Open questions

<div className="stigmem-fields">

<div>
<dt>Question</dt>
<dt><span className="stigmem-fields__type">Recommended</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Should <code>-preview</code> releases be installable via <code>pip install stigmem</code> or require <code>--pre</code>?</dt>
<dt><span className="stigmem-fields__type"><code>--pre</code> only</span></dt>
<dd>Default installs on a system where someone hasn't read the docs go to whatever the latest stable is (currently nothing — they will see "no matching distribution found" until v1.0.0 ships, which is correct behavior).</dd>
</div>

<div>
<dt>What does an experimental feature's version look like when it's promoted from <code>v2.0.0-experimental.N</code> into <code>v1.x</code>?</dt>
<dt><span className="stigmem-fields__type">flag default-off</span></dt>
<dd>It joins the v1.x line with a feature flag default-off, and the experimental release is marked superseded. ADR-008 governs the promotion gates.</dd>
</div>

</div>

These are deferred to follow-up ADRs as the questions become live.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
