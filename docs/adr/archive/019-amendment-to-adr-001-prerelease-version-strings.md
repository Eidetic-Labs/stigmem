# ADR-019: Amendment to ADR-001 — adopt PEP 440 / semver alpha-beta-rc convention for pre-release version strings

> **Superseded by ADR-001.** Content folded into ADR-001 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>5 min read</span><span>Superseded by ADR-001</span><span>Recorded 2026-05-08</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Replace the literal pre-release string "v0.9.0-preview" with the PEP 440
/ semver alpha-beta-rc convention across every version surface stigmem
emits. The first build of stigmem is **`v0.9.0a1`**. A separate YAML
manifest at `release/version-surfaces.yaml` carries the inventory of
which surfaces use which spelling.

</div>

<div className="stigmem-keypoint">

**The string "0.9.0-preview" normalizes to "0.9.0rc0".**

Any wheel built from <code>version = "0.9.0-preview"</code> lands on
PyPI as <code>stigmem 0.9.0rc0</code>. <code>pip show stigmem</code>
returns <code>Version: 0.9.0rc0</code>. The user-facing label
disappears at the Python packaging boundary, and worse, <code>rc</code>
implies imminent stability — the opposite of what the retraction post
communicates.

</div>

**Status:** Accepted (@offbyonce, 2026-05-08) · **Amends:** [ADR-001](./001-versioning) (Versioning, phases, stability commitments) · **Related:** [ADR-012](./012-version-aware-feature-exposure), [ADR-013](./013-deprecation-policy), [ADR-014](./014-compatibility-matrix)

## Context

ADR-001 (Accepted 2026-05-06) declared the literal string
**"v0.9.0-preview"** as the first build and established the
phase-to-version mapping. Subsequent operational work (Phase A PR 0
execution, 2026-05-08) surfaced two problems.

<div className="stigmem-fields">

<div>
<dt>Problem</dt>
<dt><span className="stigmem-fields__type">Effect</span></dt>
<dd>Why it matters</dd>
</div>

<div>
<dt>PEP 440 normalization</dt>
<dt><span className="stigmem-fields__type">"0.9.0-preview" → "0.9.0rc0"</span></dt>
<dd>"preview" disappears at the Python packaging boundary and is replaced with "rc0" — implying imminent stability, which is the opposite of what's being communicated.</dd>
</div>

<div>
<dt>No iteration convention</dt>
<dt><span className="stigmem-fields__type">no successor pattern</span></dt>
<dd>What follows "v0.9.0-preview" — "v0.9.0-preview-2"? "v0.9.1-preview"? Both PEP 440 and semver natively support iteration via <code>a1</code>, <code>a2</code>, <code>a3</code>, <code>b1</code>, <code>b2</code>, <code>rc1</code>, <code>rc2</code>.</dd>
</div>

</div>

A third consideration: ADR-014 (compatibility matrix) and ADR-013
(deprecation policy) both reference version strings as ordered
identifiers for compatibility windows. PEP 440 / semver provide a
strict-monotonic ordering. A "preview" label provides none.

## Decision

**Adopt PEP 440 / semver alpha-beta-rc convention for all pre-release
version strings.**

<div className="stigmem-fields">

<div>
<dt>Phase</dt>
<dt><span className="stigmem-fields__type">Original / Amended</span></dt>
<dd>Mapping</dd>
</div>

<div>
<dt>Phase A · reset, plugin infrastructure, per-feature plugins</dt>
<dt><span className="stigmem-fields__type">"v0.9.0-preview" → <code>0.9.0a1</code> … <code>0.9.0aN</code></span></dt>
<dd>Alpha series; iterates per Phase A publish.</dd>
</div>

<div>
<dt>Phase B · hardened core, capability redesign, federation hardening, operator soak</dt>
<dt><span className="stigmem-fields__type">"v0.9.x" (unlabeled) → <code>0.9.0b1</code> … <code>0.9.0bN</code></span></dt>
<dd>Beta series.</dd>
</div>

<div>
<dt>Phase C · v1.0 GA preparation</dt>
<dt><span className="stigmem-fields__type">"v1.0.0-rc" → <code>1.0.0rc1</code> … <code>1.0.0rcN</code></span></dt>
<dd>Release-candidate series.</dd>
</div>

<div>
<dt>GA</dt>
<dt><span className="stigmem-fields__type"><code>1.0.0</code></span></dt>
<dd>No suffix.</dd>
</div>

<div>
<dt>Phase D · post-1.0 expansion</dt>
<dt><span className="stigmem-fields__type"><code>1.0.1</code>, <code>1.1.0</code>, …</span></dt>
<dd>Semver-standard.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**The first build of stigmem is `v0.9.0a1`.**

</div>

### Per-ecosystem spelling

PEP 440 (Python) and semver (npm, Helm) use *different* spellings for
the same release. PEP 440 permits the bare form `0.9.0a1`; semver
requires a hyphen separator (`0.9.0-alpha.1`). This is not a
contradiction — each ecosystem has its own canonical spelling.

<div className="stigmem-fields">

<div>
<dt>Phase / class</dt>
<dt><span className="stigmem-fields__type">PEP 440 / Semver / Shorthand</span></dt>
<dd>Where each appears</dd>
</div>

<div>
<dt>Phase A alpha series</dt>
<dt><span className="stigmem-fields__type"><code>0.9.0a1</code> · <code>0.9.0-alpha.1</code> · <code>v0.9.0a1</code></span></dt>
<dd>PyPI / pyproject.toml · package.json / npm / Helm appVersion · prose, ADRs, Git tags</dd>
</div>

<div>
<dt>Phase B beta series</dt>
<dt><span className="stigmem-fields__type"><code>0.9.0b1</code> · <code>0.9.0-beta.1</code> · <code>v0.9.0b1</code></span></dt>
<dd>Same per-ecosystem split.</dd>
</div>

<div>
<dt>Phase C release-candidate series</dt>
<dt><span className="stigmem-fields__type"><code>1.0.0rc1</code> · <code>1.0.0-rc.1</code> · <code>v1.0.0rc1</code></span></dt>
<dd>Same per-ecosystem split.</dd>
</div>

<div>
<dt>GA</dt>
<dt><span className="stigmem-fields__type"><code>1.0.0</code> · <code>1.0.0</code> · <code>v1.0.0</code></span></dt>
<dd>Identical across ecosystems.</dd>
</div>

</div>

**Single shorthand for prose.** Documentation, ADRs, blog posts,
planning artifacts, GitHub release tags, and verbal communication use
the **PEP 440 spelling** (`v0.9.0a1`, `v0.9.0b1`, `v1.0.0rc1`) as the
single shorthand. It's shorter than the semver form, matches what
`pip show stigmem` returns, and prevents drift between docs that
reference the same release with two different strings.

**Git tag convention.** Git tags use the shorthand: `v0.9.0a1`,
`v0.9.0b1`, `v1.0.0rc1`, `v1.0.0`. A single tag identifies the
release across both ecosystems even though the published artifacts
have different version strings.

**Version-consistency CI.** The consistency check treats the two
spellings as equivalent for the same release. A normalizer maps both
`0.9.0a1` (PEP 440) and `0.9.0-alpha.1` (semver) to a canonical key
(e.g. `0.9.0.alpha.1`) and asserts all version emitters reference the
same canonical key. The script's allow-list — which surface uses which
spelling — is **not embedded in this ADR**.

### Surface manifest

This ADR captures **policy** (spelling rules, normalizer, immutability
boundary, shorthand convention). It deliberately does *not* embed the
inventory of release surfaces. The inventory lives in a separate YAML
manifest.

<div className="stigmem-keypoint">

**Path:** <code>release/version-surfaces.yaml</code>

In the stigmem repo; lands during Phase A PR 0 alongside
<code>scripts/check_version_consistency.py</code>.

</div>

**Schema** — one entry per surface:

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Required?</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>id</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>Stable identifier, kebab-case (e.g. <code>pypi-stigmem</code>, <code>helm-app-version</code>, <code>stigmem-version-header</code>).</dd>
</div>

<div>
<dt><code>kind</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd><code>external-registry</code> · <code>internal-protocol</code> · <code>internal-build-artifact</code> · <code>documentation</code>. Filters by audience-and-failure-mode class.</dd>
</div>

<div>
<dt><code>category</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>Domain classifier (e.g. <code>python-package</code>, <code>node-package</code>, <code>container-image</code>, <code>http-header</code>, <code>transparency-log</code>, <code>chart-metadata</code>, <code>prose</code>). Independent axis from <code>kind</code>.</dd>
</div>

<div>
<dt><code>file</code></dt>
<dt><span className="stigmem-fields__type">conditional</span></dt>
<dd>File path relative to repo root. Required for file-backed surfaces; omitted for protocol-only surfaces (e.g., HTTP headers defined by spec).</dd>
</div>

<div>
<dt><code>field</code></dt>
<dt><span className="stigmem-fields__type">conditional</span></dt>
<dd>Dotted field path within the file (e.g., <code>project.version</code>, <code>appVersion</code>).</dd>
</div>

<div>
<dt><code>spelling</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd><code>pep440</code> · <code>semver</code> · <code>shorthand</code>. Canonical spelling for this surface.</dd>
</div>

<div>
<dt><code>sort_authority</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>Which ordering rule applies (<code>pep440</code>, <code>semver</code>). Determines how CI compares versions for this surface.</dd>
</div>

<div>
<dt><code>spec</code></dt>
<dt><span className="stigmem-fields__type">optional</span></dt>
<dd>Cross-reference to the ADR or spec section (e.g., ADR-012 for HTTP headers, ADR-016 for Rekor manifest).</dd>
</div>

<div>
<dt><code>notes</code></dt>
<dt><span className="stigmem-fields__type">optional</span></dt>
<dd>Free-text caveats.</dd>
</div>

<div>
<dt><code>retired</code></dt>
<dt><span className="stigmem-fields__type">optional</span></dt>
<dd>Date the surface was retired. <strong>Tombstone, do not delete the row</strong> — keeps audit history of every surface stigmem has ever shipped to.</dd>
</div>

</div>

**Two query axes.** `kind` and `category` are independent.
`kind: external-registry` filters by audience (user-visible
breaking-change failure mode); `category: container-image` filters by
domain (Docker, GHCR, OCI). The CI script and operator tooling can use
either or both.

**Schema validator.**
`scripts/validate_version_surfaces.py` (lands with the manifest in
PR 0) enforces the schema, rejects unknown spellings, and asserts
that every entry's spelling matches its sort_authority's rules.

### Adding a new release surface

<ol className="stigmem-steps">
<li><strong>No new ADR if the spelling rule already exists.</strong> Append an entry to <code>release/version-surfaces.yaml</code> using one of the existing <code>spelling:</code> values. Add a CI test fixture. Open a normal PR.</li>
<li><strong>New ADR amendment if the spelling rule does not exist.</strong> A surface that uses CalVer, a registry with custom version semantics (e.g., date-suffix conventions), or any spelling that needs new normalizer logic requires an amendment ADR.</li>
</ol>

This split keeps policy stable and inventory operational.

### Retiring a release surface

<ol className="stigmem-steps">
<li>Set <code>retired: YYYY-MM-DD</code> on the entry. Keep the row.</li>
<li>Update CI to skip the entry when checking current version consistency (it remains validated for schema correctness).</li>
<li>Document the retirement in the next CHANGELOG entry.</li>
</ol>

The tombstone preserves the audit trail of every surface stigmem has
ever shipped to.

### Scope of replacement

Replace the literal string "0.9.0-preview" (and the `v`-prefixed form)
with `0.9.0a1` / `v0.9.0a1` / `0.9.0-alpha.1` throughout:

<div className="stigmem-grid">

<div><h4>Package manifests</h4><p><code>pyproject.toml</code>, root <code>package.json</code>, <code>sdks/stigmem-ts/package.json</code>.</p></div>
<div><h4>All CI-checked artifacts</h4><p>Subject to the version-consistency check per Phase A PR 0.</p></div>
<div><h4>Planning + retraction artifacts</h4><p>Master checklist, retraction post, LIMITATIONS.md, MAINTAINERS.md.</p></div>
<div><h4>Experimental status files</h4><p><code>experimental/&lt;feature&gt;/STATUS.md</code>.</p></div>
<div><h4>Docs surfaces</h4><p><code>docs/</code>, <code>spec/</code>, <code>release-notes/</code>, <code>migration/</code>.</p></div>
<div><h4>Internal-Comms planning</h4><p>Mutable working documents.</p></div>

</div>

<div className="stigmem-keypoint">

**Excluded from the scope of replacement: Accepted ADRs (immutable).**

ADR-001 and any other Accepted ADR that references the original
<code>v0.9.0-preview</code> string keeps its body unchanged. The
reverse-link convention — adding <code>**Amended by:** ADR-019 (DATE)</code>
to the amended ADR's Status block as lifecycle metadata — is how
readers reach the current convention without rewriting the historical
record. Same pattern applies to any future amendment chain (e.g.,
ADR-011 retroactively gets <code>**Amended by:** ADR-017</code>).

</div>

### What "preview" continues to mean

"Preview" remains as a **descriptive category word**, not a version
string.

<div className="stigmem-grid">

<div><h4>Acceptable</h4><p>"0.9.0a1 is a preview release — the first build of stigmem, pre-stable." (Microsoft uses this pattern: "Windows 11 Insider Preview build 22631.x.")</p></div>
<div><h4>Acceptable</h4><p>README, retraction post, blog posts, and marketing prose may say "preview" to convey the pre-stable nature of any 0.9.0a* or 0.9.0b* build.</p></div>
<div><h4>NOT acceptable</h4><p>"Preview" must not appear as a version string in any artifact subject to version-consistency CI.</p></div>

</div>

"Experimental" continues to refer to plugins under
`experimental/<feature>/` per ADR-008 / ADR-011 / ADR-018; that usage
is unaffected.

### Iteration semantics

Each Phase A PR that publishes a build increments the alpha number:
`0.9.0a1` (first publish), `0.9.0a2` (next), and so on. Phase A is
not required to ship one build per PR; the team chooses publish
cadence. The constraint is that any subsequent publish strictly
increments the alpha counter.

<div className="stigmem-fields">

<div>
<dt>Transition</dt>
<dt><span className="stigmem-fields__type">Marks</span></dt>
<dd>Direction</dd>
</div>

<div>
<dt>alpha → beta</dt>
<dt><span className="stigmem-fields__type">Phase A → Phase B</span></dt>
<dd>One-way ratchet.</dd>
</div>

<div>
<dt>beta → rc</dt>
<dt><span className="stigmem-fields__type">Phase B → Phase C</span></dt>
<dd>One-way ratchet.</dd>
</div>

<div>
<dt>rc → no-suffix</dt>
<dt><span className="stigmem-fields__type">Phase C → GA</span></dt>
<dd>One-way ratchet.</dd>
</div>

</div>

No version line ever rolls back from beta to alpha or from rc to beta.

### Tagging convention

Git tags use the `v` prefix: `v0.9.0a1`, `v0.9.0a2`, `v0.9.0b1`,
`v1.0.0rc1`, `v1.0.0`. Version strings emitted by tooling (pyproject,
package.json, OpenAPI) omit the `v` prefix.

## Consequences

### Positive

<div className="stigmem-grid">

<div><h4>Ecosystem-native ordering</h4><p>PyPI sorts <code>0.9.0a1 &lt; 0.9.0a2 &lt; 0.9.0b1 &lt; 1.0.0rc1 &lt; 1.0.0</code>; npm sorts <code>0.9.0-alpha.1 &lt; 0.9.0-alpha.2 &lt; 0.9.0-beta.1 &lt; 1.0.0-rc.1 &lt; 1.0.0</code>. The normalizer-backed CI maps both spellings to a single canonical key.</p></div>
<div><h4>No normalization surprise</h4><p><code>pip show stigmem</code> returns the exact PEP 440 string written in <code>pyproject.toml</code>. <code>npm view stigmem version</code> returns the exact semver string written in <code>package.json</code>.</p></div>
<div><h4>Iteration is built in</h4><p>Multiple Phase A publishes don't require inventing a successor convention.</p></div>
<div><h4>Pre-release exclusion is built in</h4><p><code>pip install stigmem</code> (without <code>--pre</code>) skips alpha/beta/rc. <code>npm install stigmem</code> (without an explicit pre-release tag) skips them. Adopters opt in explicitly.</p></div>

</div>

### Negative

<div className="stigmem-grid">

<div><h4>Rename pass across Internal-Comms</h4><p>~37 files contain references to the old "preview" string. One sweep replaces them.</p></div>
<div><h4>Marketing-language drift</h4><p>"v0.9.0-preview" was a usable shorthand. "v0.9.0a1" reads as a build identifier, not a release name. Compensate with descriptive prose ("the v0.9.0 alpha line", "preview release", "pre-stable build") in user-facing surfaces.</p></div>

</div>

### Neutral

<div className="stigmem-keypoint">

**ADR-001 is not edited.**

Per the immutability rule (`ADRs/DEFINITION.md`), Accepted ADRs
document the decision made at the time and are not rewritten when
later ADRs amend them. ADR-001's body continues to reference the
literal string <code>v0.9.0-preview</code> as the historical record.
Readers reach the current convention by following the amendment chain
— ADR-001's Status block carries an <code>**Amended by:** ADR-019 (DATE)</code>
annotation (lifecycle metadata, not a body edit), and ADR-019 is
authoritative for the phase-to-version mapping going forward.

</div>

## Open questions

None. This amendment is mechanical: replace one literal string with
another, and adopt iteration semantics that PEP 440 / semver already
specify.

## Related

- [ADR-001](./001-versioning) — the amended decision.
- [ADR-012](./012-version-aware-feature-exposure) — uses version strings as feature-gating keys; alpha/beta/rc strings are valid keys.
- [ADR-013](./013-deprecation-policy) — compatibility windows defined in version-string ranges; alpha/beta/rc fit cleanly.
- [ADR-014](./014-compatibility-matrix) — YAML source-of-truth uses ordered version strings; alpha/beta/rc preserve ordering.
