# Contributing to Stigmem

Thanks for your interest in contributing. Stigmem is a community spec — the goal is to get smart people with production experience to stress-test the design before it ossifies.

## Ways to contribute

| Track | What it is | Who it's for |
|---|---|---|
| **RFC** | Propose a spec change via issue + PR | Anyone with a concrete problem or proposed improvement |
| **Implementation** | Build an alternative node or client | Developers who want to validate the wire format against real workloads |
| **Bug / gap report** | File an issue about a spec ambiguity, docs issue, or reference-node bug | Anyone reading the spec |
| **Starter issue** | Pick up a scoped `good first issue` | New contributors who want a small, reviewable first PR |

## New contributor orientation

Start with the smallest set of pages that explains how the system hangs
together:

1. [Architecture overview](docs/docs/reference/architecture/index.md) — repo map,
   request path, fact model, HLC, federation, and storage.
2. [Single-host node](docs/docs/reference/architecture/single-host-node.md) —
   how the reference node handles local reads, writes, auth, and persistence.
3. [Federated network](docs/docs/reference/architecture/federated-network.md) —
   peer registration, pull replication, scope enforcement, and audit flow.
4. [Threat model](spec/security/threat-model.md) and
   [SECURITY.md](SECURITY.md) — what is safe today, what remains residual, and
   how to report vulnerabilities.
5. [ADRs](docs/adr/) — accepted architectural decisions. ADRs are immutable once
   accepted; propose amendments instead of editing accepted ADR history.
6. [Roadmap](ROADMAP.md) — current phase, open work, and exit criteria.

Then run the two demo paths:

```bash
make demo
make demo-attack
```

`make demo` proves two-node local federation end-to-end. `make demo-attack`
shows malicious-peer rejection for unauthorized scope writes and source forgery.

Good starter work is labeled
[`good first issue`](https://github.com/eidetic-labs/stigmem/issues?q=is%3Aissue%20is%3Aopen%20label%3A%22good%20first%20issue%22).
Prefer one small issue per PR. If a starter issue touches docs, update the
roadmap or checklist only when the issue explicitly changes project status.

### PR-closes-issue and milestone discipline (from v0.9.0a3 onward)

Every PR opened against `main` from v0.9.0a3 onward must:

1. Close exactly one issue (use `Closes #NNN` in the PR body) — open an issue first if none exists.
2. Be assigned to the milestone that the closing issue belongs to. If no active
   release-line milestone exists, open one before starting release-scoped work.

The discipline lets anyone answer "what shipped in release X?" by reading the milestone instead of triangulating across CHANGELOG, ROADMAP, and git history. PRs that predate v0.9.0a3 are not retroactively backfilled.

Future release-line milestones are created only when their feature-launch goals and release horizon are approved.

Exceptions: emergency security patches and pure-revert PRs may land without a closing issue, with the rationale stated in the PR body.

## Documentation ownership

Recurring release, security, and evidence facts have one canonical owner. Before
adding a second copy of the same table or disposition, check
[`docs/internal/documentation-ownership.md`](docs/internal/documentation-ownership.md)
and link to the owner instead. In particular:

- `SECURITY.md` is the public security posture and advisory-disposition index.
- `CHANGELOG.md` is a release-impact summary, not an audit ledger.
- dated security evidence registries carry PR, path, test, and disposition proof.
- `spec/security/threat-model.md` carries enduring architectural risks only.
- Internal-Comms holds unpublished or embargoed staging material only.

## RFC process

Use this when you want to propose a spec change, add a new field or endpoint, change semantics, or resolve an open question in a modular spec.

1. **Open an RFC issue** using the [RFC template](.github/ISSUE_TEMPLATE/rfc.yml). Include:
   - The problem you're solving
   - Your proposed change
   - Alternatives you considered
   - Open questions
2. **Discuss** on the issue. Aim for at least one week of async discussion before calling for merge.
3. **Submit a PR** against the relevant modular spec under `docs/docs/spec/specs/`
   and any generated/canonical mirrors that the issue names. Reference the issue.
4. **Merge criteria:** ≥2 approvals from contributors who have merged at least one prior PR. The spec maintainer may veto with a written rationale.

For small fixes (typos, clarity, example corrections), skip the RFC issue and send a PR directly.

## Conformance suite

**Contract:** every new spec section or wire-format change MUST include at least one new conformance vector in `data/conformance/v1.0/`. PRs that add or modify spec text without a corresponding vector will not be merged.

The `data/conformance/v1.0/` directory contains machine-readable test vectors that every conforming implementation must pass. The CI job **Stigmem v1.0 Conformance Suite** runs on every push to `main` and on pull requests that touch `node/`, `spec/`, `data/conformance/`, or the workflow file itself.

**Run locally:**

```bash
uv run pytest node/tests/test_conformance_v1.py -v
```

## Security evidence for mitigated risks

A threat-model risk may move to `Mitigated` only when the PR also updates
[`spec/security/evidence-registry.json`](spec/security/evidence-registry.json).
The registry entry must include:

- the risk ID and title;
- status;
- version introduced;
- implementation file(s);
- test file(s);
- docs or reference file(s);
- a review decision.

Run the registry validator before opening the PR:

```bash
python scripts/validate_security_evidence.py
```

The validator checks that every threat-model `Mitigated` risk is registered, that
required fields are present, and that listed paths still exist. It does not
decide whether the evidence is good enough; reviewers still own that judgment.

## Experimental feature security docs

Per ADR-020 §11 (security taxonomy), experimental features keep feature-owned security analysis beside
the feature at `experimental/<feature>/security.md`. Use this file for Gate 1
threat-model deltas, owned R-XX risks, contributed risks, operator scenarios,
conformance pointers, reintroduction gates, and cross-references back to the
unified threat model.

Cross-cutting protocol risks stay in
[`spec/security/threat-model.md`](spec/security/threat-model.md). A
per-feature risk should have exactly one owning feature; contributing features
carry short notes that link back to the canonical entry.

Run both validators before opening a PR that changes threat-model or feature
security content:

```bash
python scripts/validate_security_evidence.py
python scripts/check_security_documentation.py
```

**Adding a new test vector:**

1. Open (or create) a numbered file in `data/conformance/v1.0/` (e.g., `06_new_feature.json`). The runner loads all files matching `0*.json` in sorted order.
2. Use this top-level structure:

```json
{
  "spec_section": "§X.Y",
  "title": "Short group title",
  "description": "Optional longer description",
  "vectors": [...]
}
```

3. Each vector must include at minimum `id`, `description`, `method`, `path`, and one of the `expected_*` assertion fields:

```json
{
  "id": "unique-kebab-id",
  "description": "What this vector tests",
  "method": "POST",
  "path": "/v1/facts",
  "body": { "entity": "stigmem://node/user/alice", "relation": "memory:role", "..." },
  "expected_status": 201,
  "expected_body_contains": { "entity": "stigmem://node/user/alice" },
  "expected_body_has_keys": ["id", "timestamp"]
}
```

4. Use `expected_nested` for deep assertions without matching the full response. Keys are dotted paths:

```json
"expected_nested": { "value.type": "number", "value.v": 42.5 }
```

   This checks `response["value"]["type"] == "number"` and `response["value"]["v"] == 42.5`.

5. Use `requires_setup` (another vector's `id`) to declare ordering dependencies — the runner will execute the prerequisite first within the same DB session.

6. **Do not add vectors with `requires_auth: true` to files in `data/conformance/v1.0/`.** Zero skips are enforced by CI; auth-dependent scenarios belong in the dedicated auth test module.

## CLI reference docs

Regenerate the CLI reference pages (under `docs/docs/reference/cli/`) after changing CLI flags or adding subcommands: `make gen-cli-docs`.

## Issue templates

Use the issue template that matches the work:

- **Bug / spec ambiguity** — prototype behavior, docs mistakes, unclear spec
  text, or contradictory semantics.
- **RFC** — proposed wire-format, protocol, namespace, or semantic changes.
- **Security advisory coordination** — public, non-sensitive coordination only.
  Do not disclose active vulnerabilities, exploit details, secrets, or private
  operator information in a public issue; use GitHub private security advisories
  or the path in [SECURITY.md](SECURITY.md).
- **Operator candidate** — teams interested in running a node during external
  validation or the future hardened-core soak.
- **Federation expressivity** — discussion of federation semantics that do not
  yet fit an implementation issue.

## Branch and publish verification

Before pushing a review branch or publishing an artifact, verify the target from
the repository you intend to update:

```bash
git rev-parse --show-toplevel
git status --short --branch
git fetch origin
git rev-list --left-right --count origin/main...HEAD
git ls-remote --heads origin "$(git branch --show-current)"
```

Confirm the branch name, ahead/behind count, and remote ref before pushing. For
release or package publishing work, include the checked branch and publish target
in the PR body so reviewers can verify that the artifact came from the expected
source.

## Major-version dependency holds

Major-version holds are allowed only when they are explicit. Record intentional
holds in [`docs/internal/major-version-holds.md`](docs/internal/major-version-holds.md)
or the active release tracker with:

- package and owning workspace;
- current major and latest major;
- owner;
- rationale and security impact;
- tests required before the bump;
- review date.

Patch and minor updates for runtime, auth/session, parsing, validation, bundling,
or protocol-generation packages should normally be evaluated before framework
major migrations.

## Per-version-line docs-delta requirement

Every version line of the roadmap MUST ship a docs-improvement deliverable. This is a board mandate (2026-05-03).

**What counts as a docs-delta:**

- A new guide, reference page, or conceptual doc added to the docs site.
- A substantive update to existing content (not just typo fixes).
- A new working code example for a feature that shipped in the version line.
- An updated architecture diagram reflecting the version line's changes.
- A Features-table row update (see below).

**How to declare it in a PR:**

Include a `docs-delta:` line in the PR body listing what docs shipped with the release. Example:

```
docs-delta: Added federation-trust guide (docs/docs/build/guides/federation-trust.md),
updated Features table row for org manifests.
```

Release PRs without a docs-delta line will be flagged during review.

## Features page update procedure

The [Features page](docs/docs/concepts/features.md) status table is the **single source of truth** for what Stigmem can do today. When a feature ships:

1. Open `docs/docs/concepts/features.md`.
2. Find or add the row for the capability in the appropriate section table.
3. Set its **Status** column to one of: `Stable`, `Preview`, `Experimental`, or `Deferred`.
4. Fill the **Spec** column with the relevant modular Spec ID (e.g., `Spec-X3-Time-Travel`).
5. Fill the **Docs** column with a relative link to the guide or reference page.
6. If a previously `Deferred` or `Experimental` feature graduates per [ADR-008](docs/adr/008-experimental-gates.md), update the row in place — do not add a duplicate. Run the [graduation procedure](ROADMAP.md#spec-graduation-process) for any spec moving from `experimental/` into the canonical surface.

The Features page intentionally avoids calendar dates. Do not add target-quarter references.

## Docs versioning snapshot procedure

Stigmem docs are currently in **single-version mode** (current published build = `v0.9.0a4`; no next alpha milestone is open yet). No versioned snapshots are created during the alpha series. The first versioned snapshot will be cut only when a stable GA line actually ships per [ADR-001](docs/adr/001-versioning.md).

When v1.0.0 GA ships, create a versioned snapshot:

1. Merge all docs IA restructuring, de-duplication, and content updates for the release.
2. From the `docs/` directory:

```bash
npm run docusaurus docs:version v1.0.0
```

This copies `docs/docs/` → `docs/versioned_docs/version-v1.0.0/` and `docs/sidebars.ts` → `docs/versioned_sidebars/version-v1.0.0-sidebars.json`, then prepends the tag to `docs/versions.json`.

3. Update `docusaurus.config.js` → `docs.versions`:
   - Set `lastVersion` to the new tag (e.g., `'v1.0.0'`) so bare `/docs/*` URLs resolve to the released version.
   - Add the new version entry: `'v1.0.0': { label: 'v1.0.0', badge: true }`.
   - Relabel `current`: `{ label: 'pre-reset draft', path: 'next', badge: true, banner: 'unreleased' }`.

4. Run `npm run build` — must exit 0 with no broken links.

**Version naming:** use `v<major>.<minor>.<patch>` matching the released git tag for stable releases. Pre-release tags (`v0.9.0a1`, `v0.9.0a2`, …) do not get versioned snapshots — the `current` site is the alpha-series source of truth.

## Audience and status frontmatter conventions

Every docs page must include an `audience` field in its YAML frontmatter:

```yaml
---
id: my-page
title: My Page
audience: Integrator
---
```

**Allowed audience values** (enforced by `docs/plugins/validate-audience.js`):

| Value         | Who it addresses                                     |
|---------------|------------------------------------------------------|
| `Evaluator`   | Newcomers deciding whether to adopt                  |
| `Integrator`  | Developers building on Stigmem (agent devs, SDK consumers) |
| `Operator`    | Node operators running and maintaining a Stigmem node |
| `Security`    | Security reviewers, threat-model readers, secure-tab landings |
| `Spec`        | Spec contributors and reference-node developers      |

In the post-PR-#56 four-tab IA, pages under `concepts/` and `get-started/` default to `Evaluator` or `Integrator`; pages under `operators/` default to `Operator`; pages under `security/` default to `Security`; pages under `reference/` (spec, architecture, API) use `Spec`. Always set the field explicitly rather than relying on defaults.

The build-time validation plugin (`docs/plugins/validate-audience.js`) will fail the build if any doc page is missing a valid `audience` field. Auto-generated API reference pages (under `reference/api/generated/`) are exempt.

**Optional `status` field:**

Pages describing non-stable features may include a `status` field, which renders a prominent admonition banner:

| Value          | Admonition type | Meaning |
|----------------|-----------------|---------|
| `Experimental` | caution         | Behind a flag, breaking changes expected |
| `Beta`         | warning         | Early adopters, minor breaking changes possible |
| `Planned`      | info            | Spec draft exists, not yet implemented |

Stable features do not need a `status` field. The Features page table remains the single source of truth for overall feature status.

## Docs drift watchdog

CI runs `docs/scripts/check_drift.py` on every push and PR to catch stale or forbidden content in the docs tree. It checks for:

- **Forbidden strings** — product names or terms that must not appear (e.g., references to unrelated products).
- **Calendar quarter dates** — `Q1 2025`-style strings outside exempt historical/roadmap files, which go stale quickly.
- **Stale claims** — absolute statements that are no longer true (e.g., "no vector search" after that feature shipped).
- **Bare tracker IDs** — internal issue tracker references (e.g., `ACM-123`) that leaked into public docs.

Rules live in `docs/scripts/drift-rules.json`. To add a new rule, edit the appropriate section in that file — no code changes required. Run locally:

```bash
python docs/scripts/check_drift.py
```

To exempt a file from the calendar-quarter check (e.g., a new changelog page), add its path to the `exempt_globs` array in `drift-rules.json`.

### Rule types in `drift-rules.json`

| Key                  | Purpose                                               | How to add a new entry                                        |
|----------------------|-------------------------------------------------------|---------------------------------------------------------------|
| `forbidden_strings`  | Block specific terms from the docs tree               | Add `{ "pattern": "...", "flags": "i", "description": "..." }` to the array |
| `calendar_quarters`  | Flag `Q1 2025`-style refs that go stale               | Update `exempt_globs` to whitelist new historical pages       |
| `stale_claims`       | Catch absolute negatives disproved by shipped features | Add `{ "pattern": "...", "flags": "i", "description": "..." }` to the array |
| `bare_ticket_ids`    | Prevent internal tracker IDs from leaking             | Add the prefix string to `tracker_prefixes`                   |

After editing `drift-rules.json`, run `python docs/scripts/check_drift.py` locally to verify no false positives before pushing.

## Prototype contributions

The prototype in `prototype/` is a minimal reference implementation — not production software. Contributions that validate spec behavior are welcome; contributions that add production-hardening, auth, or persistence layers should wait until the corresponding version-line scope is set.

To run it:

```bash
cd prototype
pip install -r requirements.txt
python main.py        # starts the local node on :8000
python seed_memory.py # loads example facts
```

Tests: `pytest` (when test coverage exists — contributions welcome).

## Local verification

Install the same core toolchain the CI jobs expect:

- `uv` with Python 3.11
- Node 20 with Corepack / `pnpm`
- Go 1.22+
- Docker and Helm for container/deploy checks

Fast PR-equivalent checks:

```bash
make check
```

Focused package checks:

```bash
make check-python
make check-node
make check-contract
make check-go
make check-docs
make check-obsidian
make check-sdk-compat
```

Notes:

- Python lint and mypy are on a staged baseline. New findings fail CI even though historical debt is still being burned down.
- `make check-sdk-compat` starts a local node with auth disabled and smoke-tests the Python, TypeScript, and Go SDKs against the same server.
- Slower suites such as eval, federation soak, and multi-backend deployment checks remain outside the default PR loop.

## Test policy

The repository is converging on a shared marker taxonomy:

- `unit`
- `integration`
- `conformance`
- `postgres`
- `libsql`
- `docker`
- `eval`
- `slow`
- `network`

Fast PR checks should stay in `unit` plus fast `integration`. New slow or environment-dependent coverage should be marked accordingly.

## Flaky tests

Do not silently quarantine flaky tests.

- If a test is quarantined or temporarily skipped, link an issue in the skip reason.
- Assign an owner in the issue.
- Include an expiration or review date in the issue/PR so the quarantine is not permanent.
- Re-enabling the test is preferred over broad retries that hide regressions.

## Spec authorship and attribution

The spec file records authors in its header. RFC contributors who make substantive changes to spec content are listed. Implementation-only contributors are acknowledged in CHANGELOG.

## AI-authorship disclosure

Stigmem is built by two contributors with heavy AI-coding assistance. We disclose this because a category whose product is trust shouldn't quietly hide where the work came from. The same disclosure appears in [README.md](README.md#ai-authorship-disclosure) and the docs-site [AI authorship disclosure](docs/docs/community/ai-authorship.md).

**Paths with deeper human review (line-by-line):**
- `spec/` — protocol specification text
- `docs/adr/` — Architecture Decision Records
- `LIMITATIONS.md`, `SECURITY.md`, `MAINTAINERS.md`, root `README.md`
- All threat-model entries (`spec/security/`, `docs/security/`)

**Paths with lighter human review (high-level direction + spot-checks):**
- `node/src/` — implementation
- `adapters/` — adapter implementations
- `sdks/` — SDK stubs
- `apps/` — UI scaffolding
- Test suites
- Documentation pages outside the spec and ADRs

**What we ask of contributors:**
- When submitting a PR that includes AI-generated code, say so in the PR description. We don't reject AI-generated contributions — we calibrate review effort. Code in deeper-review paths gets line-by-line attention regardless of authorship.
- When reviewing a PR, treat lighter-reviewed paths as you would any AI-written code: verify behavior against the spec, run the conformance suite, and audit before merging.
- Disclosing AI assistance is a calibration aid, not a defect notice.

## Code of conduct

Be direct and technically rigorous. Assume good faith. Disagree with arguments, not people. There is no formal CoC document yet; interim standard is the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree your contributions are licensed under Apache-2.0 (same as the project).
