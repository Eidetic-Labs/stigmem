# Release cadence

How stigmem publishes a new release. Internal-facing maintainer doc; not part of the public docs site.

This document is a **runbook**, not a policy. The policy (versioning rules, stability commitments, contributor approval rule) lives in [ADR-001](../../docs/adr/001-versioning.md), [ADR-019](../../docs/adr/019-amendment-to-adr-001-prerelease-version-strings.md), and `release/version-surfaces.yaml`. This doc describes the operational sequence a maintainer follows to ship — and the discipline that keeps tags, docs, and published artifacts aligned.

---

## Release discipline (the durable rules)

These rules keep release labels, docs, and published artifacts aligned. Once a version is public, the corresponding tag and artifact must remain a stable historical record; follow-on corrections move to the next version or to a post-release where the ecosystem permits one.

### Rule 1 — PyPI/npm versions are immutable

PyPI and npm enforce this at the registry: once `stigmem-py 0.9.0a1` is uploaded, it cannot be replaced — only **yanked** (PEP 592 on PyPI) or **deprecated** (npm). This is not our policy; it's the ecosystem's. We design around it.

### Rule 2 — Tags are immutable after publish

The git tag is the bridge between commit history and the registry artifact. Once the registry has the artifact, **the tag must never move.** Force-moving a tag after publish desyncs the artifact from its declared source.

The corollary: **don't push a `v*` tag until you are confident the commit at the tag is what you want to ship.** Iterate on `main` first; tag once.

### Rule 3 — All errata go to the next version

If we publish `v0.9.0a1` and find a problem afterward, **we do not patch `v0.9.0a1` in place.** Two paths:

- **Doc-only or non-functional fix** (typo, broken link, stale CHANGELOG entry): ship `v0.9.0a1.post1` per [PEP 440 §Post-releases](https://peps.python.org/pep-0440/#post-releases). Post-releases are explicitly for "trivial errata" and do not signal new functionality.
- **Code fix or behavior change** (any source change): ship `v0.9.0a2`. Increment the alpha counter; new tag; full publish.

Never patch in place under the same label. This is the single rule that v1.0 violated.

### Rule 4 — Tag protection on GitHub

Tag pattern `v*` is protected via Settings → Tags → Tag protection rule. Force-pushing or deleting a `v*` tag requires admin override and is recorded in the audit log. Hard guard against accidental Rule-2 violation.

### Rule 5 — No `--force` on `main` or release branches, ever

`main` is protected per ADR-001 §Contributor approval rule. When `release/v1.x` exists (post-v1.0.0 GA, see §Release-branch strategy below), it gets the same protection.

### Rule 6 — GHCR images must be set to Public after first publish

Added 2026-05-10 after the dogfooding finding (#103) that `stigmem-node` shipped private and broke the README's `docker pull` quickstart.

GHCR packages default to **private** when first published. Adopters following the documented Docker quickstart will hit 403 Forbidden until the visibility is manually flipped.

**Required after the first publish of any new GHCR image:**

1. Go to `https://github.com/orgs/eidetic-labs/packages/container/<package-name>/settings`
2. **Danger Zone** → **Change visibility** → **Public**
3. Confirm

**Mechanically enforced by** the `GHCR visibility check` workflow at `.github/workflows/ghcr-visibility-check.yml`, which runs on every push to main + daily at 14:00 UTC. The workflow probes the GHCR token endpoint anonymously; failure means the image is private. Add new images to the check by extending `scripts/check_ghcr_public.py` with their reference.

### Rule 7 — GHCR image retention

Added 2026-05-11 after the founder observation that the GHCR package page shows ~40+ short-SHA tags accumulated since first publish, with no automatic cleanup.

The publish workflow (`.github/workflows/publish.yml`) publishes several tag flavours per push:

| Trigger | Tags pushed |
|---|---|
| Release tag (`refs/tags/v*`) | `:latest`, `:0.9.0aN` (PEP 440), `:0.9.0-alpha.N` (semver), `:<short-sha>` |
| Plain `main` push | `:edge`, `:<short-sha>` |

This is the right layout — `:latest` is release-gated and immutable version tags exist for reproducibility. But the short-SHA tags accumulate forever unless we prune them.

**Retention rules:**

| Tag class | Retention | Rationale |
|---|---|---|
| Immutable version tags (`:0.9.0aN`, `:0.9.0bN`, `:1.0.0rcN`, `:1.0.0`, plus semver-strict spellings) | **Forever** | Supply-chain auditability (Rule 2 corollary). An immutable artefact whose name disappears is operationally indistinguishable from a deleted artefact. |
| Rolling pointers (`:latest`, `:edge`) | **Forever** | They are pointers; the underlying digests are kept via the version-tag retention above. |
| Short-SHA tags (`:<7-char-sha>`) | **90 days** | Forensics window: long enough to debug a regression that landed 1–2 release cycles back; short enough to keep the tag inventory readable. |
| Orphan Sigstore signatures (`sha256-…sig` whose target image was pruned) | Pruned with their target | Without a target image, the signature is unverifiable noise. |

**Mechanically enforced by** the `GHCR retention` workflow at `.github/workflows/ghcr-retention.yml`, which runs weekly (Sundays 03:00 UTC). The workflow:

1. Lists all versions of `ghcr.io/eidetic-labs/stigmem-node` via `gh api`.
2. For each version, extracts its tag list.
3. **Skips** any version whose tag list contains a protected tag — `:latest`, `:edge`, or any tag matching the immutable-version regex `^[0-9]+\.[0-9]+\.[0-9]+(a[0-9]+|b[0-9]+|-?(alpha|beta)\.[0-9]+|rc[0-9]+|-rc\.[0-9]+)?$`.
4. **Deletes** any remaining version whose `created_at` is older than 90 days. This catches short-SHA-tagged versions and orphan Sigstore signatures.

The workflow runs in `dry-run` mode by default (logs what would be deleted) and respects a `STIGMEM_RETENTION_DRY_RUN=false` workflow input to actually delete. First production run after this rule lands: review the dry-run output, confirm scope, then flip to live mode.

**Operator audit:** the workflow's run log is the audit trail. The action posts a markdown summary to the workflow run page listing every deletion (version id, age, tags). To extend retention beyond 90 days for a specific period (e.g. a regression-hunt window), set `STIGMEM_RETENTION_MIN_AGE_DAYS=180` on the workflow run.

---

## Release-branch strategy

### Pre-1.0

**No release branches.** Each pre-release is allowed to break the previous per ADR-001 stability commitments. Discipline:

- Tag a commit on `main`.
- Publish.
- Don't move the tag.
- Next release picks up from `main` HEAD wherever `main` happens to be.

We are not committing to support old alpha releases. Adopters who pinned to `v0.9.0a1` stay on `v0.9.0a1` until they upgrade.

### At v1.0.0 GA (the cutover)

When `v1.0.0` GA ships:

1. Cut `release/v1.x` from the tagged commit.
2. Apply branch protection (no force-push, require PR, status checks must pass).
3. From this point, `main` moves toward `v1.1`, `v2.0`, etc. independently.
4. **`v1.0.x` patch releases land on `release/v1.x`**, not on `main`. Cherry-pick or merge-forward to `main` as appropriate.
5. **`v1.1.0` minor releases** ship from `main` directly. When `v1.1.0` GA ships, fast-forward `release/v1.x` to that tag (or cut `release/v1.1.x`, depending on how minor lines diverge).

This is the standard pattern used by Python, Django, FastAPI, and similar mature projects.

---

## Audience

A maintainer with publish rights (founder during the v0.9.0aN alpha series) preparing a new tagged release of stigmem. Assumes you've already merged the work into `main` and CI is green.

---

## Pre-release checklist

Before pushing a tag, verify:

- [ ] All open PRs that should ship in this release are merged into `main`.
- [ ] CI is green on the latest `main` commit.
- [ ] `python scripts/check_version_consistency.py` passes locally (CI also runs this).
- [ ] `release/version-surfaces.yaml` reflects every surface this release publishes to.
- [ ] `CHANGELOG.md` has a top entry for the new version, drafted and reviewed.
- [ ] If this release introduces breaking changes, the changelog entry includes a clearly-marked `### BREAKING` subsection.
- [ ] If this release closes any GitHub issues, those issues are linked from the CHANGELOG entry.
- [ ] `MAINTAINERS.md § Credential rotation` table is up to date — no expired tokens.
- [ ] Any pending Trusted Publisher (PyPI) configurations for new packages added in this release are registered at pypi.org.
- [ ] **Local smoke-build:** all four Python wheels build cleanly via `uv build --package <name>` and pass `uv run twine check dist/*`. Catches package-metadata issues that the version-consistency CI gate doesn't see (missing files, broken `[build-system]`, etc.).
- [ ] **OpenAPI spec is current:** `uv run python scripts/export_openapi.py && git diff --exit-code docs/openapi/stigmem.json` produces no diff. If there's drift, the FastAPI `app.version` was changed but the exported spec wasn't regenerated.
- [ ] **Eval fast gate:** `make eval-fast` passes on the release candidate
  commit when the release includes eval, recall, node, SDK, spec, conformance,
  or eval-harness feature-record changes. For `v0.9.0a11` and later alpha
  releases, the release-readiness script also statically verifies adversarial
  corpus count, recall probe count, baseline hash/schema, eval-fast path
  filters, and that generated `eval/results/` artifacts were not accidentally
  tracked. `make eval-soak-smoke` remains optional/manual unless a maintainer
  explicitly opens a Docker/Colima-dependent soak gate.
- [ ] **Meta-package dep ranges updated** (if applicable). The root `stigmem` `pyproject.toml` `dependencies` and `[project.optional-dependencies]` lists pin to e.g. `stigmem-py>=0.9.0a2,<1.0.0` — when bumping the canonical line, the lower bound should bump too. If you're cutting a beta from an alpha (`0.9.0a3` → `0.9.0b1`), the upper bound stays at `<1.0.0`; if cutting `1.0.0`, the meta-package's bounds get a major-version bump (separate decision; revisit before then).
- [ ] **Update security artifacts** per `docs/internal/evidence-maintenance.md`: refresh the docs-landing risk-register summary, threat-model page status header, `CHANGELOG.md` `### Security` subsection when security work or risk-status changes landed, and SBOM/signature verification evidence for published artifacts.
- [ ] **Evidence maintenance validators pass:** `python3 scripts/check_evidence_maintenance.py`, `python3 scripts/validate_security_evidence.py`, and `python3 scripts/check_security_documentation.py`.
- [ ] **Maintainer GPG key is available locally:** `gpg --list-secret-keys`
  shows the release signing key and `git tag -s` can create a signed tag.
  Detached artifact signatures are created manually after the publish workflow
  completes and are uploaded to the GitHub release.

If any item fails, fix or document before proceeding.

---

## Version-string sweep

Every published version string in the repo must agree with the new release. The version-consistency CI gate (per ADR-019) catches most of this; this section documents the human-driven updates.

**File-backed surfaces** (caught by CI):

- `pyproject.toml`, `node/pyproject.toml`, `sdks/stigmem-py/pyproject.toml`, `adapters/openclaw/pyproject.toml` — PEP 440 form (e.g. `0.9.0a2`).
- `package.json`, `sdks/stigmem-ts/package.json` — semver form (e.g. `0.9.0-alpha.2`).
- `experimental/deploy-helm/helm/stigmem/Chart.yaml` — `appVersion` in semver form.

**Documentation surfaces** (currently CI-skipped; sweep manually):

- `README.md` status banner, install commands, badges.
- `CHANGELOG.md` top entry.
- `LIMITATIONS.md` "Applies to" line.
- `SECURITY.md` "Applies to" line + Supported Versions table.
- `docs/docs/community/security-disclosure.md` Supported Versions table.
- `node/src/stigmem_node/main.py` FastAPI(version=) string.
- `docs/openapi/stigmem.json` `info.version` (regenerate via `uv run python scripts/export_openapi.py`).
- `node/src/stigmem_conformance/__init__.py` `__version__`.
- `eval/README.md` baseline JSON `server_version` example.
- `deploy/systemd/README.md` `pip3 download` example.
- `adapters/openclaw/skill/SKILL.md` (if cutting a new ClawHub skill release alongside).

**Compose surfaces** (added to release cadence on 2026-05-09):

- `docker-compose.yml` — both `node-a` and `node-b` `image:` fields. Use the new tag (e.g. `ghcr.io/eidetic-labs/stigmem-node:0.9.0a2`). Compose still falls back to local build if the image can't be pulled (e.g. on a dev branch before the image exists), so this update is forward-looking but doesn't break older clones.

---

## Tag and trigger publish

```bash
# Confirm working copy clean
git status

# Confirm you're on main with the latest
git fetch origin
git log --oneline main..origin/main  # should be empty
git pull --ff-only origin main

# Tag with the PEP 440 shorthand (per ADR-019). Use a signed tag for release
# provenance; detached artifact signatures are created manually after publish.
git tag -s v0.9.0a2 -m "v0.9.0a2"  # adjust version
git push origin v0.9.0a2

# Watch the workflow run
gh run watch --repo eidetic-labs/stigmem $(gh run list --workflow=publish.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

Pushing the tag triggers `.github/workflows/publish.yml`, which fans out into:

1. **`publish-node`** — multi-arch (linux/amd64 + linux/arm64) GHCR image; Sigstore cosign keyless signed; SBOM (SPDX JSON) attached. Image gets BOTH PEP 440 and semver tags (e.g. `:0.9.0a2` and `:0.9.0-alpha.2`) so adopters can pull via either form.
2. **`publish-sdk-ts`** — npm publish of `@eidetic-labs/stigmem-ts` with `--tag <alpha|beta|rc|latest>` (derived from the version via `scripts/translate_version.py` — no manual computation needed), with provenance attestation via npm Trusted Publisher/OIDC. The workflow does not use `NPM_TOKEN`.
3. **`publish-python`** — matrix publishes `stigmem`, `stigmem-py`, `stigmem-node`, `stigmem-openclaw` to PyPI via Trusted Publishers (OIDC; no API token).
4. **`create-release`** — runs after publish-node + publish-sdk-ts + publish-python succeed. Extracts the `## [<version>]` section from `CHANGELOG.md`, prepends a "Published artifacts" header with the install commands for each registry, and creates the GitHub release with that body. Marks as prerelease for any non-`latest` dist-tag (alpha/beta/rc). Title format follows the translated release tier, for example `v0.9.0aN — preview alpha`; future beta or release-candidate titles are used only when those release lines are explicitly opened.

The first four publish jobs run in parallel (~5-8 minutes total). The release-creation job runs after to ensure the release page only links at working artifacts. **Stay near the workflow run** until the release page appears — if anything fails, you'll want to triage immediately rather than discover hours later.

> **Important precondition for `create-release`:** the CHANGELOG must already have a `## [<version>]` entry. If you forget to add it before tagging, the job fails fast with `::error:: No CHANGELOG section found for [<version>]`. The release won't be created; the package publishes already happened. Recover by adding the CHANGELOG entry, then either re-run the failed `create-release` job (`gh run rerun`) or create the release manually via `gh release create`.

---

## Post-publish verification

Within ~5 minutes of tag push:

- [ ] **PyPI** — `pip install --pre stigmem` resolves to the new version. `pip show stigmem` returns the expected `Version:`. Repeat for `stigmem-py`, `stigmem-node`, `stigmem-openclaw`.
- [ ] **npm** — `npm view @eidetic-labs/stigmem-ts version` returns the new semver. `npm view @eidetic-labs/stigmem-ts` shows the right `dist-tags`: the line-specific tag (`alpha` / `beta` / `rc`) advances to the new prerelease. While the project is pre-stable, maintainers also advance `latest` manually after the Trusted Publisher release succeeds:
  ```bash
  npm dist-tag add @eidetic-labs/stigmem-ts@<semver> latest
  npm view @eidetic-labs/stigmem-ts dist-tags --json
  ```
- [ ] **GHCR** — `docker pull ghcr.io/eidetic-labs/stigmem-node:<tag>` succeeds. (No `stigmem-dashboard` image: dashboard is deferred per ADR-002; `publish-dashboard` was removed from `publish.yml` in PR #64.)
- [ ] **GHCR visibility** — for first publish of a new package only: visit `https://github.com/orgs/eidetic-labs/packages` → find the package → Package settings → Danger Zone → Change visibility → **Public**. Subsequent pushes inherit the visibility setting; this is one-time per package.
- [ ] **Cosign** — replace `<tag>` with the actual version (e.g. `0.9.0a2`):
  ```bash
  TAG=0.9.0a2
  cosign verify \
    --certificate-identity-regexp 'github.com/eidetic-labs/stigmem' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    ghcr.io/eidetic-labs/stigmem-node:$TAG
  ```
- [ ] **GPG release assets** — export the maintainer public key, create
  detached signatures for the release assets, upload the public key and
  signatures to the GitHub release, and verify them before archiving or
  mirroring:
  ```bash
  gpg --armor --export <KEYID_OR_FINGERPRINT> > stigmem-release-signing-key.asc
  gpg --armor --detach-sign <artifact>
  gh release upload v0.9.0a2 stigmem-release-signing-key.asc <artifact>.asc --repo eidetic-labs/stigmem

  gpg --import stigmem-release-signing-key.asc
  gpg --verify <artifact>.asc <artifact>
  ```
- [ ] **GitHub release** — Created automatically by `publish.yml` `create-release` job. Verify the release page at `https://github.com/eidetic-labs/stigmem/releases/tag/v<tag>` shows: (1) the install-commands header, (2) the full CHANGELOG section for this version, (3) the prerelease badge (for alpha/beta/rc) or no badge (for final). If the page is missing or notes are empty, check the `create-release` job log for an extraction error.
- [ ] **Close the tracking issue** for this release if one was opened (e.g., the PR-N issue in the master-checklist).

Within ~2 hours of tag push:

- [ ] **piwheels** mirror — `https://www.piwheels.org/project/stigmem-py/` shows the new version with ARM wheels.
- [ ] **npm CDN mirrors** — `curl -sI https://unpkg.com/@eidetic-labs/stigmem-ts@<semver>/package.json` returns 200.

---

## ClawHub publish (manual)

ClawHub doesn't auto-publish from CI. Maintainer pushes the new skill version from their machine:

```bash
# Authenticate (interactive; uses cached creds from a prior login if available)
openclaw whoami    # confirms you're authenticated as offbyonce
# If not authenticated:
openclaw login

cd adapters/openclaw/skill
# Edit SKILL.md:
#   version: <next iteration> (independently versioned — does NOT match
#     the canonical line; bump the trailing patch number)
#   package: "stigmem-py>=<canonical>,<upper-bound>" (update if the
#     canonical line moved; e.g., to >=0.9.0a2,<1.0.0)
openclaw skills push
```

If the ClawHub skill pins a `stigmem-py` version range that doesn't yet exist on PyPI, this push will succeed (ClawHub doesn't validate transitive Python deps), but `openclaw skills install stigmem-node` will fail at the dep-resolution step. So **push ClawHub *after* PyPI publish is confirmed working** (i.e., after the post-publish PyPI verification above succeeds).

---

## Rollback

PyPI, npm, GHCR each have different retraction mechanics:

| Surface | Mechanism | Time-bounded? |
|---|---|---|
| **PyPI** | `twine yank` (PEP 592) — or via pypi.org Web UI Manage page | No time limit; reversible |
| **npm** | `npm unpublish <pkg>@<ver>` (within 72 hours of publish) or `npm deprecate <pkg>@<ver> "msg"` (anytime) | unpublish is 72h-bound; deprecate has no time limit |
| **GHCR** | Image manifests stay forever (immutable). Tag can be deleted but pulled image references resolve from local cache. Best response is to publish the next version with the fix. | Effectively no rollback |
| **ClawHub** | No yank mechanism. Push next skill version with corrected pin/content; reach out to ClawHub admin for last-resort delete. | No rollback |

**General rollback principle:** publishing the *next* version with a fix is almost always preferable to retracting the bad one. PyPI and npm are exceptions where yanking is appropriate signaling for "broken release that adopters shouldn't reach for." For GHCR, fix-forward.

If a release is found broken post-publish:

1. **File a tracking issue** explaining the breakage and the chosen response. Label `severity:high` if adopter-visible.
2. **Yank PyPI versions where appropriate.** Web UI: pypi.org → Manage → Releases → Options → Yank. Or CLI:
   ```bash
   # Generate / use a PyPI API token; OIDC trusted publisher doesn't grant yank rights
   pip install --upgrade twine
   twine yank stigmem-py 0.9.0a1 --reason "Withdrawn — <one-line>. Use 0.9.0a2+."
   # Repeat per affected package
   ```
3. **Deprecate npm versions where appropriate.**
   ```bash
   npm deprecate "@eidetic-labs/stigmem-ts@0.9.0-alpha.1" "Withdrawn — <one-line>. Use 0.9.0-alpha.2+."
   ```
4. **Publish the fix** as the next version (e.g., `0.9.0a2` follows `0.9.0a1`) — never reuse a version number. Walk this same runbook end-to-end for the fix release.
5. **Update CHANGELOG** with both entries: the broken version with a brief `### Withdrawn` callout, and the fix version with the diff from the broken one.
6. **Close out the tracking issue** when the fix release is verified.
7. **Notify** if the broken version was widely-installed: post to the GitHub Discussions / Issues tracker; consider a brief blog/dev.to post if usage was non-trivial.

See ADR-019 for why version numbers are immutable across all our surfaces (PEP 440 / npm both forbid republish under the same number).

---

## Annual review

This document is reviewed once per major release cycle (the v0.9.0aN alpha series → B, B → C, C → GA, etc.) to incorporate operational lessons. Last reviewed: **2026-05-09** (created — the v0.9.0aN alpha series in progress).
