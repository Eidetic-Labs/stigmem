# Maintainers

This file is the canonical record of who currently holds maintenance roles in the stigmem project. It is updated as the team evolves.

This file lives in the stigmem repo root. ADRs reference roles ("the founder," "the founding team," "contributors"); this file maps those roles to current GitHub identities.

---

## Founder

- **[@offbyonce](https://github.com/offbyonce)** — Founder, Eidetic Labs.

## Founding team

Additional team members listed upon their consent.

## Other contributors

Contributions from anyone outside the listed roles above are recorded in git history and welcome under [`CONTRIBUTING.md`](CONTRIBUTING.md). Inclusion in this file is a separate, opt-in step.

---

## Authority and approval

Per [ADR-001 § *Contributor approval rule*](docs/adr/001-versioning.md), sign-off on ADRs, ADR amendments, and PRs through the pre-stable hardening window requires **either** two contributors **or** the founder alone. The founder takes responsibility for the validation discipline whenever signing alone — the guardrail against AI-velocity-outrunning-validation (per the v1.0 retraction narrative) lives with the founder when they approve solo.

Audit logs (plugin registration per ADR-011, PR approval records, ADR sign-off commits) show the actual signing identities. This file describes who currently holds the roles; git history is the durable record of who exercised them.

---

## Plugin signing identities (per ADR-011)

When the C1 plugin architecture (ADR-011) ships its production signing infrastructure, **Eidetic Labs** is the default trusted publisher for stigmem core plugins (the seven cross-cutting feature plugins shipped in the v0.9.0aN alpha series). Operators may add additional trusted publishers in their own deployments.

The Sigstore identity mapping for Eidetic Labs is documented separately in `docs/Operate/Plugins/signing.md` (per ADR-020 §12 (docs IA) IA, lands in v0.9.0aN docs work).

---

## Release cadence

The operational runbook for cutting a new tagged release lives at [`docs/internal/release-cadence.md`](docs/internal/release-cadence.md). It covers pre-release checklist, version-string sweep across all surfaces, tag-and-publish flow, post-publish verification, ClawHub manual push, and rollback procedures. Any maintainer about to push a `v*` tag should walk that runbook end-to-end.

### Release discipline (non-negotiable)

The runbook documents five durable rules that prevent the v1.0 retraction failure mode from recurring. Summary for fast reference:

1. **PyPI/npm versions are immutable** (registry-enforced).
2. **Tags are immutable after publish** — never force-move a `v*` tag once the registry has the artifact.
3. **All errata go to the next version** — never patch in place. Doc-only fixes ship as PEP 440 `.postN`; code fixes ship as the next alpha/beta/rc/patch.
4. **Tag protection on GitHub** for pattern `v*`.
5. **No `--force` on `main` or release branches, ever.**

Pre-1.0: no release branches; tag-and-publish from `main` HEAD. Only the active alpha horizon should have an open release milestone. **At stable GA: cut `release/v1.x`** and patch releases ship from there. See [the runbook §Release-branch strategy](docs/internal/release-cadence.md#release-branch-strategy) for the full cutover procedure.

---

## Credential rotation

External-registry credentials used by CI to publish stigmem artifacts rotate on a **90-day cadence**, owned by the founder through the v0.9.0aN alpha series. The cadence balances rotation hygiene against the operational cost of regenerating + redistributing tokens.

### Active credentials

| Credential | GH secret name | Scope | Created | Rotate by | Owner |
|---|---|---|---|---|---|
| npm granular access token | `NPM_TOKEN` | Read+Write on `@eidetic-labs/*` (scope-level) | 2026-05-08 | **2026-08-06** | @offbyonce |
| PyPI API token / OIDC trusted publisher | `PYPI_API_TOKEN` (if token) or n/a (if OIDC) | `stigmem`, `stigmem-py`, `stigmem-node` projects | _pending #45_ | _90 days from creation_ | @offbyonce |

### Rotation procedure

1. **Generate replacement** at the registry (npm Settings → Access Tokens → Generate New Token; or PyPI account settings → API tokens → Add API token). New token uses naming convention `<repo>-gh-actions-<purpose>-<YYYY-MM-DD>` (e.g., `stigmem-gh-actions-publish-2026-08-06`).
2. **Update GH repo secret** at `eidetic-labs/stigmem` → Settings → Secrets and variables → Actions. Edit the existing `NPM_TOKEN` (or `PYPI_API_TOKEN`) and paste the new value. The secret name stays the same; the value is rotated in place.
3. **Verify CI can publish** — manually trigger the `publish.yml` workflow (or wait for the next tag push) and confirm the publish step succeeds with the new token.
4. **Revoke the old token** at the registry. **Do not** revoke before step 3 confirms the new token works — race window for failed publishes.
5. **Update this file** with the new "Created" + "Rotate by" dates.

### Authentication path-of-least-privilege

The CI tokens above grant publish authority to GitHub Actions runs on tagged releases. Human maintainers do **not** use these tokens for ad-hoc publishes — they use their own personal credentials with team-membership-based permissions (npm `@eidetic-labs:publishers` team for npm; PyPI maintainer access for PyPI). Compromise of the GH secret does not compromise founder/contributor personal accounts and vice versa.

### Compromise response

If a CI token is suspected compromised:

1. **Revoke immediately** at the registry (do not wait for rotation cadence).
2. **Audit recent publishes** for that scope — npm registry shows a per-version publisher; PyPI shows uploader email per release.
3. **Yank or unpublish unauthorized versions** within the registry's allowed window (npm: 72h since publish; PyPI: PEP 592 yank, no time limit).
4. **Generate replacement** per Rotation procedure §1–3.
5. **File an incident note** in `docs/internal/incidents/` (per v0.9.0aN operator-hardening doc work) describing the incident, the response, and any operator-visible impact.

---

## Updating this file

- **Adding an entry:** the person being added must explicitly consent in writing (via PR comment, email, or other auditable channel). The PR must reference the consent.
- **Modifying an entry:** the entry's holder approves the change.
- **Removing an entry (voluntary):** the entry's holder may remove themselves at any time without further approval.
- **Removing an entry (involuntary):** treat as a governance change requiring an ADR amendment.

---

*Last updated: 2026-05-08. Updated per [ADR-001 § *Contributor approval rule*](docs/adr/001-versioning.md). Credential-rotation section added 2026-05-08 alongside the first NPM_TOKEN registration.*
