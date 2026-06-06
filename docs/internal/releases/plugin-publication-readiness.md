# Plugin Publication Readiness

**Status:** active
**Release owner:** maintainer
**Milestone:** plugin publication readiness
**Tag / release:** not applicable
**Last updated:** 2026-05-23

## Release Intent

This horizon prepares standalone experimental plugin artifacts for publication
after the `v0.9.0a8` alpha extraction train. It is not a new alpha release, a
beta opening, an ADR-008 graduation, or a stable-support claim.

The goal is narrower: make plugin packages publishable with clear metadata,
default-disabled behavior, enabled-mode conformance, security posture, and
release evidence before any standalone plugin artifact reaches a registry.

## Scope Summary

| Area | In scope | Out of scope | Canonical references |
| --- | --- | --- | --- |
| Publication policy | Define which plugins may publish, under what labels, and with what evidence. | Declaring plugins supported or stable. | ADR-008, ADR-011, ADR-011, ADR-020 |
| Package metadata | Standardize package names, versions, manifests, entry points, READMEs, and compatibility declarations. | Moving implementation directories for cosmetic reasons. | `features/<feature>/`, `experimental/<feature>/` |
| Default-disabled behavior | Prove each plugin returns no-op/pass-through decisions when disabled or unconfigured. | Enabling plugins by default. | plugin handlers, plugin tests |
| Enabled-mode conformance | Prove enabled plugin behavior matches the feature record and security notes. | Completing future ADR-008 30-day soak or documentation-parity gates. | feature evidence/security records |
| Release evidence | Define and validate artifact signatures, provenance, package registry state, and release-note language. | Publishing without maintainer clearance. | `docs/docs/operators/release-verification.md`, `release/version-surfaces.yaml` |

## Detailed Scope

### Goal 1 - Close Out the Alpha Extraction Train

**Issue:** [#649](https://github.com/eidetic-labs/stigmem/issues/649)

**Objective:** make current docs accurately state that `v0.9.0a8` shipped and
that plugin publication is the next active horizon.

**Included changes:**
- Mark `v0.9.0a8` as historical in internal release roadmaps.
- Mark the alpha extraction train as complete through `v0.9.0a8`.
- Update public release-readiness and roadmap language so adopters do not
  infer an open beta, RC, GA, or next-alpha milestone.

**Excluded / deferred:**
- ADR edits.
- Version bumps.
- Standalone plugin publication.

**Evidence required:**
- Docs validators pass.
- No ADR files are changed.

### Goal 2 - Define the Plugin Publication Contract

**Issue:** [#647](https://github.com/eidetic-labs/stigmem/issues/647)

**Objective:** define the required package, metadata, evidence, and security
criteria every standalone experimental plugin must satisfy before publication.

**Included changes:**
- Standard plugin package checklist in
  [`docs/internal/plugin-publication-contract.md`](../plugin-publication-contract.md).
- Required manifest fields and compatibility metadata.
- Required README/install/build/test content.
- Required feature-record security/evidence/changelog updates.
- Release-note and registry labeling conventions for experimental plugins.

**Excluded / deferred:**
- Per-plugin code changes.
- Stable support or ADR-008 graduation claims.

**Evidence required:**
- Checklist is referenced from the plugin publication readiness roadmap.
- The contract defines package metadata, feature-record, behavior, security,
  release-evidence, and approval gates.
- Feature-record validators still pass.

### Goal 3 - Validate Security-Sensitive Core Plugins

**Issue:** [#651](https://github.com/eidetic-labs/stigmem/issues/651)

**Objective:** prepare the extracted security-sensitive plugins for publication
readiness review as standalone experimental artifacts.

**Included plugins:**
- `stigmem-plugin-lazy-instruction-discovery`
- `stigmem-plugin-time-travel`
- `stigmem-plugin-tombstones`
- `stigmem-plugin-memory-garden-acl`
- `stigmem-plugin-source-attestation`
- `stigmem-plugin-multi-tenant`

**Included changes:**
- Align package metadata, entry points, README files, build metadata, and source
  distribution manifests with the publication contract.
- Preserve disabled-gate no-op/pass-through behavior and enabled-mode behavior
  through existing focused plugin tests.
- Align feature records with the remaining publication hold: package metadata
  is ready, but registry publication still requires dry-run evidence and
  maintainer clearance.

**Excluded / deferred:**
- Publishing artifacts before maintainer clearance.
- ADR-008 graduation.

**Evidence required:**
- `node/tests/plugins/test_security_plugin_publication_contract.py` validates
  package metadata, entry points, README presence, build metadata, source
  distribution manifests, and feature-record publication state.
- Focused plugin tests pass.
- Feature security/evidence records identify residual risks and publication
  state consistently.

### Goal 4 - Decide Adapter and Tooling Plugin Publication Order

**Issue:** [#650](https://github.com/eidetic-labs/stigmem/issues/650)

**Objective:** separate adapter/tooling plugin publication readiness from
security-sensitive core plugin readiness so the launch train does not sprawl.

**Included surfaces:**
- MCP, Obsidian, Cognee, Letta, Zep, Gemini, OpenAI-compatible tools,
  Paperclip, dashboard, evaluation harness, and deployment helpers.

**Included changes:**
- Classify each surface as publish-now, hold, or defer in
  [`docs/internal/plugin-publication-disposition.md`](../plugin-publication-disposition.md).
- Define per-surface missing live validation.
- Avoid publishing adapter artifacts that cannot be meaningfully validated.

**Excluded / deferred:**
- Treating every migrated feature record as a publishable package.
- Creating unsupported package promises.

**Evidence required:**
- Internal tracker identifies publication disposition for each adapter/tooling
  surface.
- Public docs continue to mark experimental surfaces accurately.

### Goal 5 - Dry-Run and Publish Approved Plugin Artifacts

**Issue:** [#648](https://github.com/eidetic-labs/stigmem/issues/648)

**Objective:** after Goals 2-4 land, dry-run and publish only the plugins that
meet the publication contract and receive maintainer clearance.

**Included changes:**
- Build/package dry-runs for security-sensitive plugin source packages.
- No-publication disposition because no plugin has explicit maintainer
  clearance for registry publication.
- Registry provenance, signature verification, release evidence, post-publish
  verification, and rollback/yank instructions remain future publication
  requirements for any later approved artifact.

**Excluded / deferred:**
- Publishing plugins that fail the contract.
- Publishing by implication from source-package existence.

**Evidence required:**
- Dry-run commands and hashes are captured in
  [`docs/internal/plugin-publication-dry-run.md`](../plugin-publication-dry-run.md).
- No published package metadata exists for this goal.
- Public docs continue to state that plugin and adapter surfaces are
  experimental, opt-in, held, or deferred.

## Artifact Surfaces

| Surface | Expected artifact | Status | Evidence |
| --- | --- | --- | --- |
| Security-sensitive plugins | Standalone experimental packages after readiness review | Active | Goals 2-3 |
| Adapter/tooling plugins | Publication disposition before package launch | Active | Goal 4 |
| Core release artifacts | Already published through `v0.9.0a8` | Complete | `v0.9.0a8` release |
| GitHub issues/milestone | Goal workflow tracking | Active | plugin publication readiness milestone |

## Security and Risk Posture

Publication readiness does not change plugin stability. Published plugins
remain experimental unless a future ADR-008 graduation completes all required
gates. Security-sensitive plugins must preserve default-disabled behavior,
state residual risk in their feature security records, and avoid implying
shared-node, federation, or operator-soak readiness where that evidence is not
present.

Security publication policy remains unchanged: Critical/High disclosures use
GHSA where applicable; Medium/Low findings remain in `SECURITY.md` unless a
documented risk-profile, reporter-coordination, or downstream-compliance
carve-out applies.

## Evidence Gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| Alpha closeout | a8 docs marked historical and release-readiness updated. | Active |
| Publication contract | Standard checklist and package evidence requirements exist. | Complete for baseline contract |
| Security-sensitive plugin readiness | Each plugin has package metadata, disabled behavior, enabled behavior, and security evidence reviewed. | Complete for source-package readiness; publication remains blocked on Goal 5 dry-run evidence and maintainer clearance. |
| Adapter/tooling disposition | Each adapter/tooling surface is classified before publication. | Complete for publication-order classification; hold/defer surfaces still require follow-up validation before any Goal 5 publication action. |
| Publish clearance | Maintainer approval, dry-runs, provenance/signature evidence, and post-publish verification. | Dry-run complete; no publication approved or executed. |

## Release Notes Candidates

No release notes are published for this closeout because no plugin artifact was
published. When a future plugin artifact ships, release notes must state that
the plugin is experimental, opt-in, and not ADR-008 graduated.

## Deferred / Follow-Up Work

| Item | Disposition | Target |
| --- | --- | --- |
| ADR-008 graduation | Deferred until all five gates pass for a feature. | post-GA / v1.x |
| Beta, RC, GA | Future gates only. | future release roadmaps |
| Next alpha release | Not opened by this readiness track. | maintainer decision |

## Historical Disposition

The readiness track is complete for the no-publication closeout: source-package
dry-runs were recorded, adapter/tooling dispositions were recorded, and all
registry publication remains blocked pending explicit maintainer clearance.
