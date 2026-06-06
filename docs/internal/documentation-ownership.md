# Documentation Ownership

This file defines where recurring release, security, and evidence facts live.
It implements the ADR-020 §12 (docs IA) rule that each topic has one canonical owner and the
ADR-020 §11 (security taxonomy) rule that security documentation should use a hub-and-link model instead
of duplicating the same analysis across multiple files.

## Canonical Homes

| Information type | Canonical home | Other files may | Other files must not |
| --- | --- | --- | --- |
| Release user/operator impact | `CHANGELOG.md` | Summarize impact and link to detailed security or release docs | Reprint full audit, evidence, or advisory tables |
| Current security posture and advisory disposition | `SECURITY.md` | Link to evidence ledgers and threat-model risks | Duplicate path/test/PR evidence |
| Finding-level evidence | `docs/internal/security-evidence-registry-*.md` | Record PRs, paths, tests, dispositions, and publication state | Become the public advisory index |
| Enduring architectural risks | `spec/security/threat-model.md` | Register cross-cutting R-XX risks and link to per-feature analysis | Add every audit finding as a risk |
| Machine-checkable mitigated-risk evidence | `spec/security/evidence-registry.json` | Support validators for mitigated threat-model risks | Carry human narrative or release notes |
| Feature facts | `features/<feature-slug>/` | Project summaries into roadmap, release, security, changelog, protocol, compatibility, and public feature docs | Maintain parallel feature dossiers in root docs, public docs, release docs, or `experimental/` |
| Strategic roadmap | `ROADMAP.md` | Link to detailed release roadmaps and milestone execution | Become a per-issue task board or release-notes draft |
| Detailed release scope | `docs/internal/releases/<version>-roadmap.md` | Define release contracts, scope, exclusions, artifacts, evidence gates, and release-note candidates | Replace GitHub issues for live execution |
| Release readiness | GitHub issues, milestones, and `docs/docs/operators/release-readiness.md` | Feed tag-time checks and public/operator status summaries | Be manually mirrored in several prose trackers |
| Private or embargoed staging | `Internal-Comms/stigmem/security/drafts/` | Hold unpublished publication drafts | Preserve post-publication snapshots of public docs |
| Architecture decisions | `docs/adr/` | Be linked from IC and planning docs | Be duplicated under Internal-Comms after publication |
| Roadmap/release document format | `docs/internal/roadmap-standards.md` | Be linked from release docs and review checklists | Drift into undocumented local conventions |
| Feature record migration sequencing | `docs/internal/features/feature-record-migration.md` | Track PR slicing, pilot migrations, and transition validation | Amend ADR-020 or become the canonical feature record itself |

## Document Classes

Every non-code document should fit one of these classes. If a document does not
fit, either move it to the correct class or add an explicit row here before it
becomes a second source of truth.

| Class | Owner | Examples | Rule |
| --- | --- | --- | --- |
| Public orientation | Root/public docs | `README.md`, `LIMITATIONS.md`, `SECURITY.md`, `CONTRIBUTING.md`, `OPERATING.md` | Summarize current posture and link to deeper owners. |
| Public history | Root changelog and release notes | `CHANGELOG.md`, `release-notes/archive/` | Record what shipped; do not plan future work. |
| Strategic planning | Roadmap and internal release roadmaps | `ROADMAP.md`, `docs/internal/releases/` | Preserve horizon and release contracts; do not become issue trackers. |
| Feature-owned records | `features/<feature>/` | `README.md`, `spec.md`, `status.md`, `evidence.md`, `security.md`, `changelog.md` | Own detailed feature truth and feed projections. |
| Projection surfaces | Generated or curated summaries | `SECURITY.md`, `CHANGELOG.md`, `spec/PROTOCOL.md`, `docs/docs/reference/experimental-features.md`, compatibility docs | Summarize feature records, specs, or registries; never own conflicting detail. |
| Operator/user guides | Docs site and operator runbooks | `docs/docs/**`, `OPERATING.md`, `deploy/**` | Explain how to use the current product; link to feature records for detailed status. |
| Maintainer runbooks | `docs/internal/` | `release-cadence.md`, `development.md`, `evidence-maintenance.md` | Describe repo operations and release mechanics; avoid product-roadmap scope. |
| Analysis and evidence | `docs/internal/*analysis*`, `docs/internal/*evidence*`, `spec/security/` | Security evidence registries, dependency scans, extraction analyses | Capture proof, one-shot analysis, and enduring risk records; link to public summaries. |
| Archive/historical snapshots | `archive/`, `docs/archive/`, `spec/archive/` | Retraction post source, old docs snapshots, evolution specs | Preserve history with archive framing; not a current source of truth. |
| Templates/examples | Feature template and examples | `features/feature-template/`, example configs | Define structure or show usage; not a canonical product claim. |

## Current Ownership Inventory

### Root and Release Files

| Path | Class | Owner / source of truth | Projection or dependency |
| --- | --- | --- | --- |
| `README.md` | Public orientation | Root project overview | Summarizes `LIMITATIONS.md`, `ROADMAP.md`, `SECURITY.md`, and feature/spec state. |
| `LIMITATIONS.md` | Public orientation | Current adopter constraints | Links to roadmap, threat model, and feature/security owners. |
| `SECURITY.md` | Public security index / projection | Security posture and public advisory disposition | Projects feature security records and links to evidence registries. |
| `CHANGELOG.md` | Public history / projection | Root release history | Projects feature-local changelogs during release prep. |
| `ROADMAP.md` | Strategic planning | Public strategic horizon | Links to internal release roadmaps for detailed release contracts. |
| `CONTRIBUTING.md` | Public orientation | Contributor workflow | Links to ADRs, feature records, and docs standards where needed. |
| `OPERATING.md` | Operator guide | Operational quick reference | Links to docs-site runbooks and release verification guidance. |
| `MAINTAINERS.md` | Public orientation | Maintainer roles and contact paths | Does not duplicate release/security policy. |
| `CODE_OF_CONDUCT.md` | Public governance | Community behavior policy | Stable standalone policy. |
| `LOG.md` | Public history | Lightweight project progress notes | Must not replace changelog or roadmap. |

### Feature and Spec Files

| Path | Class | Owner / source of truth | Projection or dependency |
| --- | --- | --- | --- |
| `features/<feature>/README.md` | Feature-owned record | Feature metadata and overview | Feeds feature matrix and public docs summaries. |
| `features/<feature>/spec.md` | Feature-owned record | Feature-level normative behavior | Links to modular spec pages or experimental compatibility paths. |
| `features/<feature>/status.md` | Feature-owned record | Lifecycle state and known gaps | Feeds release readiness and roadmap summaries. |
| `features/<feature>/evidence.md` | Feature-owned record | Implementation/test/evidence paths | Feeds security and release evidence summaries. |
| `features/<feature>/security.md` | Feature-owned record | Feature-specific security posture | Feeds `SECURITY.md` projection. |
| `features/<feature>/changelog.md` | Feature-owned record | Feature-local change history | Feeds `CHANGELOG.md` projection. |
| `spec/specs/` | Normative specification | Modular protocol component specs | Composed into `spec/PROTOCOL.md` and rendered docs. |
| `experimental/<feature>/` | Implementation / compatibility wrapper | Feature implementation until package promotion | Must point at `features/<feature>/` once the feature record exists. |

### Internal Maintainer Files

| Path | Class | Owner / source of truth | Projection or dependency |
| --- | --- | --- | --- |
| `docs/internal/documentation-ownership.md` | Maintainer runbook | Documentation ownership rules | Checked by `scripts/check_documentation_ownership.py`. |
| `docs/internal/feature-tracker.md` | Maintainer inventory | Feature migration and implementation-path inventory | Checked by `scripts/check_feature_records.py`. |
| `docs/internal/features/feature-record-migration.md` | Maintainer transition record | Feature-record migration sequencing and closeout | Maintenance-mode transition history only. |
| `docs/internal/roadmap-standards.md` | Maintainer standard | Roadmap and release-roadmap format | Controls `ROADMAP.md` and `docs/internal/releases/`. |
| `docs/internal/plugin-publication-contract.md` | Maintainer standard | Standalone experimental plugin publication gates | Controls plugin artifact readiness; does not grant ADR-008 graduation. |
| `docs/internal/plugin-publication-disposition.md` | Maintainer tracker | Adapter/tooling publication order and disposition for the active plugin readiness milestone | Feeds Goal 4 and Goal 5 planning; does not publish artifacts or override feature records. |
| `docs/internal/plugin-publication-dry-run.md` | Maintainer evidence | Goal 5 dry-run build evidence and no-publication disposition | Records local dry-runs and registry-blocking state; not a release note or published artifact manifest. |
| `docs/internal/releases/` | Strategic planning | Per-release contracts and historical release scope | Links back to `ROADMAP.md` and `CHANGELOG.md`. |
| `docs/internal/release-cadence.md` | Maintainer runbook | Release publishing sequence | Does not define release scope. |
| `docs/internal/development.md` | Maintainer runbook | Local development workflow | Does not own product behavior. |
| `docs/internal/evidence-maintenance.md` | Analysis/evidence | Recurring evidence owner/trigger matrix | Feeds release gates. |
| `docs/internal/major-version-holds.md` | Analysis/evidence | Dependency major-version hold register | Feeds dependency-currency checks. |
| `docs/internal/security-evidence-registry*.md` | Analysis/evidence | Human-readable security evidence ledgers | Links from `SECURITY.md`; does not replace it. |
| `docs/internal/*analysis*.md` | Analysis/evidence | One-shot design or migration analysis | Should be cited by owner docs, not copied into them. |
| `docs/internal/*best-practices*.md` | Maintainer standards | Internal engineering standards | Feed CI/checklist work; do not become public policy. |

### Generated and Archive Files

| Path | Class | Owner / source of truth | Projection or dependency |
| --- | --- | --- | --- |
| `docs/docs/reference/api/generated/` | Projection surface | Generated from OpenAPI | Regenerate from code; do not hand-edit product truth. |
| `spec/PROTOCOL.md` | Projection surface | Generated/validated composition of modular specs and feature records | Checked by feature protocol projection validators. |
| `docs/compatibility-matrix.yaml` | Projection surface | Compatibility matrix projection | Checked by feature compatibility validator. |
| `archive/` | Archive/historical snapshots | Historical public artifacts | Must keep archive framing. |
| `docs/archive/` | Archive/historical snapshots | Historical docs snapshots and superseded pages | Not current guidance. |
| `spec/archive/` | Archive/historical snapshots | Evolutionary spec snapshots | Not current normative protocol. |

## Release Security Rule

For a security release:

1. `SECURITY.md` is the public disposition index.
2. `CHANGELOG.md` records the release-impact summary.
3. The dated evidence registry records proof and lineage.
4. The threat model changes only when a finding exposes an enduring
   architectural risk class.
5. Internal-Comms drafts are deleted or trimmed to still-embargoed residue in
   the same coordinated publication batch.

## Review Checklist

Before merging a docs PR that touches release, security, or evidence material:

- Identify the canonical owner for each fact being added.
- Replace duplicate prose with links to the canonical owner.
- For feature facts, update `features/<feature-slug>/` once the feature has
  migrated to the ADR-020 structure.
- Keep summaries short in non-owner files.
- If a public artifact graduated from Internal-Comms, cross-link the public PR
  and IC cleanup PR.
- Run the relevant evidence and docs validators named by the changed files.

## Validation

Run the ownership validator from the repository root:

```bash
python3 scripts/check_documentation_ownership.py
```

The validator ensures that the high-signal recurring documentation owners remain
listed here. It is intentionally a boundary ratchet, not an exhaustive index of
every generated API page, archive snapshot, or feature file.
