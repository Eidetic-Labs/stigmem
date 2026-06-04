# Feature Record Migration Plan

**Status:** complete; retained as a maintenance control
**Owner:** maintainers
**ADR:** [ADR-020](../../adr/020-feature-owned-product-structure.md)
**Last updated:** 2026-05-21

This plan implemented ADR-020 without putting migration sequencing into the
ADR. The migration is complete for the current identified inventory: feature
truth lives in uniform feature records, while root, public, protocol, release,
and security documents act as hubs or projections.

## Goals

1. Establish the feature record scaffold and validator.
2. Migrate a small pilot set that proves both core and plugin-backed patterns.
3. Migrate remaining feature facts from `spec/specs/`, `docs/docs/`,
   `experimental/`, release roadmaps, security docs, and changelog entries.
4. Convert high-level documents into concise hubs or generated/curated
   projections.
5. Remove transition allowlists once the legacy inventory is migrated.

## Non-Goals

- Do not rewrite accepted ADRs as part of migration.
- Do not move Python package code unless the package/import stability impact has
  been reviewed.
- Do not use this plan as a release task board; GitHub issues and milestones
  remain the live execution system.
- Do not publish embargoed security detail from Internal-Comms.

## Source-of-Truth Rules

| Fact type | Canonical owner after migration | Projection or summary surfaces |
| --- | --- | --- |
| Feature overview, maturity, owner, and implementation path | `features/<feature>/README.md` | Public feature matrix, release roadmap, compatibility matrix |
| Feature behavior | `features/<feature>/spec.md` | `spec/PROTOCOL.md`, `spec/specs/*.md`, public concept docs |
| Feature lifecycle and gates | `features/<feature>/status.md` | `ROADMAP.md`, release roadmap, public experimental index |
| Feature implementation proof | `features/<feature>/evidence.md` | Release evidence gates, internal evidence registries |
| Feature-specific security analysis | `features/<feature>/security.md` | `SECURITY.md`, threat model, advisory index |
| Feature-local history | `features/<feature>/changelog.md` | Root `CHANGELOG.md`, release notes |

## Migration Phases

### Phase 0: Scaffold and advisory validation

Status: complete.

Deliverables:

- `features/README.md` defines the registry and metadata contract.
- `features/feature-template/` defines the required six-file shape.
- `scripts/check_feature_records.py` validates migrated feature records.
- `scripts/check.sh docs` runs the feature record validator.

Exit criteria:

- The docs check passes with no migrated feature directories.
- The validator fails on incomplete migrated feature directories.
- Documentation ownership names feature records as the canonical home for
  feature facts.

### Phase 1: Pilot feature records

Status: complete.

Pilot set:

| Feature | Type | Why |
| --- | --- | --- |
| `content-addressed-ids` | core | Proves the core feature pattern and protocol/spec projection path. |
| `time-travel` | plugin | Proves plugin-backed and experimental metadata without using an experimental docs category. |

Exit criteria:

- Both pilot records include all six files and pass validation.
- Existing legacy paths link to the pilot feature records instead of duplicating
  the same detail.
- Release roadmap entries reference pilot feature records for implementation
  detail.

Progress:

- `features/content-addressed-ids/` added as the pilot core feature record.
- `features/time-travel/` added as the pilot plugin-backed feature record.
- `spec/specs/21-content-addressed-ids.md` and `experimental/time-travel/`
  spec/status/security files now act as compatibility pointers.

### Phase 2: Inventory and migrate remaining feature families

Status: complete.

Inventory sources:

- `spec/specs/*.md`
- `experimental/*/spec.md`
- `experimental/*/STATUS.md`
- `experimental/*/security.md`
- `docs/docs/concepts/features.md`
- `docs/docs/reference/experimental-features.md`
- `docs/internal/feature-tracker.md`
- release roadmaps under `docs/internal/releases/`
- root `CHANGELOG.md` and `SECURITY.md`

Exit criteria:

- Every identified feature has a feature record or an explicit documented
  disposition of `deferred` or `superseded`.
- Legacy files are wrappers, indexes, or projections rather than independent
  owners of feature detail.
- The feature tracker is an inventory with validated migrated rows.

Progress:

- `docs/internal/feature-tracker.md` now tracks feature id, target record,
  legacy owner, migration status, feature type, stability, default surface,
  canonical spec, horizon, and notes.
- `scripts/check_feature_records.py` validates that `migrated` inventory rows
  correspond to complete feature records.
- Security-sensitive records for `tombstones`, `source-attestation`, and
  `lazy-instruction-discovery` now migrate R-16/R-17, R-22, and R-15/R-21
  feature analysis into feature records.
- Protocol-bearing `0.9.xA` records for `memory-garden-acl`, `subscriptions`,
  `intent-envelope`, `decay`, `synthesis`, and `recall-graph` now own their
  Spec-X detail under `features/<feature>/`.
- `multi-tenant` now owns opt-in tenant-scoping behavior, evidence, and
  R-01/R-02/R-21 security contributions under `features/multi-tenant/`.
- `async-jobs` now owns shared lint/decay background job lifecycle, polling,
  evidence, and open queue-control gaps under `features/async-jobs/`.
- `fuzzy-resolver` now owns entity-resolution behavior, alias-management
  evidence, and resolver security gaps under `features/fuzzy-resolver/`.
- `oidc-sso` now owns OIDC exchange behavior, token-validation evidence, and
  M5/L5 security disposition references under `features/oidc-sso/`.
- `storage-backends` now owns backend-selection behavior, adapter evidence, and
  R-04/R-08 storage security posture under `features/storage-backends/`.
- Every identified non-deferred row in `docs/internal/feature-tracker.md` now
  has a canonical feature record under `features/<feature>/`.
- `billing` remains explicitly `deferred` as a future-gate business feature,
  not a pending migration row.

### Phase 3: Projection tooling

Status: complete.

Projection candidates:

| Projection | Source |
| --- | --- |
| Public feature matrix | Feature `README.md` metadata and `status.md` summaries |
| Experimental feature index | Feature metadata where `stability: experimental` or `default_surface: experimental` |
| `SECURITY.md` feature-security section | Feature `security.md` summaries and advisory refs |
| Root `CHANGELOG.md` release candidates | Feature `changelog.md` entries |
| Compatibility matrix | Feature metadata, package surfaces, and release lines |
| Protocol index | Feature `spec.md` metadata and canonical spec identifiers |

Exit criteria:

- At least one projection is generated or mechanically checked.
- Projection checks run in CI.
- Manual projections include a freshness check or explicit review checklist.

Progress:

- `scripts/check_feature_projections.py` mechanically checks that migrated
  feature records are represented in the public feature matrix and that
  experimental/default-off migrated records are represented in the public
  experimental feature index.
- `scripts/check_feature_security_projection.py` mechanically checks that
  `SECURITY.md` keeps the advisory-publication policy, internal audit
  dispositions, and feature-security index aligned with migrated feature
  records.
- `scripts/check_feature_changelog_projection.py` mechanically checks that
  root `CHANGELOG.md` carries feature-changelog links, release-line metadata,
  and status projections for migrated feature records without duplicating
  feature-local history.
- `scripts/check_feature_compatibility_projection.py` mechanically checks that
  `docs/compatibility-matrix.yaml` and the public operator compatibility page
  carry feature-record links, release-line metadata, stability, surface, type,
  package, and implementation projections for migrated feature records.
- `scripts/check_feature_protocol_projection.py` mechanically checks that
  feature `canonical_spec` metadata is represented in generated
  `spec/PROTOCOL.md`, that feature specs name their canonical Spec-* id, and
  that features without a protocol assignment explicitly state the absence of a
  Spec-X assignment.
- `scripts/check.sh docs` runs the feature projection checks after validating
  feature records.

### Phase 4: Strict validation

Status: complete for the current inventory; ongoing for new work.

Exit criteria:

- CI validates the complete feature inventory, not only migrated directories.
- Transition allowlists are empty.
- New feature PRs must include a feature record before merge.

Progress:

- `scripts/check_feature_records.py` now validates the complete migration
  inventory against existing feature records and top-level experimental
  implementation directories, not only rows already marked `migrated`.
- Migrated inventory rows now project core metadata from the canonical feature
  `README.md`; title, type, stability, default surface, and canonical spec must
  match before docs checks pass.
- `features/README.md` now documents the strict validation contract for new
  feature work and migrated rows.
- `storage-libsql` now has a canonical adapter-specific feature record under
  `features/storage-libsql/`; legacy experimental docs remain compatibility
  pointers until their operator guidance is promoted or retired.
- `mcp-adapter` now has a canonical adapter feature record under
  `features/mcp-adapter/`; package alignment and connector validation remain
  future alpha release-line gates.
- `sdk-go` now has a canonical SDK feature record under `features/sdk-go/`;
  API parity, package alignment, and live-node smoke validation remain future
  alpha release-line gates.
- `obsidian-adapter` now has a canonical adapter feature record under
  `features/obsidian-adapter/`; package, plugin, threat-model, and live-vault
  validation remain future alpha release-line gates.
- `cognee-adapter` now has a canonical adapter feature record under
  `features/cognee-adapter/`; ownership, package, dependency, and live Cognee
  validation remain future alpha release-line gates.
- `letta-adapter` now has a canonical adapter feature record under
  `features/letta-adapter/`; package metadata and mocked validation are
  complete for v0.9.0a10, while live Letta validation remains
  design-partner/operator-owned for v0.1.0.
- `zep-adapter` now has a canonical adapter feature record under
  `features/zep-adapter/`; package metadata and mocked validation are complete
  for v0.9.0a10, while live Zep validation remains
  design-partner/operator-owned for v0.1.0.
- `gemini-adapter` now has a canonical adapter feature record under
  `features/gemini-adapter/`; package metadata and mocked validation are
  complete for v0.9.0a10, while live Gemini validation remains
  design-partner/operator-owned for v0.1.0.
- `ollama-litellm-adapter` now has a canonical compatibility feature record
  under `features/ollama-litellm-adapter/`; implementation detail is
  consolidated under the OpenAI-compatible tools adapter.
- `openai-tools-adapter` now has a canonical adapter feature record under
  `features/openai-tools-adapter/`; package metadata and mocked validation are
  complete for v0.9.0a10, while live LiteLLM, OpenAI SDK, and Ollama validation
  remain operator-owned for v0.1.0.
- `paperclip-adapter` now has a canonical adapter feature record under
  `features/paperclip-adapter/`; installation, ownership, live Paperclip, and
  security validation remain future alpha release-line gates.
- `dashboard` now has a canonical tooling feature record under
  `features/dashboard/`; dependency currency, auth/session, live-node, and
  deployment posture remain future alpha release-line gates.
- `eval-harness` now has a canonical tooling feature record under
  `features/eval-harness/`; the `eval/` implementation, corpus, Make targets,
  and path-filtered CI now form the active internal a11 foundation surface,
  while standalone package publication remains a future release-line gate.
- `deploy-helm` now has a canonical deployment feature record under
  `features/deploy-helm/`; chart publication, live cluster validation,
  hardening review, and ownership remain future alpha release-line gates.
- `deploy-fly` now has a canonical deployment feature record under
  `features/deploy-fly/`; live Fly deployment, persistence, dashboard
  validation, secrets review, and ownership remain future alpha release-line
  gates.
- `deploy-grafana` now has a canonical deployment feature record under
  `features/deploy-grafana/`; live observability stack validation, metric
  review, alert review, packaging, and ownership remain future alpha
  release-line gates.
- `deploy-paas` now has a canonical deployment feature record under
  `features/deploy-paas/`; live platform validation, persistence, secrets,
  scaling/cost review, and ownership remain future alpha release-line gates.
- `deploy-systemd` now has a canonical deployment feature record under
  `features/deploy-systemd/`; live distro validation, installer review,
  hardening review, upgrade/rollback, offline install, and ownership remain
  future alpha release-line gates.
- `scripts/check_docs_drift.py` prevents reintroducing `pending` feature
  inventory rows, stale deploy-path references, and retracted-release labels in
  live docs outside approved historical posture files.

## Maintenance Mode

New feature work must choose one of three explicit states before merge:

- Add a complete six-file feature record under `features/<feature>/` and mark
  the inventory row `migrated`.
- Mark the inventory row `deferred` with a clear future-gate reason.
- Mark the inventory row `superseded` and point to the canonical replacement.

Do not add new `pending` rows. A `pending` state was useful during migration,
but after the initial inventory closure it reintroduces unclear ownership.

## Release Horizon Alignment

The migration should follow the release horizon, not overwrite it.

| Horizon | Feature-record work |
| --- | --- |
| `v0.9.0a1` and `v0.9.0a2` historical docs | Link shipped feature detail to feature records as features migrate. Do not rewrite history to claim later work shipped. |
| `v0.9.0a3` and `v0.9.0a4` shipped alpha releases | Preserve feature detail and release evidence without rewriting history to claim later work shipped earlier. |
| Future `0.9.xA` alpha phases | Use feature records for detailed implementation plans and release roadmaps for version-specific contracts. |
| Beta, RC, and GA | Remain future gates until explicitly opened. |

## PR Slicing

1. Scaffold registry, template, migration plan, and validator.
2. Add pilot core and plugin-backed feature records.
3. Convert the internal feature tracker into a validated migration inventory.
4. Convert public feature matrix and experimental index into projections or
   hub documents.
5. Convert security and changelog summaries to pull from feature records.
6. Migrate remaining feature families and remove transition exceptions.
7. Close the migration inventory and enforce maintenance-mode drift checks.

Each PR should describe the canonical owner being introduced or changed. PR and
commit text should avoid blame language; describe the structural correction and
the source-of-truth effect.
