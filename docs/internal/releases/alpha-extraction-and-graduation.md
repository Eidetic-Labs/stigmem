# Alpha Extraction and Graduation Reference

**Status:** maintainer reference
**Release owner:** maintainer
**Milestone:** not applicable
**Tag / release:** not applicable
**Last updated:** 2026-05-22

## Release Intent

This document preserves the alpha extraction and ADR-008 graduation process
that previously lived in `ROADMAP.md`. It is a maintainer reference for the
alpha series and post-GA graduation review; it is not an active release
contract by itself.

## Scope Summary

| Area | In scope | Out of scope | Canonical references |
| --- | --- | --- | --- |
| Alpha extraction | Opt-in experimental plugin extraction during `v0.9.0aN` | Supported/stable graduation | ADR-011, ADR-011 |
| ADR-008 graduation | Five-gate supported-surface promotion review | Bypassing gates during alpha | ADR-008 |
| Review checklist | Founder/contributor graduation review artifacts | Live issue tracking | feature records, compatibility matrix |

## Detailed Scope

## Experimental Extraction vs. Graduation

The alpha series and ADR-008 describe two different moves:

- **Alpha extraction (`v0.9.0aN`)** moves feature-specific code and spec text out of core and into opt-in experimental plugin packages. This preserves the v1.0.0 default-install scope while making the experimental feature easier to test. It does **not** make the feature supported, stable, or default-on.
- **ADR-008 graduation (`v1.x.y`, post-GA)** promotes an experimental feature into the supported surface after the five reintroduction gates pass. For cross-cutting features, the plugin remains a plugin; graduation changes its support/trust tier, not its architectural home.

### Alpha Extraction Process

During the alpha series, a feature can be extracted into an opt-in experimental plugin when the extraction preserves default-install behavior and the package is clearly marked as experimental.

Required extraction artifacts:

| Artifact | Purpose |
| --- | --- |
| Plugin package | `stigmem-plugin-<feature>` package with manifest, hook registrations, and tests |
| Spec placement | `experimental/<feature>/spec.md` remains the authoritative experimental spec text |
| Status file | `experimental/<feature>/STATUS.md` records extraction status, known gaps, and ADR-008 gate status |
| Compatibility note | Docs state that the plugin is opt-in, experimental, and not part of the stable/default surface |
| Changelog entry | Records the extraction and any migration instructions for existing alpha users |

Extraction should include targeted tests for the plugin boundary and default-install no-op behavior. It does not require the ADR-008 30-day soak.

### ADR-008 Graduation Process

When does a spec move from `Spec-X*` (experimental) toward `Spec-NN` (supported/core spec)?

Per [ADR-008](../../adr/008-experimental-gates.md): **all five gates pass.** Each gate produces a concrete artifact; only after the founder (or two contributors per ADR-001 §Contributor approval rule) signs off on all five does the feature graduate into the supported surface.

### The Five Gates

| # | Gate | Artifact |
| --- | --- | --- |
| 1 | Threat-model delta | `experimental/<feature>/security.md` per ADR-020 §11 (security taxonomy), merged into `spec/security/threat-model.md` |
| 2 | ADR drafted and merged | `docs/adr/NNN-<feature>.md` |
| 3 | Conformance vectors | `data/conformance/<feature>/` including adversarial cases |
| 4 | 30-day external operator soak | LOG.md entry in this repo with at least one closed issue tagged `<feature>-soak-finding` |
| 5 | Documentation parity | Pages across all four tabs (Learn / Build / Operate / Secure) per [ADR-020](../../adr/020-feature-owned-product-structure.md) §12 (docs IA) |

Order matters per ADR-008: 1 before 2, 3 before 4, 5 last. Skipping requires explicit two-contributor sign-off recorded in the feature's ADR.

### What Changes During Alpha Extraction

Using `Spec-X1-Lazy-Instruction-Discovery` as the worked case:

| Surface | Before extraction (`v0.9.0a1`) | After extraction on `main`, before plugin artifact launch |
| --- | --- | --- |
| Spec content | `experimental/lazy-instruction-discovery/spec.md` (Spec-X1) | Remains experimental under `experimental/lazy-instruction-discovery/spec.md` until a future ADR-008 graduation |
| Plugin package | Not published | `stigmem-plugin-lazy-instruction-discovery` source package extracted under `experimental/lazy-instruction-discovery/`; signed/package publication evidence is deferred until the plugin launch train and tracked in [#298](https://github.com/eidetic-labs/stigmem/issues/298) |
| Default install behavior | Routes mounted but feature dormant unless configured (per LIMITATIONS §11) | Plugin is opt-in; default install is unchanged in user-visible behavior. Operators who want the feature install the plugin |
| `experimental/<feature>/STATUS.md` | `Status: Dormant`, ADR-008 gates Open | `Status: Extracted / opt-in experimental`; ADR-008 gates still Open unless separately completed |
| `ROADMAP.md` v0.9.0aN work table | This row | Lazy-instruction extraction marked complete within the broader per-feature extraction row; remaining feature extractions stay in flight |
| `concepts/features.md` | Experimental; embedded/dormant implementation acknowledged | Experimental; opt-in plugin source extracted, artifact publication deferred |
| `docs/compatibility-matrix.yaml` | `stability: experimental` for the feature | Still `stability: experimental`; source package and artifact-evidence status are explicit |
| `CHANGELOG.md` | — | Entry under `### Added` for `v0.9.0a2` noting the extraction and migration notes for alpha users |
| `spec/EVOLUTION.md` | — | Entry recording the alpha extraction while preserving `Spec-X1` status |
| `data/conformance/lazy-instruction-discovery/` | optional/empty | Targeted plugin-boundary tests; full ADR-008 conformance vectors arrive before graduation |

### What Does NOT Happen During Alpha Extraction

- The feature does **not** become default-on. Plugin architecture per [ADR-011](../../adr/011-cross-cutting-extraction.md) means extracted cross-cutting features are shipped as opt-in plugins.
- The feature does **not** become supported or stable. Stability remains experimental until ADR-008 gates pass.
- The feature does **not** move from `Spec-X*` to `Spec-NN`. That is a later graduation step.
- The ADR-008 five-gate process is **not** bypassed; it is simply not the alpha extraction gate.
- Older releases are **not** retroactively updated. `v0.9.0a1` remains a published, immutable release; the extraction lands in `v0.9.0a2`'s release artifacts.

### What the Founder Reviews at ADR-008 Graduation

A graduation PR should include:

1. The five gate artifacts above
2. The `ROADMAP.md` supported-surface update
3. The `CHANGELOG.md` entry under `### Added` for the graduating release
4. The `experimental/<feature>/STATUS.md` flip from Experimental -> Graduated with all five gate dates
5. The `concepts/features.md` row update
6. The `compatibility-matrix.yaml` update

CI rejects a graduation PR that's missing any of those artifacts (per ADR-008 §Deprecation policy deprecation-policy validator pattern + ADR-008 gate-tracking).

## Artifact Surfaces

Not applicable. This is a maintainer reference.

## Security and Risk Posture

Alpha extraction does not make a feature stable, supported, or default-on.
Graduation requires the ADR-008 gate artifacts, including threat-model delta
and documentation parity.

## Evidence Gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| Alpha extraction | Plugin package, spec placement, status file, compatibility note, changelog entry | Validated by active phase |
| ADR-008 graduation | Threat-model delta, ADR, conformance vectors, 30-day soak, documentation parity | Future gate |

## Release Notes Candidates

Not applicable. Release notes are owned by the active release roadmap and
`CHANGELOG.md`.

## Deferred / Follow-Up Work

| Item | Disposition | Target |
| --- | --- | --- |
| Graduation | Deferred until all ADR-008 gates pass | Post-GA / v1.x |

## Historical Disposition

Not applicable. This is a maintainer reference.
