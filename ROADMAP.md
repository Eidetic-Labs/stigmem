# Stigmem Roadmap

> Public roadmap for stigmem. Milestone-gated, not time-gated — version lines complete when their exit criteria are met.
>
> **Current release candidate:** v0.9.0a10. **Active horizon:** adapter batch publication readiness only; no beta, RC, or GA milestone is open (per [ADR-001](docs/adr/001-versioning.md) (versioning + per-ecosystem version-string convention)).
> **Last updated:** 2026-05-26.

---

## How this roadmap is organized

This file is the strategic roadmap: it preserves the release-line horizon,
major workstreams, and gates that open later lines. Detailed release contracts
live in [`docs/internal/releases/`](docs/internal/releases/), using the format
defined in [`docs/internal/roadmap-standards.md`](docs/internal/roadmap-standards.md).

`ROADMAP.md` should not be the per-issue task board or the release-notes draft.
GitHub milestones track live execution; `CHANGELOG.md` records what actually
shipped.

---

## Version-line model

The work is organized into sequential version lines per [ADR-001](docs/adr/001-versioning.md). Only one alpha artifact refresh is opened as an active release target at a time; future beta, release-candidate, and GA lines stay as policy horizons until alpha exit evidence justifies opening them.

| Version line | Goal |
|---|---|
| **`v0.9.0aN` — alpha series** | Single-org, single-node, audit-first scope. Artifact refreshes align ClawHub/OpenClaw alpha framing; docs site restructured; modular spec migration completed per [ADR-020](docs/adr/020-feature-owned-product-structure.md) §9 (modular specs); cross-cutting features extracted to plugins per [ADR-011](docs/adr/011-cross-cutting-extraction.md). |
| **Future beta line — hardened core** | Opens only after alpha exit evidence supports it. Every Open risk in the v1.0.0 critical-path threat model must close before beta exit: capability redesign, federation hardening, Argon2id migration, OpenClaw safety, and per-feature security colocation. The storage-immutability stack has landed on `main`; remaining hardening (Rekor anchoring cadence, mandatory SDK verify-by-default) continues in this line. No active GitHub milestone exists yet. |
| **Future release-candidate and GA lines** | Opens only after hardened-core exit. Sigstore-signed releases; reproducible builds; SBOM; external operator validation in production (per [ADR-001](docs/adr/001-versioning.md) 1.0 GA criteria). Wire format frozen. No active GitHub milestone exists yet. |
| **`v1.x.y` — post-GA expansion** | Experimental features graduate into the supported surface via [ADR-008](docs/adr/008-experimental-gates.md) reintroduction gates; cross-cutting features remain opt-in plugins per ADR-011; modular spec evolution. |

---

## Current Strategic Horizon

`v0.9.0a8` shipped the multi-tenant isolation validation release and completed
the planned alpha extraction train. Default installs collapse callers into the
single `default` tenant, while plugin-loaded deployments can opt into
tenant-scoped request context through `stigmem-plugin-multi-tenant`. The
detailed historical release contract lives in
[`docs/internal/releases/v0.9.0a8-roadmap.md`](docs/internal/releases/v0.9.0a8-roadmap.md).

`v0.9.0a10` is the current adapter batch publication-readiness release
candidate. It validates the Cognee, Gemini, Letta, OpenAI-compatible tools, and
Zep adapter packages as opt-in experimental plugins, plus the public plugin
catalog, Trusted Publisher release path, and current release-line documentation
before tag. This is not a beta/RC/GA opening and does not make any plugin
supported or stable. The detailed readiness contract lives in
[`docs/internal/releases/plugin-publication-readiness.md`](docs/internal/releases/plugin-publication-readiness.md).

The broader alpha deployment sequence remains intact. The detailed alpha-series
phase plan, including the `v0.9.0a4` through `v0.9.0a8` planned extraction
horizons and Phase A exit evidence, lives in
[`docs/internal/releases/v0.9.0-alpha-series-roadmap.md`](docs/internal/releases/v0.9.0-alpha-series-roadmap.md).

| Horizon | Strategic purpose | Status |
|---|---|---|
| `v0.9.0a3` | CID core/spec validation and the next alpha artifact refresh. | Shipped |
| `v0.9.0a4` | Time-travel query extraction into an opt-in experimental plugin; default `as_of` behavior fails closed without plugin registration. | Shipped |
| `v0.9.0a5` | RTBF tombstone extraction into an opt-in experimental plugin; default routes and filters require plugin registration. | Shipped |
| `v0.9.0a6` | Memory Garden advanced ACL extraction into an opt-in experimental plugin; basic garden CRUD and direct guards remain core. | Shipped |
| `v0.9.0a7` | Source-attestation extraction into an opt-in experimental plugin; default source checks remain inert without plugin registration. | Shipped |
| `v0.9.0a8` | Multi-tenant isolation extraction into an opt-in experimental plugin, completing the planned alpha extraction train. | Shipped |
| `v0.9.0a10` | Adapter batch publication readiness, including package metadata, feature records, conformance, release evidence, and Trusted Publisher path. | Release candidate |
| Plugin publication readiness | Standalone experimental plugin artifact readiness, including package metadata, conformance, and release evidence. | Active workstream |

---

## Future Horizon

Future beta, release-candidate, GA, and post-GA expansion work remains
milestone-gated. The detailed workstreams have been moved out of the public
roadmap and into internal future-horizon release docs:

| Horizon | Detailed plan | Gate |
|---|---|---|
| Future hardened core | [`docs/internal/releases/future-hardened-core-roadmap.md`](docs/internal/releases/future-hardened-core-roadmap.md) | Opens only after alpha exit evidence supports it. |
| Future release-candidate and GA | [`docs/internal/releases/future-rc-ga-roadmap.md`](docs/internal/releases/future-rc-ga-roadmap.md) | Opens only after hardened-core exit and a later RC observation window. |
| Post-GA expansion | [`docs/internal/releases/post-ga-expansion-roadmap.md`](docs/internal/releases/post-ga-expansion-roadmap.md) | Starts only after stable `v1.0.0` ships. |

---

## Experimental Extraction and Graduation

Alpha extraction and ADR-008 graduation are distinct lifecycle events. The
detailed process, worked example, five-gate graduation checklist, and founder
review checklist live in
[`docs/internal/releases/alpha-extraction-and-graduation.md`](docs/internal/releases/alpha-extraction-and-graduation.md).

---

## Spec naming convention

Per [ADR-020](docs/adr/020-feature-owned-product-structure.md) §9 (modular specs): the canonical spec naming is **`Spec-NN-Topic-Name`** (or **`Spec-XN-Topic-Name`** for experimental specs), with stable two-digit identifiers and descriptive names.

| Prefix | Meaning | Example |
|---|---|---|
| `Spec-NN-` | Supported protocol component spec; in-tree at `spec/specs/NN-topic-name.md` | `Spec-01-Fact-Model`, `Spec-09-Audit-Log` |
| `Spec-XN-` | Experimental spec; lives at `experimental/<feature>/spec.md` per ADR-020 §13 (repo structure)'s experimental-feature layout | `Spec-X1-Lazy-Instruction-Discovery` |

**The number is stable across renames.** If a spec's topic name changes, the number stays. New specs get the next available number; numbers are never reused.

### Why Legacy Section Numbering Is Still Visible

The original stigmem spec was a single monolithic document with sections
numbered 1 through 25. ADR-010 supersedes that model. The supported component
specs now live under `spec/specs/`, experimental specs live under
`experimental/<feature>/spec.md`, and `spec/PROTOCOL.md` is generated from
their frontmatter.

### Spec ID inventory

**Supported protocol component specs:**

| Spec ID | Topic | Legacy source material |
|---|---|---|
| `Spec-01-Fact-Model` | Atomic fact model | Legacy section 2 |
| `Spec-02-Scopes-and-ACL` | Scopes + basic ACL | Legacy sections 3.5 and 17 basic ACL material |
| `Spec-03-HTTP-API` | HTTP API contract | Legacy API-surface material |
| `Spec-04-Manifests` | Manifests + Rekor | Legacy sections 19.1 and 19.2 |
| `Spec-05-Federation-Trust` | Federation trust (peer auth, replication) | Legacy section 19 |
| `Spec-06-Capability-Tokens` | Capability tokens | Legacy section 19.3 |
| `Spec-07-Recall-Pipeline` | Recall pipeline (basic) | Legacy sections 6 and 20 basic recall material |
| `Spec-08-Quarantine-Garden` | Quarantine semantics | Legacy section 19.5 |
| `Spec-09-Audit-Log` | Audit log | Legacy section 22.3 |
| `Spec-10-Hardening` | Security hardening | Legacy sections 22.1, 22.2, 22.4, and 22.6 |
| `Spec-11-Replay-Protection` | Replay protection | Legacy section 22.5 |
| `Spec-12-HLC-Bounded-Skew` | HLC bounded skew | (new; per R-19) |
| `Spec-13-Capability-Based-Instructions` | `interpret_as` capability model | (new; per ADR-003) |
| `Spec-14-Batch-Assert` | Batch fact assert | (new; per ADR-006) |
| `Spec-15-Fact-Semantics` | Fact semantics | Legacy section 3 |
| `Spec-16-Namespace-Registry` | Namespace registry | Legacy section 9 |
| `Spec-17-Schema-and-Migration` | Schema and migrations | Legacy section 10 |
| `Spec-18-Conformance-and-Failure-Modes` | Conformance and failure modes | Legacy section 11 |
| `Spec-19-Adapter-ABI` | Adapter ABI | Legacy section 12 |
| `Spec-20-Lint-Semantics` | Lint semantics | Legacy section 14 |
| `Spec-21-Content-Addressed-IDs` | Content-addressed IDs | `features/content-addressed-ids/spec.md`; legacy section 25 |

**Experimental specs (feature records own migrated entries; unmigrated entries remain at `experimental/<feature>/spec.md`):**

| Spec ID | Topic | Located at | Legacy source material |
|---|---|---|---|
| `Spec-X1-Lazy-Instruction-Discovery` | Lazy instruction discovery | `features/lazy-instruction-discovery/spec.md` | Legacy section 21 |
| `Spec-X2-RTBF-Tombstones` | RTBF tombstones | `features/tombstones/spec.md` | Legacy section 23 |
| `Spec-X3-Time-Travel-Queries` | `as_of` time-travel queries | `features/time-travel/spec.md` | Legacy section 24 |
| `Spec-X5-Memory-Garden-Advanced-ACL` | Memory garden advanced ACL | `features/memory-garden-acl/spec.md` | Legacy section 17 advanced material |
| `Spec-X6-Source-Attestation` | Source attestation | `features/source-attestation/spec.md` | Legacy section 18 |
| `Spec-X7-Subscriptions` | Subscriptions / push federation | `features/subscriptions/spec.md` | (new) |
| `Spec-X8-Intent-Envelope` | Intent envelope | `features/intent-envelope/spec.md` | Legacy section 4 |
| `Spec-X9-Decay-Semantics` | Decay semantics | `features/decay/spec.md` | Legacy section 15 |
| `Spec-X10-Synthesis` | Synthesis | `features/synthesis/spec.md` | Legacy section 16 |
| `Spec-X11-Recall-Graph` | Advanced recall graph | `features/recall-graph/spec.md` | Legacy section 20 advanced material |

---

## How to follow along

- **Public engineering log:** Friday weekly post in `docs/blog/` (alpha-series onwards).
- **CHANGELOG.md** at repo root — Keep-a-Changelog format.
- **GitHub Project — "Stigmem GA Readiness Plan":** [eidetic-labs/projects/1](https://github.com/orgs/eidetic-labs/projects/1).
- **ADR index:** [`docs/adr/README.md`](docs/adr/README.md).
- **Compatibility matrix** (planned): to be published at `docs.stigmem.dev/operate/compatibility`.
- **Model certification list** (per [ADR-015](docs/adr/015-adversarial-conformance-and-model-certification.md)): the `corpus-v1` adversarial conformance corpus (80 patterns) and certification runner ship today; the reviewed *public* model-results list is still pending and will be published at `docs.stigmem.dev/secure/model-certification`.

---

## Stability commitments by version line

Per [ADR-001](docs/adr/001-versioning.md) + [ADR-008](docs/adr/008-experimental-gates.md) §Deprecation policy:

- **Pre-1.0:** No stability guarantee. Breaking changes in any alpha or future pre-stable release; pin to specific versions; auto-upgrade is not safe.
- **`v1.0.0` and `v1.x`:** Wire format and public Python API are stable. Removing a public API requires a deprecation in v1.x followed by removal no earlier than v2.0.0.
- **Deprecated features:** supported through the rest of the major version they were deprecated in.
- **Experimental features:** subject to breaking changes in any release without notice; their use behind feature flags is at-your-own-risk.

---

*Roadmap is a living document. Updates land alongside ADR amendments and version-line transitions. Contributions to roadmap shaping go through the ADR amendment process per [ADR-001](docs/adr/001-versioning.md) §Contributor approval rule.*
