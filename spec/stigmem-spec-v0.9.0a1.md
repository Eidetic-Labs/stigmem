# Stigmem Protocol Specification — v0.9.0a1

**Status:** Historical alpha.1 canonicalization snapshot. Current modular protocol composition lives in [`PROTOCOL.md`](PROTOCOL.md) and `spec/specs/` per [ADR-020](../docs/adr/020-feature-owned-product-structure.md) §9 (modular specs).
**Applies to:** Stigmem v0.9.0a1 and reference node implementation.
**Last updated:** 2026-05-09.

> **About this document.** v0.9.0a1 is the first build of stigmem per [ADR-001](../docs/adr/001-versioning.md) (versioning + per-ecosystem version-string convention). The protocol-spec content evolved over multiple development checkpoints (snapshots preserved at [`spec/archive/evolution/`](archive/evolution/)). This document is the canonical destination — content is migrated forward from the most-complete pre-reset checkpoint (`stigmem-spec-v2.0.md`), reviewed section-by-section against `node/` implementation, and improved for clarity. Earlier evolutionary snapshots become reference material once a section's content has migrated forward.
>
> **Section status convention** ([ADR-008](../docs/adr/008-experimental-gates.md) §Version exposure):
> - `Stable in v0.9.0a1` — committed contract; no breaking changes within v0.9.0a series within the section's wire-format scope.
> - `Experimental in v0.9.0a1` — implementation exists but the section's contract is not committed; reintroduction per [ADR-008](../docs/adr/008-experimental-gates.md) for any section that moves to `experimental/<feature>/spec.md`.
> - `Deferred from v0.9.0a1` — section's content moves to `experimental/<feature>/spec.md` per [ADR-002](../docs/adr/002-v1-scope.md) v1 critical-path scope decision.
>
> **Modular spec migration ([ADR-020](../docs/adr/020-feature-owned-product-structure.md) §9 (modular specs)) has landed structurally on `main`.** This file remains as the v0.9.0a1 canonicalization snapshot and legacy section map. Current component specs live in `spec/specs/`; experimental specs live in `experimental/<feature>/spec.md`.

## How to read this document

Per [ADR-020](../docs/adr/020-feature-owned-product-structure.md) §9 (modular specs), the canonical spec naming convention is `Spec-NN-Topic-Name` for supported protocol component specs and `Spec-XN-Topic-Name` for experimental specs. This monolithic file is retained as the alpha.1 snapshot and section-disposition table; the generated current index is [`PROTOCOL.md`](PROTOCOL.md).

The spec is divided into supported protocol components (kept in this canonical file until extraction) and deferred sections (migrated to per-feature `experimental/<feature>/spec.md`).

| Spec ID (target) | Topic | Legacy § | Status in v0.9.0a1 | Canonical destination |
|---|---|---|---|---|
| (protocol overview) | Motivation | §1 | Stable | This file |
| `Spec-01-Fact-Model` | Atomic fact shape | §2 | Stable | `spec/specs/01-fact-model.md` |
| `Spec-01-Fact-Model` + `Spec-02-Scopes-and-ACL` + `Spec-15-Fact-Semantics` | Fact semantics | §3 | Stable | `Spec-02` scope-enforcement material is in `spec/specs/02-scopes-and-acl.md`; remaining fact-semantics material is in `spec/specs/15-fact-semantics.md` |
| (deferred indefinitely) | Intent envelope | §4 | **Deferred indefinitely** ([ADR-001](../docs/adr/001-versioning.md)) | `features/intent-envelope/spec.md` (feature record for future reintroduction per ADR-008) |
| `Spec-03-HTTP-API` | Wire format | §5 | Stable | `spec/specs/03-http-api.md` |
| `Spec-05-Federation-Trust` (basic parts) + `Spec-07-Recall-Pipeline` (basic) | Federation (basic) | §6 | Stable | `spec/specs/05-federation-trust.md`; recall-specific material extracted to `spec/specs/07-recall-pipeline.md` |
| (protocol governance) | Design decisions log | §7 | Stable | This file |
| (protocol governance) | Open questions | §8 | Stable | This file |
| `Spec-16-Namespace-Registry` | Namespace registry | §9 | Stable | `spec/specs/16-namespace-registry.md` |
| `Spec-17-Schema-and-Migration` | Schema and migration | §10 | Stable | `spec/specs/17-schema-and-migration.md` |
| `Spec-18-Conformance-and-Failure-Modes` | Failure-mode scenarios | §11 | Stable | `spec/specs/18-conformance-and-failure-modes.md` |
| `Spec-19-Adapter-ABI` | Adapter ABI | §12 | Stable | `spec/specs/19-adapter-abi.md` |
| (placeholder) | (reserved) | §13 | Placeholder | `docs/archive/placeholder-pages/spec/section-13.md` |
| `Spec-20-Lint-Semantics` | Lint semantics | §14 | Stable | `spec/specs/20-lint-semantics.md` |
| (deferred) | Decay semantics | §15 | **Deferred** ([ADR-002](../docs/adr/002-v1-scope.md)) | `features/decay/spec.md` |
| (deferred) | Synthesis | §16 | **Deferred** | `features/synthesis/spec.md` |
| `Spec-02-Scopes-and-ACL` (basic) + `Spec-08-Quarantine-Garden` + `Spec-X5-Memory-Garden` (advanced) | Memory garden | §17 | Basic Stable; quarantine Stable; advanced ACL deferred | `spec/specs/02-scopes-and-acl.md` (basic); `spec/specs/08-quarantine-garden.md` (quarantine); `features/memory-garden-acl/spec.md` (advanced ACL per [ADR-011](../docs/adr/011-cross-cutting-extraction.md)) |
| `Spec-X6-Source-Attestation` | Source attestation | §18 | **Deferred** | `experimental/source-attestation/spec.md` |
| `Spec-04-Manifests` + `Spec-05-Federation-Trust` + `Spec-06-Capability-Tokens` | Federation trust | §19 | Basic Stable; advanced trust scoring deferred | `Spec-04`, `Spec-05`, and `Spec-06` material extracted; `experimental/federation-trust-extensions/spec.md` (advanced) |
| `Spec-07-Recall-Pipeline` (basic) + `Spec-X11-Recall-Graph` (advanced) | Recall and graph | §20 | Basic Stable; advanced deferred | `spec/specs/07-recall-pipeline.md` (basic); `features/recall-graph/spec.md` (advanced) |
| `Spec-X1-Lazy-Instruction-Discovery` | Lazy instruction discovery | §21 | **Deferred** | `experimental/lazy-instruction-discovery/spec.md` |
| `Spec-09-Audit-Log` + `Spec-10-Hardening` + `Spec-11-Replay-Protection` | Security hardening | §22 | Stable | `Spec-09`, `Spec-10`, and `Spec-11` material extracted |
| `Spec-X2-RTBF-Tombstones` | RTBF tombstones | §23 | **Deferred** | `experimental/tombstones/spec.md` |
| `Spec-X3-Time-Travel` | Time-travel queries | §24 | **Deferred** | `experimental/time-travel/spec.md` |
| `Spec-21-Content-Addressed-IDs` | Content-addressed fact IDs (CIDs) | §25 | **Stable in core** ([ADR-011](../docs/adr/011-cross-cutting-extraction.md)). This is a core modular-spec assignment, not ADR-008 graduation. | `spec/specs/21-content-addressed-ids.md` |
| `Spec-12-HLC-Bounded-Skew` | HLC bounded skew (R-19) | (new in v0.9.0a2) | Implemented on main for v0.9.0a2 | `spec/specs/12-hlc-bounded-skew.md` |
| `Spec-13-Capability-Based-Instructions` | Capability-based instructions per ADR-003 | (new after v0.9.0a1) | Future hardened-core work; no active beta milestone | `spec/specs/13-capability-based-instructions.md` |
| `Spec-14-Batch-Assert` | Batch assert API per ADR-006 | (new after v0.9.0a1) | Future hardened-core work; no active beta milestone | `spec/specs/14-batch-assert.md` |
| `Spec-X7-Subscriptions` | Subscriptions / push federation | (new) | **Deferred** | `features/subscriptions/spec.md` |

## Section status

This file is a skeleton — content arrives section by section as the master-checklist §4.3a per-section review completes. Each migrated section gets a review note documenting:

- What `node/` files were cross-checked against the spec text.
- What discrepancies were found (with issue references for future hardened-core follow-up).
- What clarity improvements were made.
- What the section's status is (Stable / Experimental / Deferred).

Until a section is migrated, refer to the corresponding section in `spec/archive/evolution/stigmem-spec-v2.0.md` as the most-recent-but-superseded source. The v2.0 snapshot is the most complete pre-reset spec content; review-and-migrate is in progress.

## Cross-references

- [`spec/archive/evolution/`](archive/evolution/) — superseded evolutionary snapshots (`pre-reset` through `v2.0`). Each retains a banner pointing here.
- [`spec/EVOLUTION.md`](EVOLUTION.md) — spec-level changelog (renamed from `spec/CHANGELOG.md`).
- [`spec/security/threat-model.md`](security/threat-model.md) — threat model; section references in this spec link to the threat model's risk register.
- [`docs/adr/`](../docs/adr/) — architecture decision records governing the spec evolution.
- [`experimental/<feature>/spec.md`](../experimental/) — per-feature spec content for deferred sections.

---

*This canonical spec lands in PR 2.5 sub-phase 2.5.B. Content migrates incrementally; this file represents the destination structure and the table of section dispositions. The full content arrives across sub-phase 2.5.B commits.*
