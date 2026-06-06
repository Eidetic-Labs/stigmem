# Stigmem Spec — Index

This directory contains the canonical specification for the stigmem federated knowledge protocol.

## Canonical spec

**[`stigmem-spec-v0.9.0a1.md`](stigmem-spec-v0.9.0a1.md)** is the canonical specification as of 2026-05-09. Per [ADR-001](../docs/adr/001-versioning.md) (versioning + per-ecosystem version-string convention), v0.9.0a1 is the first build of stigmem; the version *markers* on earlier evolutionary checkpoints labeled internal development steps, not tagged releases.

The ADR-020 §9 (modular specs) component specs are the active protocol decomposition. The
monolithic v0.9.0a1 file remains as the historical disposition map and bridge
for legacy section numbers.

### Section disposition (full table in the canonical spec)

| Section group | Status | Destination |
|---|---|---|
| §1–§14 (core protocol foundation) | Stable in v0.9.0a1 | `spec/specs/` component specs, plus monolithic overview/governance bridge prose |
| §15 Decay, §16 Synthesis | Deferred per [ADR-002](../docs/adr/002-v1-scope.md) | [`features/decay/spec.md`](../features/decay/spec.md), [`features/synthesis/spec.md`](../features/synthesis/spec.md) |
| §17 Memory Garden | Basic concept stable; advanced ACL deferred per [ADR-011](../docs/adr/011-cross-cutting-extraction.md) | [`specs/02-scopes-and-acl.md`](specs/02-scopes-and-acl.md), [`specs/08-quarantine-garden.md`](specs/08-quarantine-garden.md), [`features/memory-garden-acl/spec.md`](../features/memory-garden-acl/spec.md) |
| §18 Source Attestation | Deferred / experimental plugin | [`features/source-attestation/spec.md`](../features/source-attestation/spec.md) |
| §19 Federation Trust | Basic stable (mTLS, capability tokens); advanced trust scoring deferred | [`specs/04-manifests.md`](specs/04-manifests.md), [`specs/05-federation-trust.md`](specs/05-federation-trust.md), [`specs/06-capability-tokens.md`](specs/06-capability-tokens.md) |
| §20 Recall and Graph (advanced) | Deferred | [`features/recall-graph/spec.md`](../features/recall-graph/spec.md) |
| Subscriptions / push federation | Deferred | [`features/subscriptions/spec.md`](../features/subscriptions/spec.md) |
| §21 Lazy Instruction Discovery | Deferred / experimental plugin | [`features/lazy-instruction-discovery/spec.md`](../features/lazy-instruction-discovery/spec.md) |
| §22 Security Hardening | Stable | [`specs/09-audit-log.md`](specs/09-audit-log.md), [`specs/10-hardening.md`](specs/10-hardening.md), [`specs/11-replay-protection.md`](specs/11-replay-protection.md) |
| §23 RTBF Tombstones | Deferred / experimental plugin | [`features/tombstones/spec.md`](../features/tombstones/spec.md) |
| §24 Time-Travel Queries | Deferred / experimental plugin | [`features/time-travel/spec.md`](../features/time-travel/spec.md) |
| §25 Content-Addressed Fact IDs (CIDs) | **Stable in core** per [ADR-011](../docs/adr/011-cross-cutting-extraction.md) | [`features/content-addressed-ids/spec.md`](../features/content-addressed-ids/spec.md) |

## Modular spec migration (ADR-020 §9 (modular specs))

Per [ADR-020](../docs/adr/020-feature-owned-product-structure.md) §9 (modular specs), supported component specs live
under [`spec/specs/`](specs/) with independent versioning. Experimental specs
remain colocated with their feature code under
[`experimental/<feature>/spec.md`](../experimental/). [`PROTOCOL.md`](PROTOCOL.md)
is generated from those files' YAML frontmatter and records the current
protocol composition.

## Evolution

The protocol-spec content evolved through development checkpoints from pre-reset to v2.0. Snapshots preserved at [`spec/archive/evolution/`](archive/evolution/) — see that directory's README. The development-checkpoint changelog is at [`spec/EVOLUTION.md`](EVOLUTION.md) (renamed from `spec/CHANGELOG.md` 2026-05-09 per master-checklist §4.3a). The protocol-release-level changelog going forward is at [`CHANGELOG.md`](../CHANGELOG.md) at repo root.

## Conformance

Conformance vectors at `data/conformance/<spec-version>/` — see `data/conformance/README.md` for the suite layout.

## Cross-references

- [`spec/stigmem-spec-v0.9.0a1.md`](stigmem-spec-v0.9.0a1.md) — canonical spec
- [`spec/PROTOCOL.md`](PROTOCOL.md) — generated modular-spec protocol composition
- [`spec/specs/`](specs/) — ADR-020 §9 (modular specs) core spec files and frontmatter
- [`experimental/<feature>/spec.md`](../experimental/) — ADR-020 §9 (modular specs) experimental specs and frontmatter
- [`spec/EVOLUTION.md`](EVOLUTION.md) — development-checkpoint history
- [`spec/archive/evolution/`](archive/evolution/) — superseded evolutionary snapshots
- [`spec/security/threat-model.md`](security/threat-model.md) — threat model
- [`docs/adr/`](../docs/adr/) — architecture decision records
- [`experimental/<feature>/spec.md`](../experimental/) — per-feature spec content for deferred sections
- [`CHANGELOG.md`](../CHANGELOG.md) — protocol-release-level changelog
- [`ROADMAP.md`](../ROADMAP.md) — public roadmap
