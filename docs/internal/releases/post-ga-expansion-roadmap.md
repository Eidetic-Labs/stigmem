# Post-GA Expansion Roadmap

**Status:** future gate
**Release owner:** maintainer
**Milestone:** not opened
**Tag / release:** not tagged
**Last updated:** 2026-05-22

## Release Intent

The `v1.x.y` post-GA expansion horizon starts only after `v1.0.0` GA ships. It
is the project's steady state for experimental feature graduation, plugin
ecosystem maturity, modular spec evolution, and ongoing evidence maintenance.

## Scope Summary

| Area | In scope | Out of scope | Canonical references |
| --- | --- | --- | --- |
| Experimental graduation | ADR-008 gates for supported-surface promotion | Skipping gate artifacts | ADR-008 |
| Plugin stewardship | Cross-cutting features remain opt-in plugins unless a future ADR changes that boundary | Treating plugin extraction as temporary by default | ADR-011 |
| Spec evolution | Modular spec evolution | Reopening pre-reset monolithic spec structure | ADR-020 §9 (modular specs) |
| Evidence maintenance | Dependency/security evidence maintenance | One-time checklist closure | evidence maintenance docs |

## Detailed Scope

### Work

- Experimental features graduate into the supported surface via [ADR-008](../../adr/008-experimental-gates.md) reintroduction gates (each gate produces a concrete artifact: threat-model delta, ADR, conformance vectors, 30-day soak, documentation parity). Cross-cutting features remain opt-in plugins per ADR-011 unless a future ADR explicitly changes that boundary. Post-GA plugin stewardship is tracked in [#443](https://github.com/eidetic-labs/stigmem/issues/443).
- Multi-tenant remains a plugin (`stigmem-plugin-multi-tenant`); the cross-cutting plugin shape per ADR-011 is the permanent home, not a stop on the path to core. Adopters who need multi-tenancy install the plugin explicitly.
- Modular spec evolution.
- Plugin ecosystem matures; third-party plugins become first-class.
- Cross-phase source/test layout hygiene is complete via [#444](https://github.com/eidetic-labs/stigmem/issues/444): the node test-layout slice landed in [#465](https://github.com/eidetic-labs/stigmem/issues/465), observability/utility leaf-module flattening in [#467](https://github.com/eidetic-labs/stigmem/issues/467), federation/networking leaf-module flattening in [#471](https://github.com/eidetic-labs/stigmem/issues/471), lifecycle/deletion helper flattening in [#473](https://github.com/eidetic-labs/stigmem/issues/473), and recall/graph helper flattening in [#475](https://github.com/eidetic-labs/stigmem/issues/475). Dependency/security evidence maintenance remains an ongoing release responsibility ([#445](https://github.com/eidetic-labs/stigmem/issues/445)). The owner/trigger map lives in `docs/internal/evidence-maintenance.md` and is mechanically checked by `make check-evidence-maintenance`.

## Artifact Surfaces

| Surface | Expected artifact | Status | Evidence |
| --- | --- | --- | --- |
| PyPI | v1.x package releases | Future gate | Not opened |
| npm | v1.x SDK releases | Future gate | Not opened |
| GHCR | v1.x node images | Future gate | Not opened |
| Docs | Graduation, plugin stewardship, and compatibility docs | Future gate | Not opened |
| GitHub release | Future v1.x releases | Not tagged | Not opened |

## Security and Risk Posture

Post-GA expansion preserves the stable-line compatibility commitment. Feature
graduation follows ADR-008 and security colocation remains feature-owned.

## Evidence Gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| v1.0.0 GA | Stable release shipped | Future gate |
| ADR-008 graduation | Five gate artifacts for each feature | Future gate |
| Compatibility | ADR-008 §Deprecation policy commitment honored | Future gate |

## Release Notes Candidates

- Post-GA release notes are drafted per individual v1.x release.

## Deferred / Follow-Up Work

| Item | Disposition | Target |
| --- | --- | --- |
| None defined | This is the project's steady state | v1.x |

## Historical Disposition

Not applicable. This horizon is not active.
