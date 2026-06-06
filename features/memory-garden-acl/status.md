# Memory Garden Advanced ACL Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |
| Publication state | `hold` - package metadata aligned; registry publication blocked on dry-run evidence and maintainer clearance. |

Basic garden CRUD, membership, and direct `garden_id` fact read/write guards
remain core. Advanced cross-cutting ACL behavior is extracted into an opt-in
plugin package with registration and operator-controlled gates.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Advanced Memory Garden ACL semantics carried forward as deferred section 17 material. | `spec/stigmem-spec-v0.9.0a1.md` |
| Post-`v0.9.0a1` main | Plugin source package scaffolded with disabled-by-default hooks and validation tests. | `experimental/memory-garden-acl/`; plugin tests |
| `v0.9.0a6` | Core garden boundary, opt-in plugin boundary, and cross-surface ACL disposition validated for the alpha release horizon. | `features/memory-garden-acl/evidence.md`; `docs/internal/releases/v0.9.0a6-roadmap.md` |
| `0.9.xA` planned | Continue alpha validation of opt-in plugin behavior and R-21 contribution. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record R-21 contribution and reintroduction blockers. | Partial | `features/memory-garden-acl/security.md` |
| ADR alignment | Preserve deferred advanced ACL and plugin-boundary decisions. | Partial | ADR-002, ADR-008, ADR-020 §9 (modular specs), ADR-011, ADR-020 |
| Conformance vectors | Validate registration gates, explicit opt-in flags, deterministic hook ordering, core boundary behavior, and cross-surface disposition. | Partial | `features/memory-garden-acl/evidence.md` |
| External operator soak | Validate production-like garden isolation workloads. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | In progress | This feature record. |

## Known Gaps

- No signed or published plugin artifact exists yet.
- Gate 1 remains partial: a6 records that the feature supports and coexists
  with R-21 mitigation work but does not itself close same-session read/write
  graph isolation.
- External operator soak evidence is not recorded.
