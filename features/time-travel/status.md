# Time-Travel Queries Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |
| Publication state | `hold` - package metadata aligned; registry publication blocked on dry-run evidence and maintainer clearance. |

Time-travel query source exists on `main` as an experimental plugin package for
`v0.9.0a4` validation. The default install rejects `as_of` requests unless the
plugin is registered, and registered plugin installs still require explicit
operator gates for fact-query and recall `as_of` surfaces. This validates the
ADR-011 plugin boundary without graduating time-travel into the default
supported surface.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Spec lineage carried section 24 time-travel semantics. | `spec/stigmem-spec-v0.9.0a1.md` |
| Post-`v0.9.0a1` main | Source package and fail-closed behavior landed for alpha validation. | `experimental/time-travel/`; plugin tests |
| `v0.9.0a4` active | Active release target for time-travel extraction validation, operator-gated `as_of` behavior, historical-query semantics, tombstone/legal-hold safety, and release-surface alignment. | `ROADMAP.md`; `docs/internal/releases/v0.9.0a4-roadmap.md`; `features/time-travel/evidence.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record contributed risks and reintroduction blockers. | Complete for a4 read-path validation | `features/time-travel/security.md` |
| ADR alignment | Preserve experimental and plugin-boundary decisions. | Complete for a4 read-path validation | ADR-008, ADR-020 §9 (modular specs), ADR-011, ADR-020 |
| Conformance vectors | Split default fail-closed, operator-disabled, and plugin-enabled behavior. | Complete for a4 read-path validation | `node/tests/plugins/test_time_travel_plugin_validation.py`; `node/tests/time_travel/test_phase13_time_travel_cid.py` |
| External operator soak | Validate production-like workloads. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | Complete for a4 read-path validation | This feature record; `docs/docs/spec/experimental/time-travel-queries.md` |

## Known Gaps

- No signed or published plugin artifact exists yet.
- Operator runbooks for historical legal-hold access remain incomplete.
- Artifact publication evidence is deferred until the planned plugin set is
  ready for release packaging.
