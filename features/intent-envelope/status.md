# Intent Envelope Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |

Intent envelope was deferred indefinitely in the v0.9.0a1 reset, but the design
intent is preserved as Spec-X8 so future reintroduction has a concrete starting
point and must pass ADR-008 gates.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Section 4 intent envelope material was removed from the active default roadmap and preserved as experimental/deferred material. | `spec/stigmem-spec-v0.9.0a1.md`; `spec/EVOLUTION.md` |
| Post-`v0.9.0a1` main | Spec-X8 frontmatter and legacy compatibility path were established. | `experimental/intent-envelope/spec.md` |
| `0.9.xA` planned | Preserve the feature record while deciding whether intent envelope belongs in a later alpha horizon. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Define prompt-injection and instruction-authority impact. | Open | `features/intent-envelope/security.md` |
| ADR alignment | Preserve ADR-001 deferral and ADR-008 reintroduction gates. | Partial | ADR-001, ADR-008, ADR-020 §9 (modular specs), ADR-020 |
| Conformance vectors | Define wire-format and validation differences from ordinary facts. | Open | None currently recorded. |
| External operator soak | Identify an adapter or deployment that uses intent envelopes. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | In progress | This feature record. |

## Known Gaps

- No implementation package exists.
- No conformance vectors exist.
- Security impact on instruction-authoring authority remains open.
