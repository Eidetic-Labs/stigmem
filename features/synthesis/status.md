# Synthesis Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |

Synthesis remains outside the default supported surface per ADR-002 and
ADR-020 §13 (repo structure). The repo contains implementation and test evidence for synthesis
behavior, but release-facing support still requires ADR-008 gate completion.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Section 16 synthesis semantics preserved as deferred experimental material. | `spec/stigmem-spec-v0.9.0a1.md` |
| Post-`v0.9.0a1` main | Synthesis tests validate confidence-weighted summary behavior. | `node/tests/recall/test_synthesis_decay.py` |
| `0.9.xA` planned | Decide whether synthesis remains deferred or enters an alpha plugin/protocol lane. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record prompt-injection and feedback-loop implications. | Partial | `features/synthesis/security.md` |
| ADR alignment | Preserve deferred experimental status and Spec-X ownership. | Partial | ADR-002, ADR-008, ADR-020 §9 (modular specs), ADR-020 |
| Conformance vectors | Validate confidence filtering and contradiction presentation. | Partial | `node/tests/recall/test_synthesis_decay.py` |
| External operator soak | Validate synthesis output in production-like agent workflows. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | In progress | This feature record. |

## Known Gaps

- Release-facing support posture remains deferred.
- Adapter rendering guidance for synthesized summaries is incomplete.
- External operator soak evidence is not recorded.
