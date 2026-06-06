# Recall Graph Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |

Advanced recall graph behavior remains outside the default supported surface.
Some implementation pieces exist in the current node, but this feature record
keeps the advanced protocol horizon distinct from `Spec-07-Recall-Pipeline`.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Advanced section 20 recall and graph material preserved as deferred experimental material. | `spec/stigmem-spec-v0.9.0a1.md` |
| Post-`v0.9.0a1` main | Recall, vector, card, and graph tests cover portions of the advanced design. | `node/tests/recall/` |
| `0.9.xA` planned | Decide which advanced graph pieces remain deferred, plugin-backed, or future-alpha only. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record embedding, graph traversal, and feedback-loop risks. | Partial | `features/recall-graph/security.md` |
| ADR alignment | Preserve deferred experimental status and Spec-X ownership. | Partial | ADR-002, ADR-008, ADR-020 §9 (modular specs), ADR-020 |
| Conformance vectors | Validate graph depth, embeddings, cards, and traversal boundaries. | Partial | `node/tests/recall/`; `node/tests/time_travel/test_phase13_time_travel_cid.py` |
| External operator soak | Validate production-like advanced recall workloads. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | In progress | This feature record. |

## Known Gaps

- Advanced graph behavior is not a default supported surface.
- Cloud embedding and graph traversal risk evidence remains incomplete.
- Operator guidance for graph/card recall at scale is incomplete.
