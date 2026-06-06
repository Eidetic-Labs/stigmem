# Subscriptions Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `deferred` |
| Stability | `experimental` |
| First release | `0.9.0a1` spec lineage |
| Default surface | `opt-in` |

Subscriptions remain outside the default supported surface. The current repo
contains protocol text, generated API documentation, and some test coverage for
related delivery behavior, but no published standalone feature artifact.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Subscription semantics preserved as deferred experimental protocol material. | `spec/stigmem-spec-v0.9.0a1.md` |
| Post-`v0.9.0a1` main | API documentation and tombstone delivery tests reference subscription behavior. | `docs/docs/reference/api/`; `node/tests/tombstones/test_tombstone_filter.py` |
| `0.9.xA` planned | Validate whether subscriptions remain deferred, become plugin-backed, or are removed from the active alpha launch lane. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record event-delivery authorization and revocation risks. | Partial | `features/subscriptions/security.md` |
| ADR alignment | Preserve deferred experimental status and Spec-X ownership. | Partial | ADR-002, ADR-008, ADR-020 §9 (modular specs), ADR-020 |
| Conformance vectors | Validate delivery-time auth, replay, cancellation, and tombstone suppression. | Partial | `node/tests/tombstones/test_tombstone_filter.py` |
| External operator soak | Validate webhook/wake behavior in a production-like deployment. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | In progress | This feature record. |

## Known Gaps

- No published package or supported default surface exists.
- Delivery-time authorization and token revocation conformance is incomplete.
- Operator runbooks for webhook retries, replay windows, and cancellation are
  incomplete.
