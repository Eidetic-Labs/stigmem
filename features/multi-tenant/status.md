# Multi-Tenant Scoping Status

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| First release | `v0.9.0a8` validation target |
| Default surface | `opt-in` |
| Publication state | `hold` - package metadata aligned; registry publication blocked on dry-run evidence and maintainer clearance. |

Multi-tenant scoping exists on `main` as an opt-in experimental plugin source
package. Default installs collapse callers into the `default` tenant. Plugin
registration plus `STIGMEM_MULTI_TENANT_ENABLED=true` preserves non-default
tenant resolution.

## Release History

| Release | Change | Evidence |
| --- | --- | --- |
| `v0.9.0a8` shipped | Multi-tenant isolation extraction validated the opt-in experimental plugin boundary without promoting shared-node readiness. | `docs/internal/releases/v0.9.0a8-roadmap.md`; `features/multi-tenant/evidence.md` |
| Post-extraction main | Plugin source package, default-collapse behavior, plugin-enabled tenant isolation, federation default-tenant-only boundary, and cross-surface route/plugin tests landed. | `experimental/multi-tenant/`; `node/tests/routes/test_multi_tenant.py`; `node/tests/plugins/test_multi_tenant_plugin_scaffold.py`; `node/tests/federation/test_pull.py` |
| `0.9.xA` planned | Continue alpha validation and decide whether a future Spec-X assignment is needed. | `ROADMAP.md` |

## Gate Progress

| Gate | Description | Status | Evidence |
| --- | --- | --- | --- |
| Threat-model delta | Record R-01, R-02, and R-21 contributions. | Recorded | `features/multi-tenant/security.md` |
| ADR alignment | Preserve default-surface exclusion and plugin-boundary decisions. | Covered for a8 | ADR-002, ADR-008, ADR-020 §13 (repo structure), ADR-011, ADR-020 |
| Conformance vectors | Validate default collapse, plugin-enabled tenant isolation, and current federation default-tenant-only behavior. | Covered for a8; promotion gaps remain | `features/multi-tenant/evidence.md` |
| External operator soak | Validate shared-node deployments with independent tenants. | Open | None currently recorded. |
| Documentation parity | Replace legacy experimental docs with feature-owned record plus projections. | Covered for a8 | This feature record; public docs projections. |

## Known Gaps

- No signed or published plugin artifact exists yet.
- No numbered Spec-X assignment exists.
- Tenant-aware non-default federation is not implemented; current node-level
  federation exports only `default` tenant facts.
- Per-tenant quota and process resource isolation evidence is incomplete.
- External operator soak evidence is not recorded.
