# Multi-Tenant Scoping Spec

## Scope

Multi-tenant scoping defines how a single Stigmem node can isolate facts,
gardens, audit records, API keys, recall, and plugin hooks by `tenant_id` when
the opt-in `stigmem-plugin-multi-tenant` package is registered and explicitly
enabled.

This feature has no Spec-X assignment. If it is reintroduced into the
supported surface as protocol behavior, it must receive a numbered Spec-X per
ADR-020 §9 (modular specs) and pass ADR-008 gates.

## Default Behavior

Default installs resolve every caller into the single `default` tenant. This
is true even if the stored API key carries a non-default tenant ID.

Default behavior exists so the core node can keep storage compatibility
columns without making multi-tenancy part of the default supported surface.
Single-tenant deployments do not need the plugin.

## Plugin-Enabled Behavior

When the plugin is registered and `STIGMEM_MULTI_TENANT_ENABLED=true`, the
`tenant_resolve` hook preserves the API key's tenant ID. The resolved tenant
then flows through tenant-scoped HTTP, storage, recall, audit, observability,
subscription, and plugin-hook paths that accept request tenant context.

Existing node-level federation replication remains constrained to the
`default` tenant in v0.9.0a8. Non-default tenant federation needs a dedicated
design, conformance vectors, and risk disposition before it can be promoted.

```text
Bearer token -> Identity(entity_uri, permissions, tenant_id)
                                                |
                                                v
                                  TenantContext(tenant_id)
                                                |
                                                v
                         storage and hook paths filter by tenant_id
```

## Isolation Guarantees

| Resource | Isolation mechanism |
| --- | --- |
| Facts | `tenant_id` column on `facts`; reads and writes filter by caller tenant. |
| Gardens | Garden slug lookup is scoped by tenant; the same slug can exist in multiple tenants. |
| Garden ACL | Membership checks resolve garden identity within the caller tenant. |
| Audit log | Audit rows carry `tenant_id`; audit queries are tenant-scoped. |
| API keys | Each key belongs to exactly one tenant. |
| Federation | Existing node-level pull exports only `default` tenant facts; tenant-aware non-default federation is deferred. |
| Plugin hooks | Hook payloads receive tenant context through the plugin framework. |

## Non-Isolated Node Surfaces

The following surfaces are node-level, not tenant-level:

- environment settings;
- health and well-known endpoints;
- node identity and signing keys;
- process resources such as CPU, memory, disk, and network capacity.

Operators who host independent tenants on one node must pair tenant isolation
with transport authentication, per-tenant quotas, audit review, and operational
resource controls.

## API Key Provisioning

Tenant ID is assigned when an API key is created. Keys created without an
explicit `tenant_id` use `default`.

```json
{
  "entity_uri": "service:payments",
  "permissions": ["read", "write"],
  "tenant_id": "acme-corp"
}
```

`GET /v1/me` returns the resolved identity and tenant ID. With the plugin
disabled, non-default keys resolve to `default`; with the plugin enabled, the
stored non-default tenant is preserved.

## Tenant Naming

`tenant_id` is an opaque string. Operators should use a stable URL-safe slug
such as `acme-corp`, `team-ml`, or `staging`. The node does not maintain a
separate tenant registry; tenant identity is implicit in key assignment.

## Non-Goals

- This feature does not make multi-tenancy part of the default supported
  surface.
- This feature does not publish a signed plugin artifact.
- This feature does not define per-tenant billing policy.
- This feature does not provide tenant-aware non-default federation.
- This feature does not provide process-level resource isolation between
  tenants.
