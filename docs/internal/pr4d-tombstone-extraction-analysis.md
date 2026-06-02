# PR 4d Tombstone Extraction Analysis

Issue: [#319](https://github.com/eidetic-labs/stigmem/issues/319)
Parent: [#318](https://github.com/eidetic-labs/stigmem/issues/318)
Date: 2026-05-16

## Summary

PR 4d should extract RTBF tombstones from the default core surface into
`stigmem-plugin-tombstones` without changing the plugin-loaded behavior. The
default install should keep tombstone route contracts access-gated and have no
active propagation, recall filtering, or tombstone-specific storage behavior.
When the plugin is registered, it should provide the admin and federation API
behavior, apply the same recall/query/provenance/subscription suppression
rules, and own the tombstone migration set through `migration_register`.

Artifact signing, publication, and launch evidence remain parked in the
all-plugins launch lane tracked by issue #298.

## Current Core Inventory

The current implementation is spread across these files:

| Area | Files | Current responsibility |
|---|---|---|
| Admin API | `node/src/stigmem_node/routes/tombstones.py` | Mounts `/v1/tombstones`, signs tombstones and revocations, writes records, starts best-effort federation push. |
| App mounting | `node/src/stigmem_node/main.py` | Imports and includes `tombstones_router` unconditionally. |
| Federation API | `node/src/stigmem_node/routes/federation/tombstones.py`, `node/src/stigmem_node/routes/federation/__init__.py`, `node/src/stigmem_node/routes/_federation_impl.py` | Mounts tombstone poll and ingest routes, authenticates tombstone capabilities, verifies inbound signatures, applies inbound tombstones and revocations. |
| Storage and cache | `node/src/stigmem_node/tombstones.py`, `node/src/stigmem_node/tombstone_cache.py` | Owns CRUD helpers, inbound application helpers, in-process active tombstone caches, record filtering helpers. |
| Signing | `node/src/stigmem_node/tombstone_signing.py` | Signs and verifies tombstone and revocation records. |
| Models | `node/src/stigmem_node/models/tombstones.py` | Defines tombstone, revocation, status, federation response, and `TombstoneNotice` response models. |
| Fact query and provenance | `node/src/stigmem_node/routes/facts/common.py`, `node/src/stigmem_node/routes/facts/query.py`, `node/src/stigmem_node/routes/facts/provenance.py`, `node/src/stigmem_node/routes/facts/single.py` | Applies tombstone filters to fact reads, `as_of` reads, provenance masking, and single-fact indistinguishability. |
| Recall | `node/src/stigmem_node/routes/recall/orchestration.py`, `node/src/stigmem_node/routes/recall/as_of.py` | Applies tombstone filters to normal recall, card fast-path, and time-travel recall notices. |
| Subscription delivery | `node/src/stigmem_node/subscription_delivery.py` | Uses the in-process tombstone cache to drop delivery content for tombstoned entities. |
| Migrations | `node/migrations/025_rtbf_tombstones_retractions.sql`, `node/migrations/026_cid_and_tombstone_key_id.sql`, `node/migrations/027_revocation_key_id.sql` | Creates tombstones and revocations, then adds signing key columns. Migration `025` also includes a `fact_retractions` table, which is time-travel-owned behavior and should not be re-owned by the tombstone plugin. |
| Tests | `node/tests/tombstones/test_tombstones.py`, `node/tests/tombstones/test_tombstone_filter.py`, `node/tests/tombstones/test_provenance_tombstone.py`, `node/tests/federation/test_federation_push_b2.py`, `node/tests/time_travel/test_phase13_as_of.py`, `node/tests/time_travel/test_time_travel.py`, `node/tests/time_travel/test_phase13_time_travel_cid.py`, related recall tests | Cover admin APIs, federation ingest/poll, recall/query filtering, provenance masking, legal-hold notices, and time-travel interactions. |

## Hook Mapping

The extraction should use the stable PR 4-INF.1 hook surface without adding new
hooks.

| Hook | Use in PR 4d | Notes |
|---|---|---|
| `recall_filter` | Remove facts/cards whose entity or ref target is tombstoned; set the tombstone-filtered signal used to suppress count fields. | This should cover normal recall and fact-query-style recall surfaces. For current direct SQL paths, #321 should either adapt the call site to pass candidate records through the hook or add a narrow helper owned by the plugin package and invoked only when the plugin is registered. |
| `federation_inbound_validate` | Verify inbound tombstone and revocation signatures before storage. | Current `_verify_signed_artifact_or_400`, signer-manifest lookup, key-id resolution, and trust-mode behavior move behind this hook. The route should reject tombstone ingest when the plugin is not registered. |
| `post_assert_propagate` | Propagate locally issued tombstones and revocations to peers. | Current `_enqueue_tombstone_rebroadcast` and `_push_tombstone_to_peers` become plugin-owned propagation behavior. Tombstones are not normal facts, so the plugin implementation may need a direct plugin route handler call rather than relying on fact assertion events alone. |
| `migration_register` | Register plugin migrations for `tombstones`, `tombstone_revocations`, and tombstone signing key columns. | Do not move `fact_retractions` ownership into this plugin; time-travel owns retraction history. The existing mixed `025` migration should be split or treated carefully so plugin migration registration does not duplicate the time-travel table. |
| `audit_emit` | Emit structured tombstone lifecycle and verification events. | Current code mostly logs. PR 4d should define plugin audit events for `tombstone_created`, `tombstone_revoked`, `tombstone_propagated`, `tombstone_propagation_failed`, and `tombstone_verification_failed`. |

## Core Versus Plugin Ownership

Keep in core:

- Generic plugin registry and stable hook dispatch.
- Generic fact, recall, federation, subscription, and migration call sites.
- Capability-token verification primitives, identity manifests, and core
  federation peer authentication.
- Time-travel retraction history and `as_of` behavior already extracted under
  `stigmem-plugin-time-travel`.

Move behind `stigmem-plugin-tombstones` registration:

- `/v1/tombstones` admin routes.
- `/v1/federation/tombstones` poll and `/v1/federation/tombstones/ingest`.
- Tombstone and revocation models that are not needed by core responses.
- Tombstone storage helpers, cache, signing, verification, and propagation.
- Tombstone recall/query/provenance/subscription filtering.
- Tombstone-specific migrations and tests.

Default-install behavior:

- No plugin registered: tombstone admin and federation routes should be absent
  or fail closed with a plugin-required response, consistent with the lazy
  instruction and time-travel extraction pattern.
- No plugin registered: normal fact query, recall, provenance, and subscription
  delivery should not import or execute tombstone code.
- Plugin registered: existing tombstone behavior should remain testable through
  plugin-loaded clients.

## Migration Implications

The current migration boundary is mixed:

- `025_rtbf_tombstones_retractions.sql` creates tombstones, revocations, and
  `fact_retractions`.
- `024_fact_retractions.sql` also creates `fact_retractions`.
- `026_cid_and_tombstone_key_id.sql` mixes CID compatibility with tombstone
  `key_id`.
- `027_revocation_key_id.sql` adds revocation `key_id`.

For PR 4d implementation, the plugin migration registration should own only the
tombstone tables and tombstone key columns. Retraction-history tables should
remain with time-travel. CID migration concerns should remain core. If backward
compatibility requires existing core migration files to stay present, the plugin
should add no duplicate DDL and should document the legacy migration boundary
until a later migration-checksum cleanup can safely reconcile it.

## Audit Implications

Tombstone operations are compliance-impacting administrative actions. The plugin
should emit structured audit events through `audit_emit` instead of relying only
on logger output. At minimum:

- `tombstone_created`: local admin issuance.
- `tombstone_revoked`: local admin revocation.
- `tombstone_propagated`: successful peer push.
- `tombstone_propagation_failed`: peer push error or non-accepted status.
- `tombstone_verification_failed`: inbound signature or signer-manifest failure.

Each event should include the actor, target entity or tombstone ID, tenant,
scope, peer URL or node ID when applicable, and success/failure outcome.

## Follow-On Work Plan

1. #320 should scaffold `experimental/tombstones/` as a plugin source package
   with manifest, config schema, hook placeholders, and plugin migration files.
2. #321 should gate default-install behavior by removing unconditional route
   mounting and direct tombstone imports from core read paths.
3. #322 should add plugin-loaded validation tests for admin routes, federation
   ingest/poll, recall/query/provenance/subscription filtering, and hook order.
4. #323 should update public docs and Internal-Comms closeout status while
   keeping signed/published artifact evidence deferred to #298.

## Structural Blockers

No blocker prevents PR 4d from proceeding, but #320/#321 should handle these
carefully:

- The current migration files mix tombstones, time-travel retractions, and CID
  key columns. Plugin migration ownership must be explicit to avoid duplicate or
  misplaced DDL.
- Several read paths call tombstone helpers directly, so #321 needs small core
  call-site seams for hook-driven filtering before removing those imports.
- `TombstoneNotice` is currently used by time-travel responses. If the model
  moves into the tombstone plugin, time-travel needs either a small generic
  notice shape in core or an optional plugin-provided notice payload.
