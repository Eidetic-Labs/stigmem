# Content-Addressed Fact IDs Evidence

## Implementation Paths

| Path | Purpose |
| --- | --- |
| `node/src/stigmem_node/cid.py` | CID computation, syntax checks, stored-row verification, and mismatch error. |
| `node/src/stigmem_node/routes/facts/cid.py` | Fact CID verification route. |
| `node/src/stigmem_node/routes/_facts_assert.py` | CID computation before local fact insertion, `facts.cid` persistence, alias insertion, and duplicate-CID lookup. |
| `node/src/stigmem_node/routes/facts/single.py` | Single-fact read path, including CID lookup and mismatch handling. |
| `node/src/stigmem_node/routes/facts/query.py` | Fact query read path, including CID mismatch handling. |
| `node/src/stigmem_node/routes/cid_admin.py` | CID backfill status route. |
| `node/src/stigmem_node/cli_admin_handlers.py` | `backfill-cids` CLI handler for CID-null legacy rows. |
| `sdks/stigmem-py/src/stigmem/verification.py` | Client-side CID recomputation and verification helpers. |
| `node/migrations/026_cid_and_tombstone_key_id.sql` | Storage migration for `facts.cid`, `fact_cid_aliases`, lookup indexes, and backfill state. |

## Tests and Validators

| Check | Path or command | Coverage |
| --- | --- | --- |
| CID computation and canonicalization | `node/tests/time_travel/test_phase13_time_travel_cid.py` | CID format, determinism, field sensitivity, and independent canonical JSON check. |
| Write-path persistence | `node/tests/time_travel/test_phase13_time_travel_cid.py` | Fact writes store non-null CIDs and create `fact_cid_aliases` rows. |
| CID lookup and verification | `node/tests/time_travel/test_phase13_time_travel_cid.py` | CID lookup, malformed CID handling, verify route, null stored CID, and backfill status. |
| Read-path tamper detection | `node/tests/time_travel/test_phase13_time_travel_cid.py` | Single-fact read, fact query, and recall hydration return `409 cid_mismatch` after simulated tampering. |
| Backfill CLI idempotency | `node/tests/time_travel/test_phase13_time_travel_cid.py`; `node/tests/cli/test_cli_handlers_b2.py` | CID-null legacy row backfill behavior remains idempotent and preserves immutable base rows. |
| Federation inbound CID validation | `node/tests/federation/test_replication.py` | Inbound CID-bearing facts are stored when matching and rejected on mismatch. |
| SDK verification | `sdks/stigmem-py/tests/test_client.py` | Client-side CID mismatch handling. |
| Conformance vector | `data/conformance/v2.0/25_cid_addressing.json` | Default-install CID response shape, lookup, verify endpoint, and backfill authorization behavior. |
| Fast gate | `bash scripts/check.sh python` | Runs Python lint, type, tests, and security checks. |

## Conformance and Fixtures

CID behavior is covered by the Phase 13 Python tests and by the protocol
dependency from `Spec-21-Content-Addressed-IDs` to fact model, HTTP API,
federation trust, audit log, and schema/migration specs.

The compatibility projection at `spec/specs/21-content-addressed-ids.md`
intentionally remains a short pointer to `features/content-addressed-ids/spec.md`
until protocol projection tooling owns generated compatibility files. The
public compatibility matrix projects this core feature into `v0.9.0a1` and
`v0.9.0a3`.

## v0.9.0a3 Validation Record

Issue #554 validates that CID remains a core feature for the a3 release line:

| Gate | Evidence |
| --- | --- |
| Core ownership | `feature_type: core`, `default_surface: default`, ADR-011 reference, and no `stigmem-plugin-cids` package. |
| Feature-owned spec | `features/content-addressed-ids/spec.md` is canonical; `spec/specs/21-content-addressed-ids.md` points back to it. |
| Compatibility projection | `docs/compatibility-matrix.yaml` lists `content-addressed-ids` with release lines `v0.9.0a1` and `v0.9.0a3`. |
| Implementation coverage | Core node, migration, route, CLI, SDK helper, federation, and conformance paths are listed above. |
| Release posture | Known gaps stay bounded to legacy CID-null rows, hash rotation, and federation policy ownership; none require moving CID to a plugin. |

## Coverage Gaps

- Hash algorithm rotation does not yet have conformance vectors.
- Federation CID-null policy is covered by federation trust work, not by this
  feature alone.
- Long-running operator backfill evidence is release-specific and belongs in
  release evidence when a tagged artifact is cut.
