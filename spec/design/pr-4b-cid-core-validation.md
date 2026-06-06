# PR 4b CID Core Validation

Issue: [#302](https://github.com/eidetic-labs/stigmem/issues/302)
Parent: [#301](https://github.com/eidetic-labs/stigmem/issues/301)

## Decision

PR 4b should proceed as validation and closeout work, not as a new CID
implementation and not as a plugin extraction.

ADR-011 keeps content-addressed fact IDs in core. The current `main` branch
already implements the core CID surface described by
`Spec-21-Content-Addressed-IDs`: CID computation, storage persistence, alias
lookup, verify endpoint, and backfill support. No `stigmem-plugin-cids` package
exists or should be created.

## Current core surface

The core implementation is present in these locations:

- `node/src/stigmem_node/cid.py`
  - computes `sha256:` CIDs from the seven-field canonical fact body;
  - validates CID string shape.
- `node/src/stigmem_node/routes/_facts_assert.py`
  - computes a CID before local fact insertion;
  - persists `facts.cid`;
  - inserts the `fact_cid_aliases` row in the same transaction;
  - returns the existing fact for duplicate CID assertions.
- `node/migrations/026_cid_and_tombstone_key_id.sql`
  - adds `facts.cid`;
  - creates `fact_cid_aliases`;
  - creates lookup indexes.
- `node/src/stigmem_node/routes/facts/single.py`
  - accepts `GET /v1/facts/{sha256:...}` and resolves through
    `fact_cid_aliases`.
- `node/src/stigmem_node/routes/facts/cid.py`
  - exposes `POST /v1/facts/{fact_id}/verify-cid`.
- `node/src/stigmem_node/routes/cid_admin.py`
  - exposes `GET /v1/admin/cid-backfill/status`.
- `node/src/stigmem_node/cli_admin_handlers.py`
  - implements the `backfill-cids` CLI command.
- `data/conformance/v2.0/25_cid_addressing.json`
  - covers CID response shape, unknown-CID lookup, verify endpoint behavior, and
    auth-gated backfill status.

## Alignment With ADR-011 And Spec-21

| Requirement | Current state |
|---|---|
| CIDs are core, not a plugin | Satisfied. CID code lives under `node/src/stigmem_node/`; no `stigmem-plugin-cids` package exists. |
| Default install computes CIDs | Satisfied. Local fact assertion computes and stores a CID without plugin registration. |
| CID storage contract | Satisfied. Migration `026` adds `facts.cid`, `fact_cid_aliases`, and indexes. |
| Dual addressing | Satisfied. `GET /v1/facts/{sha256:...}` validates CID syntax and resolves via alias table. |
| CID verification | Satisfied. `POST /v1/facts/{fact_id}/verify-cid` recomputes the CID and reports match, mismatch, or null stored CID. |
| Backfill path | Satisfied. CLI backfill and admin status route exist; tests cover idempotency and status shape. |
| Conformance vector | Present. `25_cid_addressing.json` covers the default-install CID wire behavior. |

## Follow-Up Scope

No new CID implementation work is required before PR 4b closeout based on this
analysis. The remaining PR 4b work is:

1. run the focused CID test and conformance validation;
2. close the implementation-gap issue as not applicable unless validation
   surfaces a concrete defect;
3. update roadmap/checklist state to mark PR 4b complete.

Federation policy for CID-null legacy rows remains owned by
`Spec-05-Federation-Trust`, as stated in `Spec-21`. That is not PR 4b scope
unless a failing conformance or review finding demonstrates a specific gap in
the current default CID behavior.
