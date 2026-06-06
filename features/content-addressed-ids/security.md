# Content-Addressed Fact IDs Security

## Threat Model Delta

CIDs add a tamper-evident identity layer to facts. A fact's CID is recomputed
from canonical assertion fields and checked on storage/read surfaces. This
raises data corruption, storage tampering, and federation mismatch from silent
drift into explicit `cid_mismatch` failures.

CIDs are not a complete trust proof. Excluded metadata such as `valid_until`,
`source_trust`, signatures, attestation chains, provenance references, and
operator reasons must still be validated by their owning features and specs.

## Mitigations

| Risk | Mitigation | Evidence |
| --- | --- | --- |
| Stored fact body changes after write | Recompute CID on read and reject mismatches. | `node/src/stigmem_node/cid.py`; `node/tests/time_travel/test_phase13_time_travel_cid.py` |
| Inbound federation payload declares a mismatched CID | Receiving nodes recompute CIDs before trusting declared identity. | `Spec-05-Federation-Trust`; CID tests and federation validation workstreams. |
| Excluded metadata is treated as trusted because CID matches | Spec explicitly excludes metadata from CID trust and requires owning-feature validation. | `features/content-addressed-ids/spec.md`; threat model R-18. |
| Legacy facts have null CIDs | Backfill status and verification surfaces expose pending rows. | `node/src/stigmem_node/routes/cid_admin.py`; `POST /v1/facts/{fact_id}/verify-cid`. |

## Residual Risk

- A matching CID does not prove excluded metadata is trustworthy.
- Legacy rows may remain CID-null until backfill completes.
- SHA-256 rotation is not yet specified beyond the prefix-based format.
- Operators still need immutable evidence retention for stronger post-incident
  proof.

## Advisories and Findings

No public GHSA is currently owned by this feature record.

Related security references:

- R-18 in `spec/security/threat-model.md`
- ADR-016 storage immutability enforcement
- ADR-011 CIDs as core behavior
