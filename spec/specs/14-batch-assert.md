---
spec_id: Spec-14-Batch-Assert
version: 0.1.0-alpha.0
status: Draft
applies_to: future hardened-core line
last_updated: 2026-05-14
supersedes: ADR-006 batch assert material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
---

# Spec-14-Batch-Assert

`Spec-14-Batch-Assert` defines the batch assertion operation targeted for a
future hardened-core line.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for ADR-006 batch assert
semantics. Batch assert is not part of the `v0.9.0a1` stable surface.

## Purpose

Batch assert lets a caller submit multiple fact assertions in one request while
retaining fact-model validation, hook execution, auditability, and predictable
failure behavior.

## Request Shape

```text
BatchAssertRequest {
  facts:          AssertRequest[]
  atomic:         boolean
  idempotency_key: string?
}
```

Each item in `facts` follows the single-fact assertion contract from
`Spec-01-Fact-Model` and `Spec-03-HTTP-API`.

## Atomic Mode

When `atomic=true`, the node MUST commit all facts or none. Validation failure,
authorization failure, hook denial, or storage failure for any item MUST abort
the entire batch.

When `atomic=false`, the node MAY persist successful items and report failures
per item.

## Idempotency

When an `idempotency_key` is supplied, retrying the same request with the same
key SHOULD return the same logical result and MUST NOT duplicate persisted
facts. Implementations MUST reject reuse of the same idempotency key for a
different request body.

## Hook And Audit Semantics

Batch assert MUST preserve the behavior of single-fact assertion hooks. Hooks
may run per fact, per batch, or both, but the externally visible result MUST
match the configured atomicity. Audit events SHOULD identify the batch and the
per-fact outcomes.

## Response Shape

```text
BatchAssertResponse {
  accepted: integer
  rejected: integer
  results:  BatchAssertItemResult[]
}

BatchAssertItemResult {
  index:   integer
  status:  "accepted" | "rejected"
  fact_id: string?
  error:   string?
}
```

## Out Of Scope

This spec does not define bulk import tooling, streaming ingestion, or
cross-node batch replication.
