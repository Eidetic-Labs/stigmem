---
spec_id: Spec-09-Audit-Log
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 22.3 audit-log material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-09-Audit-Log

`Spec-09-Audit-Log` defines the minimum audit surface for security-relevant
events in the reference node.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for audit-log semantics.
Component specs define which events they emit; this spec defines common event
requirements, ordering expectations, retention, and export boundaries.

## Required Properties

Audit records SHOULD include:

```text
AuditEvent {
  event_type:   string
  timestamp:    ISO 8601 UTC
  actor_entity: URI?
  tenant_id:    string?
  scope:        string?
  fact_id:      string?
  outcome:      "success" | "failure" | "denied"
  metadata:     object
}
```

Events MUST be append-only. Operators MAY redact sensitive metadata for export,
but redaction MUST NOT change the original stored event.

## Required Event Families

Nodes SHOULD audit:

- fact writes and retractions,
- fact reads that return data,
- auth key creation/revocation and failed authentication,
- peer registration, verification, rejection, and revocation,
- federation fact accept/reject decisions,
- scope violations,
- capability-token issuance and revocation,
- quarantine admission, promotion, and rejection,
- CID mismatch/collision events once CID support is assigned and implemented,
- administrative export and configuration changes.

## Ordering

Audit events MUST carry wall-clock timestamps. Implementations SHOULD also carry
HLC or monotonic ordering metadata when available so investigators can order
events across federation boundaries.

## Retention

Default retention SHOULD be long enough to support security investigation and
operator review. Deployments MAY configure retention, but reducing retention
below the documented default SHOULD be an explicit operator choice.

## Export

Admin export MUST require administrative authorization. Export responses SHOULD
be paginated or streamed when event volume can be large. Export shape must not
reveal data the caller is not authorized to inspect.

## Failure Handling

Audit emission failure on security-critical writes SHOULD fail closed when that
is practical. For non-critical observability events, implementations MAY fail
open but SHOULD log local diagnostics.

## Out Of Scope

This spec does not define SIEM integrations, external log storage, or component
event catalogues beyond the required families above.
