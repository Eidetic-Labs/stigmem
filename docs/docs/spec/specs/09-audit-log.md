---
spec_id: Spec-09-Audit-Log
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 22.3 audit-log material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-09-Audit-Log

<p className="stigmem-meta"><span>2 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

The minimum audit surface for security-relevant events in the
reference node. Common event requirements, ordering expectations,
retention, and export boundaries.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for audit-log
semantics. Component specs define which events they emit; this
spec defines common event requirements.

## Required properties

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

<div className="stigmem-keypoint">

**Events MUST be append-only.**

Operators MAY redact sensitive metadata for export, but redaction
MUST NOT change the original stored event.

</div>

## Required event families

Nodes SHOULD audit:

<div className="stigmem-grid">

<div><h4>Fact writes and retractions</h4></div>
<div><h4>Fact reads returning data</h4></div>
<div><h4>Auth key lifecycle</h4><p>Creation, revocation, failed authentication.</p></div>
<div><h4>Peer registration lifecycle</h4><p>Registration, verification, rejection, revocation.</p></div>
<div><h4>Federation fact decisions</h4><p>Accept/reject.</p></div>
<div><h4>Scope violations</h4></div>
<div><h4>Capability-token issuance and revocation</h4></div>
<div><h4>Quarantine lifecycle</h4><p>Admission, promotion, rejection.</p></div>
<div><h4>CID mismatch/collision</h4><p>Once CID support is assigned and implemented.</p></div>
<div><h4>Admin export + config changes</h4></div>

</div>

## Ordering

Audit events MUST carry wall-clock timestamps. Implementations
SHOULD also carry HLC or monotonic ordering metadata when available
so investigators can order events across federation boundaries.

## Retention

Default retention SHOULD be long enough to support security
investigation and operator review. Deployments MAY configure
retention, but reducing retention below the documented default
SHOULD be an explicit operator choice.

## Export

Admin export MUST require administrative authorization. Export
responses SHOULD be paginated or streamed when event volume can be
large. Export shape must not reveal data the caller is not
authorized to inspect.

## Failure handling

<div className="stigmem-keypoint">

**Audit emission failure on security-critical writes SHOULD fail closed.**

For non-critical observability events, implementations MAY fail
open but SHOULD log local diagnostics.

</div>

## Out of scope

This spec does not define SIEM integrations, external log storage,
or component event catalogues beyond the required families above.
