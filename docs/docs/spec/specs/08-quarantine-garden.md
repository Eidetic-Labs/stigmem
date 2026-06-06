---
spec_id: Spec-08-Quarantine-Garden
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md quarantine semantics from sections 17 and 19
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
---

# Spec-08-Quarantine-Garden

<p className="stigmem-meta"><span>3 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Quarantine garden behavior — isolating facts from low-trust or
failed-validation sources before they reach the main recall surface.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for quarantine
semantics. General garden ACL is owned by `Spec-02-Scopes-and-ACL`;
federation source trust is owned by `Spec-05-Federation-Trust`;
route shape is owned by `Spec-03-HTTP-API`.

## Purpose

<div className="stigmem-keypoint">

**Quarantine is a safety boundary.**

A fact that cannot be trusted enough for normal ingest may still be
worth retaining for moderator review. Instead of silently
discarding it or admitting it into the main fabric, the node routes
it to a designated quarantine garden.

</div>

## Quarantine admission

A node MAY quarantine inbound facts when:

<div className="stigmem-grid">

<div><h4>Low source-trust score</h4><p>Below the configured admission threshold.</p></div>
<div><h4>Missing or invalid source attestation</h4></div>
<div><h4>Sanitizer policy selects quarantine mode</h4></div>
<div><h4>Federation validation flag</h4><p>Reviewable but non-fatal issue.</p></div>
<div><h4>Operator policy</h4><p>Explicitly routes a source to quarantine.</p></div>

</div>

Facts admitted to quarantine MUST carry enough metadata to explain
the admission reason.

## Quarantine garden requirements

A quarantine garden is a Memory Garden with quarantine behavior
enabled. It MUST retain normal garden ACL properties and add a
moderator role.

```text
QuarantineRole = "admin" | "quarantine:moderator" | "writer" | "reader"
```

Promotion and rejection require `admin` or `quarantine:moderator`
in the quarantine garden.

## Fact state

Quarantined facts SHOULD record:

```text
quarantine_garden_id: UUID
quarantine_status:    "pending" | "promoted" | "rejected"
quarantine_reason:    string
source_trust:         number?
```

<div className="stigmem-keypoint">

**Pending quarantined facts MUST NOT appear in normal recall/query results.**

Unless the caller explicitly queries the quarantine surface and has
permission.

</div>

## Promote

Promotion moves a pending fact out of quarantine and into either
the main fabric or a target garden. Promotion MUST record who
promoted the fact, when, and why. Promoting an already promoted or
rejected fact MUST return a conflict response.

Promotion MUST re-check target garden scope and write permissions
before moving the fact.

## Reject

Rejection permanently marks a quarantined fact as rejected.
Rejection MUST record who rejected the fact, when, and why.
Rejected facts remain available for audit to authorized quarantine
moderators, but MUST NOT enter normal recall.

## Deletion guard

A quarantine garden with pending facts MUST NOT be deleted. The
node must require moderation of pending facts before deleting the
garden container.

## Audit

Nodes SHOULD audit:

<div className="stigmem-grid">

<div><h4>Quarantine admission</h4></div>
<div><h4>Promotion</h4></div>
<div><h4>Rejection</h4></div>
<div><h4>Deletion blocked by pending facts</h4></div>
<div><h4>Attempts to moderate without required role</h4></div>

</div>

Audit record shape belongs to `Spec-09-Audit-Log`.

## Out of scope

This spec does not define source-trust formula details, source
attestation, sanitizer pattern catalogues, or advanced Memory
Garden ACL behavior.
