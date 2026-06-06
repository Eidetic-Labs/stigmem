---
spec_id: Spec-18-Conformance-and-Failure-Modes
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 11 failure-mode acceptance material
depends_on:
  - Spec-03-HTTP-API >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
  - Spec-09-Audit-Log >= 0.1.0-alpha.0
  - Spec-11-Replay-Protection >= 0.1.0-alpha.0
  - Spec-15-Fact-Semantics >= 0.1.0-alpha.0
  - Spec-17-Schema-and-Migration >= 0.1.0-alpha.0
---

# Spec-18-Conformance-and-Failure-Modes

<p className="stigmem-meta"><span>4 min read</span><span>Spec contributor · Conformance tester</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Acceptance scenarios that exercise Stigmem's safety behavior under
federation partitions, malicious peer input, partial replication
failure, and replay attempts.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for failure-mode
acceptance scenarios. It defines scenario intent and expected
outcomes. Concrete test harness layout and fixture implementation
remain implementation details.

Legacy version labels from archived source material are normalized
to the current `v0.9.0a1` protocol line here. Historical wording
remains available in `spec/archive/evolution/` and
`spec/EVOLUTION.md`.

## Conformance gate

<div className="stigmem-keypoint">

**A conforming federation-capable node MUST demonstrate the scenarios in this spec or equivalent tests.**

Equivalent tests may use different fixture names, ports, or process
orchestration, but MUST preserve the setup, fault, and expected
safety outcomes. Failure-mode tests SHOULD run against the same
public HTTP and federation surfaces that clients use. White-box
shortcuts MAY be used only to simulate network partitions, process
crashes, clock state, or replay caches.

</div>

## Split-brain

**Setup.** Two nodes, A and B, are federated with `scope=public`.
Both begin with the same public facts.

**Scenario.**

<ol className="stigmem-steps">
<li>Cut network connectivity between A and B.</li>
<li>Write fact <code>F_a</code> to node A for a shared entity/relation/scope.</li>
<li>Write conflicting fact <code>F_b</code> to node B for the same entity/relation/scope.</li>
<li>Maintain the partition long enough for both nodes to continue serving local reads and writes.</li>
<li>Restore connectivity.</li>
<li>Allow replication to complete.</li>
</ol>

**Expected outcomes.**

<div className="stigmem-grid">

<div><h4>Both facts retained</h4><p>Both nodes retain both facts.</p></div>
<div><h4>Contradiction detected</h4><p>At least the node that ingests the second conflicting fact detects it.</p></div>
<div><h4>Conflict queryable</h4><p>Conflict query APIs expose the unresolved conflict.</p></div>
<div><h4>Both returned</h4><p>Fact queries with contradicted facts included return both facts with contradiction metadata.</p></div>
<div><h4>No silent discard</h4><p>No fact is silently discarded.</p></div>

</div>

## Malicious peer

**Setup.** Two nodes, A and B, are federated. A malicious process
obtains or forges input for the B-to-A direction.

**Scenario.**

<ol className="stigmem-steps">
<li>The malicious process attempts to push a fact whose scope exceeds B's peer declaration.</li>
<li>The malicious process attempts to push a fact whose source is outside B's declared namespace or authority.</li>
<li>The malicious process replays a previously observed token within the active replay window.</li>
</ol>

**Expected outcomes.**

<div className="stigmem-grid">

<div><h4>Over-scope rejected</h4></div>
<div><h4>Source-forgery rejected</h4></div>
<div><h4>In-window replay rejected</h4></div>
<div><h4>Audit captures reason</h4><p>Rejections produce audit events with enough detail to diagnose.</p></div>
<div><h4>Store uncorrupted</h4><p>The receiving fact store is not corrupted by rejected input.</p></div>

</div>

## Partial replication failure

**Setup.** Node A pulls from node B. Node B has a larger public fact
set than A has already replicated. A has persisted a cursor for the
last fully accepted page.

**Scenario.**

<ol className="stigmem-steps">
<li>B fails after returning a later page but before A persists the cursor for that page.</li>
<li>A attempts another pull while B is unreachable.</li>
<li>A continues serving local reads and writes.</li>
<li>B restarts.</li>
<li>A's next pull cycle resumes.</li>
</ol>

**Expected outcomes.**

<div className="stigmem-grid">

<div><h4>No crash on unavailability</h4><p>A does not crash while B is unavailable.</p></div>
<div><h4>Local reads/writes available</h4></div>
<div><h4>Resume from persisted cursor</h4><p>Not from the beginning and not from an uncommitted future cursor.</p></div>
<div><h4>No duplicates on re-ingest</h4></div>
<div><h4>Convergence on resume</h4><p>Final convergence includes all eligible facts.</p></div>

</div>

## Replay attack

**Setup.** Two nodes, A and B, are federated. A valid peer token is
observed by an attacker.

**Scenario.**

<ol className="stigmem-steps">
<li>The token is used legitimately once.</li>
<li>The same token is replayed within the active nonce window.</li>
<li>A new token is generated with the same nonce.</li>
<li>A token is submitted after expiry.</li>
</ol>

**Expected outcomes.**

<div className="stigmem-grid">

<div><h4>First use succeeds</h4></div>
<div><h4>Immediate replay fails</h4><p>With a nonce-replay error.</p></div>
<div><h4>Same-nonce reuse fails</h4><p>A different token carrying the same nonce also fails.</p></div>
<div><h4>Expired token fails</h4><p>With an expiry error.</p></div>
<div><h4>Failures audited</h4><p>Replay and expiry failures are audited.</p></div>

</div>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Performance/soak thresholds</h4></div>
<div><h4>Adapter ABI conformance vectors</h4></div>
<div><h4>Lint conformance vectors</h4></div>
<div><h4>Implementation fixture names</h4></div>
<div><h4>CI job topology</h4></div>
<div><h4>Experimental feature gates</h4></div>

</div>
