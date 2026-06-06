---
spec_id: Spec-18-Conformance-and-Failure-Modes
version: 0.1.0-alpha.0
status: Draft
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

`Spec-18-Conformance-and-Failure-Modes` defines acceptance scenarios that
exercise Stigmem's safety behavior under federation partitions, malicious peer
input, partial replication failure, and replay attempts.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for failure-mode acceptance
scenarios. It defines scenario intent and expected outcomes. Concrete test
harness layout and fixture implementation remain implementation details.

Legacy version labels from archived source material are normalized to the
current `v0.9.0a1` protocol line here. Historical wording remains available in
`spec/archive/evolution/` and `spec/EVOLUTION.md`.

## Conformance Gate

A conforming federation-capable node MUST demonstrate the scenarios in this
spec or equivalent tests. Equivalent tests may use different fixture names,
ports, or process orchestration, but MUST preserve the setup, fault, and
expected safety outcomes.

Failure-mode tests SHOULD run against the same public HTTP and federation
surfaces that clients use. White-box shortcuts MAY be used only to simulate
network partitions, process crashes, clock state, or replay caches.

## Split-Brain

### Setup

Two nodes, A and B, are federated with `scope=public`. Both begin with the same
public facts.

### Scenario

1. Cut network connectivity between A and B.
2. Write fact `F_a` to node A for a shared entity/relation/scope.
3. Write conflicting fact `F_b` to node B for the same entity/relation/scope.
4. Maintain the partition long enough for both nodes to continue serving local
   reads and writes.
5. Restore connectivity.
6. Allow replication to complete.

### Expected Outcomes

- Both nodes retain both facts.
- At least the node that ingests the second conflicting fact detects the
  contradiction.
- Conflict query APIs expose the unresolved conflict.
- Fact queries with contradicted facts included return both facts with
  contradiction metadata.
- No fact is silently discarded.

## Malicious Peer

### Setup

Two nodes, A and B, are federated. A malicious process obtains or forges input
for the B-to-A direction.

### Scenario

1. The malicious process attempts to push a fact whose scope exceeds B's peer
   declaration.
2. The malicious process attempts to push a fact whose source is outside B's
   declared namespace or authority.
3. The malicious process replays a previously observed token within the active
   replay window.

### Expected Outcomes

- Over-scope facts are rejected.
- Source-forgery facts are rejected.
- In-window replay attempts are rejected.
- Rejections produce audit events with enough detail to diagnose the reason.
- The receiving fact store is not corrupted by rejected input.

## Partial Replication Failure

### Setup

Node A pulls from node B. Node B has a larger public fact set than A has already
replicated. A has persisted a cursor for the last fully accepted page.

### Scenario

1. B fails after returning a later page but before A persists the cursor for
   that page.
2. A attempts another pull while B is unreachable.
3. A continues serving local reads and writes.
4. B restarts.
5. A's next pull cycle resumes.

### Expected Outcomes

- A does not crash while B is unavailable.
- Local reads and writes on A remain available.
- A resumes from the last persisted cursor, not from the beginning and not from
  an uncommitted future cursor.
- Re-ingesting a partially received page does not create duplicate facts.
- Final convergence includes all eligible facts.

## Replay Attack

### Setup

Two nodes, A and B, are federated. A valid peer token is observed by an attacker.

### Scenario

1. The token is used legitimately once.
2. The same token is replayed within the active nonce window.
3. A new token is generated with the same nonce.
4. A token is submitted after expiry.

### Expected Outcomes

- First legitimate use succeeds.
- Immediate replay fails with a nonce-replay error.
- A different token carrying the same nonce also fails.
- Expired tokens fail with an expiry error.
- Replay and expiry failures are audited.

## Out Of Scope

This spec does not define:

- performance or soak-test thresholds,
- adapter ABI conformance vectors,
- lint-specific conformance vectors,
- implementation fixture names,
- CI job topology, or
- experimental feature gates.
