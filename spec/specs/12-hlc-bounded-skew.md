---
spec_id: Spec-12-HLC-Bounded-Skew
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: R-19 HLC bounded-skew follow-up material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
---

# Spec-12-HLC-Bounded-Skew

`Spec-12-HLC-Bounded-Skew` defines bounds for remote Hybrid Logical Clock values
accepted during federation ingest.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for R-19 bounded-skew behavior.
The basic HLC field and local advance rules live in `Spec-01-Fact-Model`;
federation ingest context lives in `Spec-05-Federation-Trust`.

## Purpose

HLC values preserve causal ordering, but accepting arbitrarily far-future remote
HLCs lets a peer distort ordering and conflict resolution. Bounded skew limits
how far a remote HLC may advance local ordering relative to the receiver's wall
clock and policy.

## Inbound Bound

On federation ingest, a node MUST compare the inbound fact's HLC wall component
against its current wall clock. If the inbound HLC exceeds the configured bound,
the node MUST reject or quarantine the fact according to local policy.

The default production posture SHOULD reject excessive skew. Development
deployments MAY choose warn/quarantine modes when explicitly configured.

## Audit And Metrics

Nodes SHOULD emit an audit event for rejected or quarantined skew violations.
Metrics SHOULD include accepted skew distribution and rejected-skew counts so
operators can distinguish clock drift from hostile peers.

## Conflict Resolution Relationship

Conflict resolution may use HLC ordering as a tie-breaker. Facts rejected for
bounded-skew violation MUST NOT participate in normal conflict ordering.

## Out Of Scope

This spec does not define NTP configuration, wall-clock synchronization
operations, or replay nonce windows.
