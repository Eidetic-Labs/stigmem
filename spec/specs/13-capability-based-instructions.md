---
spec_id: Spec-13-Capability-Based-Instructions
version: 0.1.0-alpha.0
status: Draft
applies_to: future hardened-core line
last_updated: 2026-05-16
supersedes: ADR-003 capability-based prompt-injection redesign material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-06-Capability-Tokens >= 0.1.0-alpha.0
  - Spec-07-Recall-Pipeline >= 0.1.0-alpha.0
---

# Spec-13-Capability-Based-Instructions

`Spec-13-Capability-Based-Instructions` defines structural separation between
recalled content and executable instruction, plus the capability gate required
to promote memory into instruction.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for ADR-003 capability-based
instruction handling. The first implementation slice shipped in #373:
`FactValue.interpret_as` exists, local instruction writes require
`instruction:write`, and recall preserves instruction/content channels. The
remaining federation/admission pieces target a future hardened-core line and
are not part of the active alpha release horizon.

## Principle

Recalled memory is data. It MUST NOT become executable instruction merely
because it appears in context. Promotion from content to instruction requires an
explicit capability grant and a structurally separate channel.

## FactValue Extension

The capability redesign introduces an instruction interpretation marker on
facts or recalled units. A fact marked as instruction-like MUST be treated as
data unless the caller has the required capability to execute or inject that
instruction.

## Write-Time Enforcement

Writing instruction-typed facts MUST require explicit `instruction:write`
authority. General `write` authority is insufficient. Cross-organization
instruction-typed facts SHOULD be quarantined or rejected unless a trusted
deployment relationship explicitly permits them.

## Recall-Time Enforcement

Recall MUST preserve provenance and interpretation metadata. The recall pipeline
MUST NOT collapse untrusted content into executable instructions. Agent runtimes
must receive content and instructions through separate structures.

## Federation Boundary

Receiving nodes MUST NOT promote inbound content to instruction based on a
sender's assertion alone. Any instruction interpretation that crosses federation
must be revalidated against local policy and capability grants.

## Audit

Nodes SHOULD audit instruction writes, rejected promotions, cross-org
instruction quarantine, and capability failures.

## Out Of Scope

This spec does not define lazy instruction discovery, boot-stub delivery, or
instruction manifest retrieval; those belong to `Spec-X1-Lazy-Instruction-Discovery`.
