---
title: Specification
sidebar_label: Overview
audience: Spec
description: Stigmem protocol specification — modular spec navigator for v0.9.0a1.
sidebar_position: 6
---

# Stigmem Protocol Specification

<p className="stigmem-meta"><span>3 min read</span><span>Spec contributor · Implementer</span><span>v0.9.0a1 modular spec set</span></p>

<div className="stigmem-lead">

**What this page is**

A navigator that maps every legacy section-based docs page to its
maintained component spec home. Section-based pages remain
compatibility entry points for older links while ADR-020 §9 (modular specs) extraction
finishes.

</div>

:::note Authoritative source
The maintained protocol composition is generated from the modular
component specs and colocated experimental specs rendered below.
Historical evolutionary snapshots remain archived in the repository.
:::

:::info Security disclosure
Report vulnerabilities via the
[GitHub private advisory path](https://github.com/eidetic-labs/stigmem/security/advisories)
— not as public issues.
:::

## Modular spec map

<div className="stigmem-fields">

<div>
<dt>Rendered entry point</dt>
<dt><span className="stigmem-fields__type">Maintained spec home</span></dt>
<dd>Summary</dd>
</div>

<div>
<dt><a href="./motivation">Motivation</a></dt>
<dt><span className="stigmem-fields__type">Protocol overview prose</span></dt>
<dd>Why immutable typed facts beat per-agent mutable stores.</dd>
</div>

<div>
<dt><a href="./atomic-fact-shape">Atomic Fact Shape</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/fact-model">Spec-01-Fact-Model</a></span></dt>
<dd>Fact tuple, value types, HLC field, and fact-model boundaries.</dd>
</div>

<div>
<dt><a href="./fact-semantics">Fact Semantics</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/fact-semantics">Spec-15-Fact-Semantics</a></span></dt>
<dd>Provenance, expiry, retraction, contradiction, and conflict entities.</dd>
</div>

<div>
<dt>Intent Envelope</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/intent-envelope">Spec-X8-Intent-Envelope</a></span></dt>
<dd>Deferred indefinitely per ADR-001; design intent preserved for ADR-008 reintroduction.</dd>
</div>

<div>
<dt><a href="./wire-format">Wire Format</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/http-api">Spec-03-HTTP-API</a></span></dt>
<dd>JSON/HTTP API surface and route contracts.</dd>
</div>

<div>
<dt><a href="./federation">Federation</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/federation-trust">Spec-05-Federation-Trust</a></span></dt>
<dd>Peer declaration, capability negotiation, replication, and federation scope rules.</dd>
</div>

<div>
<dt><a href="./design-decisions-log">Design Decisions Log</a></dt>
<dt><span className="stigmem-fields__type">Protocol overview prose</span></dt>
<dd>Historical rationale; not an independent component spec.</dd>
</div>

<div>
<dt><a href="./open-questions">Open Questions</a></dt>
<dt><span className="stigmem-fields__type">Planning material</span></dt>
<dd>Open design questions; not an independent component spec.</dd>
</div>

<div>
<dt><a href="./namespace-registry">Namespace Registry</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/namespace-registry">Spec-16-Namespace-Registry</a></span></dt>
<dd>Reserved prefixes and registry rules.</dd>
</div>

<div>
<dt><a href="./schema-and-migration">Schema and Migration</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/schema-and-migration">Spec-17-Schema-and-Migration</a></span></dt>
<dd>Schema, migration cursor, indexes, and backend contract.</dd>
</div>

<div>
<dt><a href="./failure-mode-scenarios">Failure Mode Scenarios</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/conformance-and-failure-modes">Spec-18-Conformance-and-Failure-Modes</a></span></dt>
<dd>Federation and conformance acceptance scenarios.</dd>
</div>

<div>
<dt><a href="./adapter-abi">Adapter ABI</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/adapter-abi">Spec-19-Adapter-ABI</a></span></dt>
<dd>Minimum adapter contract and conformance expectations.</dd>
</div>

<div>
<dt><a href="./lint-semantics">Lint Semantics</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/lint-semantics">Spec-20-Lint-Semantics</a></span></dt>
<dd>Read-only lint checks, finding shapes, severity, and async job behavior.</dd>
</div>

<div>
<dt>Decay Semantics</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/decay-semantics">Spec-X9-Decay-Semantics</a></span></dt>
<dd>Experimental/deferred decay sweep semantics.</dd>
</div>

<div>
<dt>Synthesis</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/synthesis">Spec-X10-Synthesis</a></span></dt>
<dd>Experimental/deferred synthesis semantics.</dd>
</div>

<div>
<dt>Memory Garden</dt>
<dt><span className="stigmem-fields__type">Spec-02 + Spec-08 + Spec-X5</span></dt>
<dd>Basic scopes/gardens are core; advanced ACL remains experimental.</dd>
</div>

<div>
<dt>Source Attestation</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/source-attestation">Spec-X6-Source-Attestation</a></span></dt>
<dd>Experimental source-to-key binding.</dd>
</div>

<div>
<dt><a href="./federation-trust">Federation Trust</a></dt>
<dt><span className="stigmem-fields__type">Spec-04 + Spec-05 + Spec-06 + Spec-08</span></dt>
<dd>Manifests, capability tokens, peer trust, and quarantine boundaries.</dd>
</div>

<div>
<dt>Recall & Graph</dt>
<dt><span className="stigmem-fields__type">Spec-07 + Spec-X11</span></dt>
<dd>Core recall pipeline plus experimental graph/embedding features.</dd>
</div>

<div>
<dt>Subscriptions / push federation</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/subscriptions">Spec-X7-Subscriptions</a></span></dt>
<dd>Experimental subscription and push-delivery semantics.</dd>
</div>

<div>
<dt>Lazy Instruction Discovery</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/lazy-instruction-discovery">Spec-X1-Lazy-Instruction-Discovery</a></span></dt>
<dd>Experimental lazy instruction recall.</dd>
</div>

<div>
<dt><a href="./security-hardening">Security Hardening</a></dt>
<dt><span className="stigmem-fields__type">Spec-09 + Spec-10 + Spec-11 + Spec-12</span></dt>
<dd>mTLS, key rotation, audit, quotas, replay protection, and HLC skew bounds.</dd>
</div>

<div>
<dt>Right-to-be-Forgotten Tombstones</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/rtbf-tombstones">Spec-X2-RTBF-Tombstones</a></span></dt>
<dd>Experimental/deferred tombstone behavior.</dd>
</div>

<div>
<dt>Time-Travel / As-Of Queries</dt>
<dt><span className="stigmem-fields__type"><a href="./experimental/time-travel-queries">Spec-X3-Time-Travel-Queries</a></span></dt>
<dd>Experimental/deferred as-of query behavior.</dd>
</div>

<div>
<dt><a href="./content-addressed-fact-ids">Content-Addressed Fact IDs</a></dt>
<dt><span className="stigmem-fields__type"><a href="./specs/content-addressed-ids">Spec-21-Content-Addressed-IDs</a></span></dt>
<dd>Core CIDs per ADR-011.</dd>
</div>

</div>

## Archive

Previous evolutionary spec snapshots (`pre-reset` through `v2.0`)
remain preserved under the repository archive. Per ADR-001, those
version *markers* labeled internal development checkpoints, not
tagged releases; **the canonical version line of stigmem begins at
v0.9.0a1**.
