---
title: Compatibility Commitment
sidebar_label: Compatibility Commitment
audience: Operator
description: Stigmem's written compatibility commitment per ADR-008 §Deprecation policy deprecation policy.
---

# Compatibility Commitment

<p className="stigmem-meta"><span>3 min read</span><span>Operator-facing</span><span>Per ADR-008 §Deprecation policy</span></p>

<div className="stigmem-lead">

**What this commits to**

Per [ADR-008](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/008-experimental-gates.md) §Deprecation policy.
This document is the written commitment about what stigmem will not
break, scaled to project resources and the v0.9.0a1 reset posture.
Reviewed at every major release; tightening or loosening goes through
an ADR amendment.

</div>

## Stability tiers

<div className="stigmem-fields">

<div>
<dt>Tier</dt>
<dt><span className="stigmem-fields__type">Promise</span></dt>
<dd>What it means</dd>
</div>

<div>
<dt><strong>Stable</strong></dt>
<dt><span className="stigmem-fields__type">no wire-format breaks within v1.x</span></dt>
<dd>Spec section normative. In production. Eval-covered. No wire-format breaking changes within the v1.x line after v1.0.0 ships.</dd>
</div>

<div>
<dt><strong>Beta</strong></dt>
<dt><span className="stigmem-fields__type">minor breaks possible</span></dt>
<dd>Spec normative; feature-flagged or in early adopters. Minor breaking changes possible before next major release.</dd>
</div>

<div>
<dt><strong>Experimental</strong></dt>
<dt><span className="stigmem-fields__type">no commitment</span></dt>
<dd>Implementation behind a flag, in <code>experimental/&lt;feature&gt;/</code>. Spec section may be draft. Breaking changes expected.</dd>
</div>

<div>
<dt><strong>Deprecated</strong></dt>
<dt><span className="stigmem-fields__type">marked for removal</span></dt>
<dd>Still operational; replacement available. See removal-distance commitment below.</dd>
</div>

</div>

## Per-tier commitments

<div className="stigmem-grid">

<div><h4>Stable features</h4><p>Wire format: no breaking changes within the v1.x line after v1.0.0 ships. Public Python API: removing or renaming a public symbol requires a deprecation in v1.x followed by removal no earlier than v2.0.0. Default behavior: changes require a deprecation cycle.</p></div>
<div><h4>Beta features</h4><p>Subject to breaking changes in the next minor release with a CHANGELOG entry per change. Pin to specific versions; do not rely on a beta feature's wire format being stable across minor releases.</p></div>
<div><h4>Experimental features</h4><p>Subject to breaking changes in any release without notice. Use behind feature flags is at-your-own-risk. Per ADR-008 reintroduction gates, an experimental feature graduates to stable only after passing all five gates.</p></div>
<div><h4>Deprecated features</h4><p>A feature deprecated in vX.Y is supported through all subsequent vX.* releases. Removal may not happen earlier than vX+1.0. Operators have at least one major version of notice to migrate. The deprecated feature's page carries <code>removed_in:</code> and <code>replacement:</code> frontmatter.</p></div>

</div>

## Wire-format pinning via `Stigmem-Version` header

Per [ADR-008](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/008-experimental-gates.md) §Version exposure:
clients lock to a declared protocol version via the `Stigmem-Version`
request header. Server honors the pin; future server versions stay
backward-compatible to declared protocol versions for at least one
major version after a deprecation lands.

```http
POST /v1/facts HTTP/1.1
Stigmem-Version: 0.9.0a1
Authorization: Bearer <api_key>
Content-Type: application/json

{ ... }
```

The pinning header is documented in Spec-15-Fact-Semantics (Wire
Format). Server implementation is future hardened-core work.

## Beta opt-in via `Stigmem-Beta` header

Experimental wire-level features require an opt-in header per call:

```http
POST /v1/facts HTTP/1.1
Stigmem-Version: 0.9.0a1
Stigmem-Beta: instruction-typed-facts
Authorization: Bearer <api_key>
Content-Type: application/json

{ ... }
```

Lists of supported beta names live at `/v1/.well-known/stigmem` in a
`betas` field. Beta names retire when the underlying feature graduates
per ADR-008 — calls referring to a retired beta name receive
`410 Gone` with a deprecation header pointing at the now-stable
feature.

## What this commitment does NOT cover

<div className="stigmem-grid">

<div><h4>Implementation internals</h4><p>Internal Python module structure, algorithm choices, performance characteristics — not subject to the wire-format or public-API commitments above.</p></div>
<div><h4>Operational defaults</h4><p>Default rate-limit values, cache TTLs, log retention windows — operators should pin via configuration, not rely on defaults remaining constant.</p></div>
<div><h4>Pre-1.0 builds</h4><p>Alpha and any future pre-stable builds have NO stability guarantee per ADR-001. Pin to specific versions; auto-upgrade is not safe.</p></div>
<div><h4>Deferred features</h4><p><code>experimental/&lt;feature&gt;/</code> — subject to breaking changes in any release without notice until the feature graduates per ADR-008.</p></div>

</div>

## Cross-references

<div className="stigmem-next">

<a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md">
<strong>ADR-001</strong>
<span>Versioning</span>
<small>Phases and stability commitments.</small>
</a>

<a href="https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/013-deprecation-policy.md">
<strong>ADR-008 §Deprecation policy</strong>
<span>Deprecation policy</span>
<small>Lifecycle and required artifacts.</small>
</a>

<a href="../reference/experimental-features">
<strong>Reference</strong>
<span>Experimental features</span>
<small>Current deferred-feature index.</small>
</a>

</div>
