---
title: Security Model
sidebar_label: Security Model
description: Stigmem's security model — scopes, signing, federation trust, attestation, capability tokens, and the quarantine garden.
---

# Security Model

<p className="stigmem-meta"><span>3 min read</span><span>Integrator · Operator</span><span>Trust primitives</span></p>

<div className="stigmem-lead">

**What this page is**

Stigmem's security model rests on five primitives that compose into
the full trust story: **scopes**, **signing**, **federation trust**,
**source attestation**, and **capability tokens**. Each is a small,
well-defined piece — the strength of the model is in how they fit
together.

</div>

## Scopes — the visibility boundary

Every fact is written with one of four scopes.

<div className="stigmem-fields">

<div>
<dt>Scope</dt>
<dt><span className="stigmem-fields__type">Federation behavior</span></dt>
<dd>Visibility</dd>
</div>

<div>
<dt><code>local</code></dt>
<dt><span className="stigmem-fields__type">never federated</span></dt>
<dd>Origin node only. Under any circumstances.</dd>
</div>

<div>
<dt><code>team</code></dt>
<dt><span className="stigmem-fields__type">never federated</span></dt>
<dd>Origin node only. Under any circumstances.</dd>
</div>

<div>
<dt><code>company</code></dt>
<dt><span className="stigmem-fields__type">conditional</span></dt>
<dd>Federated only when the active <code>PeerDeclaration</code> explicitly includes <code>"company"</code> in <code>allowed_scopes</code>.</dd>
</div>

<div>
<dt><code>public</code></dt>
<dt><span className="stigmem-fields__type">default-on</span></dt>
<dd>Federated by default between registered peers.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Scope enforcement is read- AND write-time.**

A misconfigured peer cannot escalate <code>team</code> facts to
<code>public</code> because the scope is checked before the fact is
admitted to the federation pipeline. See Spec-02-Scopes-and-ACL for
the normative spec.

</div>

## Signing — Ed25519 over every cross-node payload

Every node publishes a `federation_pubkey` at `/.well-known/stigmem`.
Cross-node primitives are signed with the corresponding private key.

<div className="stigmem-fields">

<div>
<dt>Primitive</dt>
<dt><span className="stigmem-fields__type">Signed by</span></dt>
<dd>Purpose</dd>
</div>

<div>
<dt><strong>PeerDeclaration</strong></dt>
<dt><span className="stigmem-fields__type">declaring node</span></dt>
<dd>JSON document with excluded fields enumerated in Spec-05-Federation-Trust capability negotiation.</dd>
</div>

<div>
<dt><strong>Federation cursor advances</strong></dt>
<dt><span className="stigmem-fields__type">advancing node</span></dt>
<dd>HLC cursor checkpoints carry signatures so a misbehaving peer cannot replay or rewrite history.</dd>
</div>

<div>
<dt><strong>Capability tokens</strong></dt>
<dt><span className="stigmem-fields__type">scope owner</span></dt>
<dd>Short-lived JWS signed by the scope owner.</dd>
</div>

</div>

Key rotation uses a **dual-trust window** — the previous and current
keys are both accepted for a configurable overlap, then the previous
key is revoked via the transparency log.

## Federation trust — quarantine and source-trust scoring

Each cross-org write is admitted via a **source-trust score**
`t ∈ [0,1]` derived from identity strength, peer history, scope
authority, and attestation mode. Effective confidence at recall time
is `confidence × t`.

<div className="stigmem-keypoint">

**Low-trust facts land in a quarantine garden.**

Itself a Memory Garden (Spec-02-Scopes-and-ACL) with admin-only ACL
— operators triage, accept, or reject quarantined writes from a
single dashboard. Facts also accumulate
<code>derived_from: [fact_hash...]</code>, and — when agent-keypair
attestation is enabled (opt-in per assertion) —
<code>attestation_chain: [signature...]</code> for signed source
provenance.

</div>

See [Federation Trust](./federation/federation-trust) for the
operator runbook.

## Source attestation — binding writes to identities

Source Attestation (Spec-X6-Source-Attestation) binds an `entity_uri`
to an API key so every fact written by that key carries a verifiable
`attested` field.

<div className="stigmem-fields">

<div>
<dt>Mode</dt>
<dt><span className="stigmem-fields__type">Behavior</span></dt>
<dd>When to use</dd>
</div>

<div>
<dt><code>enforce</code></dt>
<dt><span className="stigmem-fields__type">reject unattested</span></dt>
<dd>Default for federated peers and the curator dashboard.</dd>
</div>

<div>
<dt><code>warn</code></dt>
<dt><span className="stigmem-fields__type">log but admit</span></dt>
<dd>Useful for migration windows.</dd>
</div>

<div>
<dt><code>off</code></dt>
<dt><span className="stigmem-fields__type">disabled</span></dt>
<dd>Only appropriate for fully trusted single-tenant deployments.</dd>
</div>

</div>

Attestation is the **trust anchor for the connector ecosystem**:
third-party integrations write under their own attested identity, and
the curator dashboard can filter or quarantine by attestation.

## Capability tokens — explicit, short-lived authority

Writing scope `S` on a peer node requires a short-lived **capability
token** signed by the scope owner. Each capability carries an
explicit subject + verb + object plus an expiry. Capabilities are
revocable via the transparency log, and the receiving node verifies
the chain at admission time.

<div className="stigmem-keypoint">

**Cross-org writes are authorized, not just authenticated.**

A leaked capability has a bounded blast radius (the verb/object pair)
and a bounded lifetime (the expiry).

</div>

## How it fits together

A typical write path under the full security model.

<ol className="stigmem-steps">
<li>The agent obtains a capability token from the scope owner (e.g. <code>subject: agent:writer-bot</code>, <code>verb: assert</code>, <code>object: scope:public:project:loom</code>, <code>exp: now+5m</code>).</li>
<li>The agent signs the request with its API key.</li>
<li>The receiving node verifies (a) the API-key signature, (b) the capability chain, (c) the source-trust score against the current threshold, and (d) the scope rules.</li>
<li>If trust ≥ threshold, the fact enters the canonical store with an <code>attested</code> chain.</li>
<li>If trust &lt; threshold, the fact lands in the quarantine garden for admin review.</li>
<li>At recall time, effective confidence is <code>confidence × t</code> so low-trust facts are de-ranked even after admission.</li>
</ol>

## Reading on

<div className="stigmem-next">

<a href="./federation/federation-trust">
<strong>Concepts</strong>
<span>Federation trust guide</span>
<small>Operator setup end-to-end.</small>
</a>

<a href="../security/audit-and-quotas">
<strong>Security</strong>
<span>Audit log & quotas</span>
<small>What's logged, retention, and how to read the audit stream.</small>
</a>

<a href="../security/key-rotation">
<strong>Security</strong>
<span>Key rotation runbook</span>
<small>Dual-trust window mechanics.</small>
</a>

<a href="../security/container-hardening">
<strong>Security</strong>
<span>Container hardening</span>
<small>Deployment-side security posture.</small>
</a>

<a href="../community/security-disclosure">
<strong>Community</strong>
<span>Security disclosure</span>
<small>Reporting vulnerabilities responsibly.</small>
</a>

</div>
