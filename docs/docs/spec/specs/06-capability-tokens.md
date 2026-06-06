---
spec_id: Spec-06-Capability-Tokens
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 19.3 capability-token material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-04-Manifests >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
---

# Spec-06-Capability-Tokens

<p className="stigmem-meta"><span>3 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Short-lived, signed grants used for federated and delegated
operations. Capability tokens are scoped credentials: they grant a
subject a verb on a specific object for a bounded time window.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for capability-token
shape, issuance, verification, and revocation. It intentionally
does **not** define peer admission, manifest schema, replay-window
policy, or capability-based instruction semantics.

## Token purpose

<div className="stigmem-keypoint">

**Capability tokens are portable credentials.**

Static API keys are node-local credentials. Capability tokens
provide a portable credential that a receiving peer can verify from
issuer manifest material without calling back to the issuer on
every operation.

</div>

## Token shape

```text
CapabilityToken {
  issuer:    URI
  subject:   URI
  verb:      string
  object:    URI
  issued_at: ISO 8601 UTC
  expiry:    ISO 8601 UTC
  nonce:     lowercase hex string
  key_id:    string
  signature: base64url Ed25519 signature
}
```

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Type</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>issuer</code></dt>
<dt><span className="stigmem-fields__type">URI</span></dt>
<dd>The authority that signed the token.</dd>
</div>

<div>
<dt><code>subject</code></dt>
<dt><span className="stigmem-fields__type">URI</span></dt>
<dd>The principal receiving the grant.</dd>
</div>

<div>
<dt><code>verb</code></dt>
<dt><span className="stigmem-fields__type">string</span></dt>
<dd>The allowed action.</dd>
</div>

<div>
<dt><code>object</code></dt>
<dt><span className="stigmem-fields__type">URI</span></dt>
<dd>The target scope, garden, entity, or route family.</dd>
</div>

</div>

## Signing

The signature covers a canonical encoding of the token body with
`signature` omitted. The signing key MUST correspond to an active
key in the issuer's manifest. Receivers MUST verify the issuer
manifest before trusting the token.

## Issuance

Capability-token issuance is exposed through the HTTP route owned
by `Spec-03-HTTP-API`:

```http
POST /v1/federation/capability-tokens
```

Only authorized administrative callers may issue capability tokens.
Issuance MUST record token id, issuer, subject, verb, object,
expiry, and nonce so that revocation and audit can refer to the
token later.

## Verification

Receivers MUST verify:

<ol className="stigmem-steps">
<li>The token signature.</li>
<li>The issuer manifest and active key id.</li>
<li>The token has not expired.</li>
<li>The nonce is well-formed.</li>
<li>The token has not been revoked.</li>
<li>The requested operation is within the <code>(verb, object)</code> grant.</li>
</ol>

Verification failure MUST deny the operation. Implementations SHOULD
distinguish signature, expiry, revocation, and scope/verb failures
in audit logs.

## Revocation

Revocation is exposed through:

```http
POST /v1/federation/capability-tokens/{token_id}/revoke
```

Revocation invalidates a token before its natural expiry. Nodes
SHOULD publish revocation evidence through the same
transparency-log mechanism used for manifests when configured.

<div className="stigmem-keypoint">

**Receivers MUST treat revoked tokens as invalid even if signature and expiry are otherwise valid.**

</div>

## Replay relationship

The token nonce identifies a token instance. Runtime replay windows
and inbound request nonce caches are owned by
`Spec-11-Replay-Protection`; this spec only requires the token to
carry a verifiable nonce.

## Grant boundaries

<div className="stigmem-keypoint">

**Capability tokens are additive grants, not proof of broad identity authority.**

A token granting <code>write</code> on one object MUST NOT be
interpreted as a grant to write any other object. A token granting
access to a garden or scope MUST still pass the local ACL and scope
enforcement rules that apply to that operation.

</div>

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>API-key creation</h4><p>Local operator credentials.</p></div>
<div><h4>Peer-token handshakes</h4><p>That are separate from capability tokens.</p></div>
<div><h4>Capability-based instruction</h4><p><code>interpret_as</code> enforcement.</p></div>
<div><h4>Replay cache implementation</h4></div>
<div><h4>Token UI or CLI workflows</h4></div>

</div>
