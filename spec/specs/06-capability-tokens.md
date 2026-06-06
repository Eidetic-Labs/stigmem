---
spec_id: Spec-06-Capability-Tokens
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 19.3 capability-token material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-04-Manifests >= 0.1.0-alpha.0
  - Spec-05-Federation-Trust >= 0.1.0-alpha.0
---

# Spec-06-Capability-Tokens

`Spec-06-Capability-Tokens` defines short-lived, signed grants used for
federated and delegated operations. Capability tokens are scoped credentials:
they grant a subject a verb on a specific object for a bounded time window.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for capability-token shape,
issuance, verification, and revocation. It intentionally does **not** define
peer admission, manifest schema, replay-window policy, or capability-based
instruction semantics.

## Token Purpose

Static API keys are node-local credentials. Capability tokens provide a portable
credential that a receiving peer can verify from issuer manifest material
without calling back to the issuer on every operation.

## Token Shape

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

The `issuer` identifies the authority that signed the token. The `subject` is
the principal receiving the grant. The `verb` identifies the allowed action, and
the `object` identifies the target scope, garden, entity, or route family.

## Signing

The signature covers a canonical encoding of the token body with `signature`
omitted. The signing key MUST correspond to an active key in the issuer's
manifest. Receivers MUST verify the issuer manifest before trusting the token.

## Issuance

Capability-token issuance is exposed through the HTTP route owned by
`Spec-03-HTTP-API`:

```http
POST /v1/federation/capability-tokens
```

Only authorized administrative callers may issue capability tokens. Issuance
MUST record token id, issuer, subject, verb, object, expiry, and nonce so that
revocation and audit can refer to the token later.

## Verification

Receivers MUST verify:

1. The token signature.
2. The issuer manifest and active key id.
3. The token has not expired.
4. The nonce is well-formed.
5. The token has not been revoked.
6. The requested operation is within the `(verb, object)` grant.

Verification failure MUST deny the operation. Implementations SHOULD distinguish
signature, expiry, revocation, and scope/verb failures in audit logs.

## Revocation

Revocation is exposed through:

```http
POST /v1/federation/capability-tokens/{token_id}/revoke
```

Revocation invalidates a token before its natural expiry. Nodes SHOULD publish
revocation evidence through the same transparency-log mechanism used for
manifests when configured. Receivers MUST treat revoked tokens as invalid even
if the token signature and expiry are otherwise valid.

## Replay Relationship

The token nonce identifies a token instance. Runtime replay windows and inbound
request nonce caches are owned by `Spec-11-Replay-Protection`; this spec only
requires the token to carry a verifiable nonce.

## Grant Boundaries

Capability tokens are additive grants, not proof of broad identity authority. A
token granting `write` on one object MUST NOT be interpreted as a grant to write
any other object. A token granting access to a garden or scope MUST still pass
the local ACL and scope enforcement rules that apply to that operation.

## Out Of Scope

This spec does not define:

- API-key creation or local operator credentials.
- Peer-token handshakes that are separate from capability tokens.
- Capability-based instruction `interpret_as` enforcement.
- Replay cache implementation.
- Token UI or CLI workflows.
