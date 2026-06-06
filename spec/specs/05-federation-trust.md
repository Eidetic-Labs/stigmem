---
spec_id: Spec-05-Federation-Trust
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 6 and 19 federation-trust material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
  - Spec-04-Manifests >= 0.1.0-alpha.0
---

# Spec-05-Federation-Trust

`Spec-05-Federation-Trust` defines peer admission, peer verification,
replication authorization, per-hop scope enforcement, source-trust handling, and
federation audit boundaries.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for federation trust. It
intentionally does **not** define manifest shape (`Spec-04-Manifests`),
capability-token structure (`Spec-06-Capability-Tokens`), quarantine moderation
(`Spec-08-Quarantine-Garden`), replay windows (`Spec-11-Replay-Protection`), or
transport hardening (`Spec-10-Hardening`).

## Peer Declaration

A peer declaration binds a node id, reachable node URL, public federation key,
and allowed replication scopes. A node MUST NOT replicate with a peer until that
peer is registered and verified.

```text
PeerDeclaration {
  node_id:        URI
  node_url:       URL
  public_key:     base64url Ed25519 public key
  allowed_scopes: FactScope[]
  signed_at:      ISO 8601 UTC
  signature:      base64url Ed25519 signature
}
```

The signature covers the canonical declaration body. The public key can be
confirmed through the peer's manifest and discovery document.

## Verification

Peer verification MUST:

1. Resolve the peer's discovery document.
2. Resolve or verify the peer manifest per `Spec-04-Manifests`.
3. Verify the declaration signature against the declared public key.
4. Confirm the declared node id and public key match the resolved peer evidence.
5. Transition the peer to `active` only after all required checks pass.

Rejected peers MUST NOT receive or send replicated facts. Implementations SHOULD
retain rejection reason and timestamp for audit.

## Replication Authorization

Replication is authorized by the intersection of:

- the fact's own `scope`,
- the source peer's allowed scopes,
- the current peer relationship's allowed scopes, and
- any peer-token or capability constraints required by the route.

Nodes MUST NOT return facts outside that intersection. Nodes MUST reject inbound
facts whose scope exceeds the sender's authorization.

## Pull Replication

Pull replication is the default synchronization mechanism. The requesting peer
provides a cursor and a limit; the responding node returns facts after that
cursor, filtered by the authorization rules above.

Cursors are opaque to clients. Reusing the same cursor MUST be idempotent:
receivers must not create duplicate facts when the same page is ingested more
than once.

## Push Replication

Push replication is optional and low-latency. Nodes that advertise push support
MUST apply the same inbound validation, deduplication, scope checks, and audit
logging as pull ingestion. Nodes that do not support push SHOULD omit the push
endpoint from discovery or return `405 Method Not Allowed`.

## Scope Propagation

Scope enforcement is per-hop. A relay node MUST NOT escalate a fact's scope when
serving another peer. Company-scoped facts received from one peer MUST NOT be
re-federated to another peer unless a future accepted spec explicitly defines an
operator opt-in path.

Relay nodes SHOULD retain origin metadata sufficient to enforce the original
peer's allowed-scope boundary when serving later peers.

## Source Trust

Federation trust may compute a source-trust score from manifest validity,
attestation evidence, peer history, and configured trust mode. Trust scores are
local derived values; peers MUST NOT be allowed to provide a source-trust value
that the receiver accepts as authoritative.

Advanced trust scoring remains subject to calibration and should be kept
separate from basic peer admission and scope authorization.

## Federation Audit

Nodes SHOULD audit federation events that materially affect trust or data flow:

- peer registered,
- peer verified,
- peer rejected,
- fact accepted,
- fact rejected,
- scope violation,
- replay violation,
- manifest or signature verification failure.

Audit record shape belongs to `Spec-09-Audit-Log`.

## Out Of Scope

This spec does not define:

- manifest schema or transparency-log evidence,
- capability-token wire format,
- quarantine promote/reject operations,
- mTLS certificate requirements,
- replay nonce windows, or
- content-addressed fact IDs.
