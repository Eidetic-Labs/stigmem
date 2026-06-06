---
spec_id: Spec-05-Federation-Trust
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md sections 6 and 19 federation-trust material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
  - Spec-02-Scopes-and-ACL >= 0.1.0-alpha.0
  - Spec-04-Manifests >= 0.1.0-alpha.0
---

# Spec-05-Federation-Trust

<p className="stigmem-meta"><span>4 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Peer admission, peer verification, replication authorization,
per-hop scope enforcement, source-trust handling, and federation
audit boundaries.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for federation
trust. It intentionally does **not** define manifest shape
(`Spec-04-Manifests`), capability-token structure
(`Spec-06-Capability-Tokens`), quarantine moderation
(`Spec-08-Quarantine-Garden`), replay windows
(`Spec-11-Replay-Protection`), or transport hardening
(`Spec-10-Hardening`).

## Peer declaration

A peer declaration binds a node id, reachable node URL, public
federation key, and allowed replication scopes.

<div className="stigmem-keypoint">

**A node MUST NOT replicate with a peer until that peer is registered and verified.**

</div>

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

The signature covers the canonical declaration body. The public key
can be confirmed through the peer's manifest and discovery document.

## Verification

Peer verification MUST:

<ol className="stigmem-steps">
<li>Resolve the peer's discovery document.</li>
<li>Resolve or verify the peer manifest per <code>Spec-04-Manifests</code>.</li>
<li>Verify the declaration signature against the declared public key.</li>
<li>Confirm the declared node id and public key match the resolved peer evidence.</li>
<li>Transition the peer to <code>active</code> only after all required checks pass.</li>
</ol>

Rejected peers MUST NOT receive or send replicated facts.
Implementations SHOULD retain rejection reason and timestamp for
audit.

## Replication authorization

<div className="stigmem-keypoint">

**Replication is authorized by the intersection of all applicable scopes.**

The fact's own `scope`, the source peer's allowed scopes, the
current peer relationship's allowed scopes, and any peer-token or
capability constraints required by the route. Nodes MUST NOT return
facts outside that intersection. Nodes MUST reject inbound facts
whose scope exceeds the sender's authorization.

</div>

## Pull vs push replication

<div className="stigmem-fields">

<div>
<dt>Mode</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Behavior</dd>
</div>

<div>
<dt>Pull</dt>
<dt><span className="stigmem-fields__type">default</span></dt>
<dd>The requesting peer provides a cursor and a limit; the responding node returns facts after that cursor, filtered by the authorization rules above. Cursors are opaque to clients. Reusing the same cursor MUST be idempotent: receivers must not create duplicate facts when the same page is ingested more than once.</dd>
</div>

<div>
<dt>Push</dt>
<dt><span className="stigmem-fields__type">optional</span></dt>
<dd>Low-latency. Nodes that advertise push support MUST apply the same inbound validation, deduplication, scope checks, and audit logging as pull ingestion. Nodes that do not support push SHOULD omit the push endpoint from discovery or return <code>405 Method Not Allowed</code>.</dd>
</div>

</div>

## Scope propagation

<div className="stigmem-keypoint">

**Scope enforcement is per-hop.**

A relay node MUST NOT escalate a fact's scope when serving another
peer. Company-scoped facts received from one peer MUST NOT be
re-federated to another peer unless a future accepted spec
explicitly defines an operator opt-in path. Relay nodes SHOULD
retain origin metadata sufficient to enforce the original peer's
allowed-scope boundary when serving later peers.

</div>

## Source trust

Federation trust may compute a source-trust score from manifest
validity, attestation evidence, peer history, and configured trust
mode. Trust scores are local derived values; peers MUST NOT be
allowed to provide a source-trust value that the receiver accepts as
authoritative.

Advanced trust scoring remains subject to calibration and should be
kept separate from basic peer admission and scope authorization.

## Federation audit

Nodes SHOULD audit federation events that materially affect trust or
data flow:

<div className="stigmem-grid">

<div><h4>Peer registered</h4></div>
<div><h4>Peer verified</h4></div>
<div><h4>Peer rejected</h4></div>
<div><h4>Fact accepted</h4></div>
<div><h4>Fact rejected</h4></div>
<div><h4>Scope violation</h4></div>
<div><h4>Replay violation</h4></div>
<div><h4>Manifest/signature failure</h4><p>Verification failure.</p></div>

</div>

Audit record shape belongs to `Spec-09-Audit-Log`.

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Manifest schema</h4><p>Or transparency-log evidence.</p></div>
<div><h4>Capability-token wire format</h4></div>
<div><h4>Quarantine operations</h4><p>Promote/reject.</p></div>
<div><h4>mTLS certificate requirements</h4></div>
<div><h4>Replay nonce windows</h4></div>
<div><h4>Content-addressed fact IDs</h4></div>

</div>
