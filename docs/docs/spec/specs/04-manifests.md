---
spec_id: Spec-04-Manifests
version: 0.1.0-alpha.0
status: Draft
audience: Spec
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 19.1-19.2 manifest material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-04-Manifests

<p className="stigmem-meta"><span>3 min read</span><span>Spec contributor · Node operator</span><span>Draft · v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this spec defines**

Organization and node manifests: the signed statement of entity
authority, public signing keys, key identifiers, rotation events,
validity bounds, and transparency-log evidence used by federation
trust.

</div>

## Extraction status

This file contains the ADR-020 §9 (modular specs) prose extraction for manifest
publication and verification. It intentionally does **not** define
peer admission policy, replication authorization, or
capability-token grants; those belong in
`Spec-05-Federation-Trust` and `Spec-06-Capability-Tokens`.

## Manifest purpose

<div className="stigmem-keypoint">

**A manifest is a signed statement of entity authority.**

It lets a peer verify that a node or organization is authoritative
for the entity URIs it claims and exposes the public key material
needed to verify signatures issued by that authority. Manifests
replace ad hoc key exchange — peers resolve a manifest during the
federation handshake and use it to verify the sender's signatures
and declared entity list.

</div>

## Manifest shape

```text
Manifest {
  manifest_version: integer
  entity_uri:       URI
  public_key:       base64url Ed25519 public key
  key_id:           string
  entities:         URI[]
  rotation_events:  RotationEvent[]
  issued_at:        ISO 8601 UTC
  expires_at:       ISO 8601 UTC
  signature:        base64url Ed25519 signature
}

RotationEvent {
  old_key_id: string
  new_key_id: string
  public_key: base64url Ed25519 public key
  rotated_at: ISO 8601 UTC
  signature:  base64url Ed25519 signature
}
```

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Role</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>entity_uri</code></dt>
<dt><span className="stigmem-fields__type">root authority</span></dt>
<dd>Root entity URI for the node or organization.</dd>
</div>

<div>
<dt><code>entities</code></dt>
<dt><span className="stigmem-fields__type">explicit list</span></dt>
<dd>The specific entity URIs this manifest is authoritative for. Implementations MUST NOT treat an omitted entity as covered by implication unless another accepted spec explicitly defines a delegation rule.</dd>
</div>

<div>
<dt><code>key_id</code></dt>
<dt><span className="stigmem-fields__type">fingerprint</span></dt>
<dd>SHOULD be a stable fingerprint of the active public key. Used for lookup, revocation, and audit evidence; not a substitute for signature verification.</dd>
</div>

<div>
<dt><code>rotation_events</code></dt>
<dt><span className="stigmem-fields__type">key history</span></dt>
<dd>Lets peers verify changes in signing keys over time.</dd>
</div>

</div>

## Canonical encoding

The manifest signature is computed over a canonical JSON
representation of the manifest with the `signature` field omitted.
Implementations MUST use a stable field order and byte representation
so that peers can verify signatures independently.

## Publication and resolution

<div className="stigmem-fields">

<div>
<dt>Operation</dt>
<dt><span className="stigmem-fields__type">Route</span></dt>
<dd>Authorization</dd>
</div>

<div>
<dt>Publish</dt>
<dt><span className="stigmem-fields__type"><code>PUT /v1/federation/manifest</code></span></dt>
<dd>The node MUST verify the uploaded manifest signature before persisting it. Publication by non-admin callers MUST be rejected.</dd>
</div>

<div>
<dt>Resolve</dt>
<dt><span className="stigmem-fields__type"><code>GET /v1/federation/manifest/&#123;entity_uri_encoded&#125;</code></span></dt>
<dd>Returns the full manifest object when the node has a valid manifest covering the requested entity. Missing manifests return <code>404 Not Found</code>.</dd>
</div>

</div>

Route shape is owned by `Spec-03-HTTP-API`.

## Transparency-log evidence

When a transparency-log backend is configured, the node SHOULD
publish manifest events to the log and retain inclusion evidence.
Transparency-log evidence lets peers audit manifest history
independently of the runtime node.

This spec depends on transparency-log evidence for auditability, but
does not require a specific production log service. The trust
decision for which log to use belongs to deployment policy and
federation-trust configuration.

## Key rotation

<div className="stigmem-keypoint">

**A rotation event MUST bind the old key id, new key id, new public key, rotation time, and signature.**

Peers MUST verify the rotation chain before accepting a new active
key for an existing authority. Key rotation and peer trust windows
are interpreted by `Spec-05-Federation-Trust`.

</div>

## Expiry

Peers MUST reject expired manifests. Nodes SHOULD refresh manifests
before `expires_at` to avoid federation interruptions. A manifest
with an expiry far in the future can weaken rotation discipline, so
deployments SHOULD choose bounded validity windows appropriate to
their operator model.

## Out of scope

This spec does not define:

<div className="stigmem-grid">

<div><h4>Peer admission decisions</h4><p>After manifest verification.</p></div>
<div><h4>Capability-token shape</h4><p>Signing or revocation.</p></div>
<div><h4>Replication scope authorization</h4></div>
<div><h4>Production Sigstore/Rekor</h4><p>Deployment requirements.</p></div>

</div>
