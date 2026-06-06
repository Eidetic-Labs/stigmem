---
spec_id: Spec-04-Manifests
version: 0.1.0-alpha.0
status: Draft
applies_to: stigmem v0.9.0aN
last_updated: 2026-05-14
supersedes: spec/stigmem-spec-v0.9.0a1.md section 19.1-19.2 manifest material
depends_on:
  - Spec-01-Fact-Model >= 0.1.0-alpha.0
---

# Spec-04-Manifests

`Spec-04-Manifests` defines organization and node manifests: the signed
statement of entity authority, public signing keys, key identifiers, rotation
events, validity bounds, and transparency-log evidence used by federation trust.

## Extraction Status

This file contains the ADR-020 §9 (modular specs) prose extraction for manifest publication and
verification. It intentionally does **not** define peer admission policy,
replication authorization, or capability-token grants; those belong in
`Spec-05-Federation-Trust` and `Spec-06-Capability-Tokens`.

## Manifest Purpose

A manifest lets a peer verify that a node or organization is authoritative for
the entity URIs it claims and exposes the public key material needed to verify
signatures issued by that authority.

Manifests replace ad hoc key exchange. A peer can resolve a manifest during the
federation handshake and use it to verify the sender's signatures and declared
entity list.

## Manifest Shape

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

The `entity_uri` is the root entity URI for the node or organization. The
`entities` list names the specific entity URIs this manifest is authoritative
for. Implementations MUST NOT treat an omitted entity as covered by implication
unless another accepted spec explicitly defines a delegation rule.

## Canonical Encoding

The manifest signature is computed over a canonical JSON representation of the
manifest with the `signature` field omitted. Implementations MUST use a stable
field order and byte representation so that peers can verify signatures
independently.

The `key_id` SHOULD be a stable fingerprint of the active public key. It is used
for lookup, revocation, and audit evidence; it is not a substitute for signature
verification.

## Publication

Manifest publication uses the HTTP route owned by `Spec-03-HTTP-API`:

```http
PUT /v1/federation/manifest
```

The node MUST verify the uploaded manifest signature before persisting it.
Publication by non-admin callers MUST be rejected.

## Resolution

Manifest resolution uses:

```http
GET /v1/federation/manifest/{entity_uri_encoded}
```

The response returns the full manifest object when the node has a valid manifest
covering the requested entity. Missing manifests return `404 Not Found`.

## Transparency-Log Evidence

When a transparency-log backend is configured, the node SHOULD publish manifest
events to the log and retain inclusion evidence. Transparency-log evidence lets
peers audit manifest history independently of the runtime node.

This spec depends on transparency-log evidence for auditability, but does not
require a specific production log service. The trust decision for which log to
use belongs to deployment policy and federation-trust configuration.

## Key Rotation

Manifests carry `rotation_events` so peers can verify changes in signing keys
over time. A rotation event MUST bind the old key id, new key id, new public key,
rotation time, and signature. Peers MUST verify the rotation chain before
accepting a new active key for an existing authority.

Key rotation and peer trust windows are interpreted by `Spec-05-Federation-Trust`.

## Expiry

Peers MUST reject expired manifests. Nodes SHOULD refresh manifests before
`expires_at` to avoid federation interruptions. A manifest with an expiry far in
the future can weaken rotation discipline, so deployments SHOULD choose bounded
validity windows appropriate to their operator model.

## Out Of Scope

This spec does not define:

- Peer admission decisions after manifest verification.
- Capability-token shape, signing, or revocation.
- Replication scope authorization.
- Production Sigstore/Rekor deployment requirements.
