---
title: Glossary
sidebar_label: Glossary
description: Definitions of key terms used in the Stigmem protocol and documentation.
---

# Glossary

<p className="stigmem-meta"><span>4 min read</span><span>Everyone</span><span>Reference</span></p>

<div className="stigmem-lead">

**What this page covers**

Canonical definitions for terms used throughout the Stigmem protocol
specification and documentation. Each entry cites the relevant
modular spec.

</div>

---

## Capability Token {#capability-token}

<div className="stigmem-keypoint">

**A signed, short-lived credential that grants a specific named permission (verb) to a specific subject from a specific issuer.**

Replaces ad-hoc per-peer trust agreements with a verifiable,
revocable, auditable delegation primitive. Carries an Ed25519
signature, a `verb` (`read`, `write`, `admin`, `federate`,
`subscribe`, `tombstone:read`), an `object`, and a mandatory expiry
(max 90 days).

</div>

**Spec:** `Spec-06-Capability-Tokens`

```json
{
  "token_id": "a1b2c3d4-...",
  "issuer": "stigmem://node.acme.example",
  "subject": "stigmem://node.acme.example/user/alice",
  "verb": "write",
  "object": "stigmem://node.acme.example/scope/company",
  "expiry": "2026-08-01T00:00:00Z"
}
```

---

## CID (Content ID) {#cid}

<div className="stigmem-keypoint">

**A content-addressed hash that uniquely identifies a fact by its canonical body.**

Computed as `sha256:` followed by the hex-encoded SHA-256 digest of
the fact's deterministic canonical JSON serialization. Enables
deduplication, tamper detection, and idempotent federation
ingestion without requiring a central ID authority.

</div>

**Spec:** [`Spec-21-Content-Addressed-IDs`](../../spec/specs/21-content-addressed-ids.md)

**Guide:** [Content Addressing](../../concepts/facts/content-addressing.md)

```
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Fact {#fact}

<div className="stigmem-keypoint">

**The atomic unit of knowledge in Stigmem.**

An immutable tuple `(entity, relation, value, source, timestamp,
hlc, confidence, scope)`. Facts are append-only — there is no `PUT`
or `DELETE`. Updating a value means asserting a new fact. A fact
with `confidence = 0.0` is a retraction.

</div>

**Spec:** `Spec-01-Fact-Model`

```json
{
  "entity": "stigmem://node/user/alice",
  "relation": "memory:role",
  "value": { "type": "string", "v": "engineer" },
  "source": "stigmem://node/agent/onboarding",
  "confidence": 1.0,
  "scope": "company"
}
```

---

## Garden {#garden}

<div className="stigmem-keypoint">

**A named, ACL-controlled partition within a scope.**

Provides fine-grained access control above the four-level scope
hierarchy. Each garden has a `slug`, a fixed `scope`, and a
membership list of principals with roles (`admin`, `writer`,
`reader`). Garden-tagged facts are never replicated to federation
peers — garden membership is node-local.

</div>

**Spec:** `Spec-02-Scopes-and-ACL`

```bash
curl -X POST http://localhost:8765/v1/gardens \
  -H "Authorization: Bearer $KEY" \
  -d '{"slug": "project-atlas", "name": "Project Atlas", "scope": "company"}'
```

---

## HLC (Hybrid Logical Clock) {#hlc}

The timestamp scheme used for causal ordering across federated nodes. Format: `{wall_ms_utc}.{counter}` (e.g., `1746230400000.003`). On each local write, the node advances the clock to `max(now_ms, last_hlc_ms)` and increments the counter if the wall component is unchanged. On receiving a federated fact, the clock advances to `max(now_ms, received_hlc_ms)`.

<div className="stigmem-keypoint">

**HLCs ensure that causally related facts are correctly ordered even when wall clocks drift between nodes.**

</div>

**Spec:** [`Spec-12-HLC-Bounded-Skew`](../../spec/specs/12-hlc-bounded-skew.md)

**Architecture:** [Federated Network](../architecture/federated-network.md)

```
1746230400000.003   ← wall_ms = 1746230400000, counter = 3
```

---

## PeerDeclaration {#peerdeclaration}

A signed statement one Stigmem node sends to another when establishing federation. It identifies the peer, publishes the peer's federation public key, and lists the scopes the peer is allowed to exchange. The receiving node verifies the signature before marking the peer active.

**Spec:** [`Spec-05-Federation-Trust`](../../spec/specs/05-federation-trust.md)

**Guide:** [Federation Handshake](../../concepts/federation/federation-handshake.md)

---

## Relation {#relation}

A namespaced string that identifies what kind of statement a fact makes about its entity. Relations use a `namespace:name` format to prevent collisions between independent systems asserting facts about the same entity. The spec maintains a namespace registry of reserved prefixes.

**Spec:** `Spec-01-Fact-Model`, `Spec-16-Namespace-Registry`

```
memory:role          ← the entity's role, in the memory namespace
garden:member        ← garden membership relation
stigmem:received_from ← system-generated provenance relation
```

---

## Scope {#scope}

One of four visibility levels that partition facts for access control and federation eligibility:

<div className="stigmem-fields">

<div>
<dt>Scope</dt>
<dt><span className="stigmem-fields__type">Federates?</span></dt>
<dd>Visibility</dd>
</div>

<div>
<dt><code>local</code></dt>
<dt><span className="stigmem-fields__type">no</span></dt>
<dd>Node-only, never leaves this instance.</dd>
</div>

<div>
<dt><code>team</code></dt>
<dt><span className="stigmem-fields__type">no</span></dt>
<dd>Logical team boundary, node-operator-defined.</dd>
</div>

<div>
<dt><code>company</code></dt>
<dt><span className="stigmem-fields__type">opt-in</span></dt>
<dd>Owning company node. Only when PeerDeclaration explicitly allows.</dd>
</div>

<div>
<dt><code>public</code></dt>
<dt><span className="stigmem-fields__type">default</span></dt>
<dd>Any registered peer.</dd>
</div>

</div>

<div className="stigmem-keypoint">

**Scope is enforced at write time, read time, and federation time.**

API key must permit the scope on write; queries only return facts
the caller's key allows; outbound replication respects
PeerDeclaration scope limits.

</div>

**Spec:** `Spec-02-Scopes-and-ACL`

---

## Source Trust {#source-trust}

A per-source score used to estimate how much weight to give facts from a particular source. Source trust combines identity strength, peer history, scope authority, and attestation mode; recall can use it to downweight less-trusted facts, and strict deployments can route low-trust facts to quarantine for review.

**Spec:** [`Spec-05-Federation-Trust`](../../spec/specs/05-federation-trust.md)

**Guide:** [Source Trust and Quarantine](../../concepts/federation/source-trust-and-quarantine.md)

---

## Source Attestation {#source-attestation}

An opt-in plugin mechanism that validates a fact's declared `source` URI
against the caller's authenticated `entity_uri` and explicit delegated source
entities.

<div className="stigmem-keypoint">

**Without attestation, any authenticated principal could claim to be anyone by writing an arbitrary `source` value.**

The current alpha plugin keeps default installs inert. Plugin-loaded
deployments can enforce source checks and contribute recall/federation guard
behavior, but warn-mode persistence and `attested: true` marking are not
implemented yet.

<div className="stigmem-grid">

<div><h4><code>enforce</code></h4><p>Reject mismatches when the plugin gate is enabled.</p></div>
<div><h4><code>warn</code></h4><p>Compatibility posture; persistence is not implemented in the alpha plugin.</p></div>
<div><h4><code>off</code></h4><p>No check.</p></div>

</div>

Production multi-tenant deployments should use `enforce`.

</div>

**Spec:** `Spec-X6-Source-Attestation`, `Spec-02-Scopes-and-ACL`

```bash
# A key with entity_uri "stigmem://node/agent/bot-a" can only write
# facts with source matching that URI (in enforce mode)
curl -X POST http://localhost:8765/v1/facts \
  -H "Authorization: Bearer $BOT_A_KEY" \
  -d '{"entity": "stigmem://node/user/alice", "relation": "memory:role",
       "value": {"type": "string", "v": "engineer"},
       "source": "stigmem://node/agent/bot-a", "scope": "company"}'
```

---

## Tombstone {#tombstone}

A signed right-to-be-forgotten (RTBF) marker for suppressing facts about an entity URI, optionally scoped.

<div className="stigmem-keypoint">

**Tombstones are distinct from normal retraction (`confidence = 0.0`) and are currently an opt-in experimental plugin source package.**

Not part of the v0.9.0a1 default install or a supported compliance
surface. Default installs expose tombstone route contracts but keep
them access-gated, and do not apply tombstone filtering unless
`stigmem-plugin-tombstones` is explicitly registered.

</div>

**Spec:** `Spec-X2-RTBF-Tombstones`
