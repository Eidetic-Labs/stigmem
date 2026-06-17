---
title: Federation DNSSEC Origin Trust
sidebar_label: Federation DNSSEC Trust
description: Publish the DNSSEC binding TXT record, enable relay-path DNSSEC origin trust, and work the operator-confirm queue for unsigned or unreachable origins.
audience: Operator
---

# Federation DNSSEC Origin Trust

<p className="stigmem-meta"><span>8 min read</span><span>Node operator</span><span>v0.9.0aN</span></p>

<div className="stigmem-lead">

**What this runbook covers**

Publish the DNSSEC-signed binding record that lets a downstream node
re-derive your origin key when your node is unreachable, enable the
relay-path DNSSEC trust tier, and work the operator-confirm queue for
origins that DNSSEC cannot anchor.

</div>

**Audience:** operators running a multi-hop relay (`federation_relay_enabled=true`) who want a relayed origin's facts to remain trustable when the origin node is offline but its DNS zone is DNSSEC-signed.
**See also:** [Federation Peer Setup](./federation-setup), [Federation trust](../../concepts/federation/federation-trust).

## What problem this solves

In a multi-hop relay (A → B → C), node C may receive a fact that originated at A but was relayed through B. C must verify A's per-fact origin signature against A's key. The pre-DNSSEC anchors are: an operator pin, a stored first-party binding, or a fetch-on-first TOFU fetch of A's manifest. **All three require A to be reachable or already known.** If A is unreachable and unknown, C fails closed (`relay_origin_unanchored`).

DNSSEC origin trust adds one more anchor *after* those three: A publishes a DNSSEC-signed TXT record that binds A's `entity_uri` to A's key fingerprint. Because A's DNS is independent of A's node, C can re-derive (and re-check the recency/revocation of) A's key **without ever contacting A** — A's node can stay offline while its DNS keeps answering.

The tier is **default-OFF** and strictly additive: with the flag off, the relay path is byte-identical to before (it fails closed exactly as it did, never calling a resolver).

## Step 1 — Publish the binding TXT record

Publish a DNSSEC-signed TXT record at `_stigmem-fed._key.<canonical-host>`, where `<canonical-host>` is the host of your node's `entity_uri` (for `https://memory.acme.example/` the qname is `_stigmem-fed._key.memory.acme.example`). **Your zone must be DNSSEC-signed** — the record is only consulted when the full chain to the IANA root validates.

The record grammar is `v=stigmem1`, semicolon-separated `key=value` pairs. Two forms:

```text
# active binding
v=stigmem1; fpr=<key_fpr>; epoch=<n>; prev_fpr=<or-empty>; prev_until=<or-empty>

# revocation tombstone (withdraws all keys for the host)
v=stigmem1; status=revoked; epoch=<n>; fpr=
```

<div className="stigmem-fields">

<div>
<dt>Field</dt>
<dt><span className="stigmem-fields__type">Required</span></dt>
<dd>Meaning</dd>
</div>

<div>
<dt><code>v=stigmem1</code></dt>
<dt><span className="stigmem-fields__type">yes (first token)</span></dt>
<dd>Version sentinel. Must be the first token or the record is rejected.</dd>
</div>

<div>
<dt><code>fpr</code></dt>
<dt><span className="stigmem-fields__type">active: yes</span></dt>
<dd>The bound key fingerprint (the same fingerprint format the manifest publishes). Empty/omitted on a revocation tombstone.</dd>
</div>

<div>
<dt><code>epoch</code></dt>
<dt><span className="stigmem-fields__type">yes</span></dt>
<dd>A monotonic non-negative integer. A record at an epoch <em>below</em> the floor a downstream node has already seen is a rollback and is rejected. Bump it on every rotation/revocation.</dd>
</div>

<div>
<dt><code>prev_fpr</code></dt>
<dt><span className="stigmem-fields__type">no</span></dt>
<dd>During a rotation, the retiring key's fingerprint. A relayed fact still signed by the retiring key is honored while inside the grace window.</dd>
</div>

<div>
<dt><code>prev_until</code></dt>
<dt><span className="stigmem-fields__type">no</span></dt>
<dd>ISO-8601 deadline for the <code>prev_fpr</code> grace. When omitted, the downstream derives a grace from <code>federation_key_rotation_grace_hours</code>. A present-but-unparseable value fails closed (no grace).</dd>
</div>

</div>

Unknown `key=value` pairs are ignored, so adding a field in a future version is a routine zone re-sign rather than a breaking change.

<div className="stigmem-keypoint">

**Re-sign the record on your normal zone cadence.** A downstream node treats an aged RRSIG on the relay path as a hard reject (it cannot run a mid-relay operator-confirm). Keep the binding RRSIG fresh relative to `federation_dnssec_max_rrsig_age` (default 7 days).

</div>

### Rotating your key

1. Generate the new key and update your manifest (see [Federation Peer Setup](./federation-setup)).
2. Re-sign the binding TXT at a **strictly higher epoch**, with `fpr=<new>` and `prev_fpr=<old>` plus a `prev_until` covering the in-flight window.
3. Once the grace window has elapsed, re-sign again dropping `prev_fpr`/`prev_until`.

### Revoking your key

Publish the tombstone form (`status=revoked; fpr=` at a higher epoch). A downstream re-check that resolves the tombstone hard-rejects the relayed fact (`relay_origin_revoked`) — and this works while your node is offline, because revocation lives in your DNS, not your node.

## Step 2 — Enable the relay-path DNSSEC trust tier

DNSSEC origin trust is a sub-feature of multi-hop relay. It is only meaningful when relay is also on.

```bash
# both flags must be ON for the DNSSEC tier to run
export STIGMEM_FEDERATION_RELAY_ENABLED=true
export STIGMEM_FEDERATION_DNSSEC_TRUST_ENABLED=true
# restart the node
```

With `federation_dnssec_trust_enabled=false` (the default) the tier is inert: no resolver is constructed, no DNS is queried, and an unanchored unreachable origin fails closed exactly as before.

### How a relayed origin key is trusted

When C receives a relayed fact from an unreachable, unpinned, unknown origin A whose carried manifest supplies a **candidate** fingerprint, C runs the first-trust ladder:

<ol className="stigmem-steps">
<li><strong>operator-pin</strong> — a human-confirmed anchor wins outright.</li>
<li><strong>DNSSEC</strong> — resolve <code>_stigmem-fed._key.&lt;host&gt;</code>; the validated record's fingerprint must equal the candidate. On success C pins the binding.</li>
<li><strong>operator-confirm</strong> — an unsigned/insecure delegation, an authenticated absence on a never-signed host, or a slow-resigning (aged) signature parks the candidate in a queue for a human (Step 3).</li>
<li><strong>fail-closed</strong> — anything else (revoked, rollback, bogus chain, unvalidatable) is rejected.</li>
</ol>

### Recency / revocation re-check

A relayed DNSSEC key is honored only after a **relay-path recency re-check** confirms the binding is still current. The re-check cadence is `clamp(record_DNS_TTL, floor, cap)` measured from the pin's **last genuine DNS validation**:

- `STIGMEM_FEDERATION_DNSSEC_RECHECK_FLOOR_SECONDS` (default `300`) — anti-storm floor.
- `STIGMEM_FEDERATION_DNSSEC_RECHECK_CAP_SECONDS` (default `3600`) — re-resolve at least this often.

Within the cadence the pinned key is honored with no DNS egress (re-checks are cached per-origin, not per-fact). Past it, C re-resolves once and applies asymmetric semantics:

<div className="stigmem-fields">

<div>
<dt>Re-check result</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Audit event</dd>
</div>

<div>
<dt>active, fingerprint still matches</dt>
<dt><span className="stigmem-fields__type">honor</span></dt>
<dd>—</dd>
</div>

<div>
<dt>rotation (higher epoch, new fpr; prior key in grace)</dt>
<dt><span className="stigmem-fields__type">honor + advance pin</span></dt>
<dd>—</dd>
</div>

<div>
<dt><code>status=revoked</code> tombstone</dt>
<dt><span className="stigmem-fields__type">reject</span></dt>
<dd><code>relay_origin_revoked</code></dd>
</div>

<div>
<dt>epoch below the seen floor (rollback)</dt>
<dt><span className="stigmem-fields__type">reject</span></dt>
<dd><code>relay_origin_rolled_back</code></dd>
</div>

<div>
<dt>aged RRSIG (operator-confirm is first-trust-only)</dt>
<dt><span className="stigmem-fields__type">reject</span></dt>
<dd><code>relay_origin_recheck_stale</code></dd>
</div>

<div>
<dt>no validatable answer (transport/SERVFAIL/insecure/absent)</dt>
<dt><span className="stigmem-fields__type">honor within grace, else reject</span></dt>
<dd><code>relay_origin_recheck_unreachable</code></dd>
</div>

</div>

A **positive** withdrawal (revoked/rollback) is hard-rejected — an attacker cannot forge one, so a positive answer is proof. **Suppression** (no positive proof) is honored only up to `min(STIGMEM_FEDERATION_DNSSEC_UNREACHABLE_GRACE_SECONDS, STIGMEM_FEDERATION_DNSSEC_UNREACHABLE_TTL_MULTIPLE × cap)` measured from the last genuine DNS validation — never treated as a revocation, and never extended by relay activity.

## Step 3 — Work the operator-confirm queue

Origins that DNSSEC can neither anchor nor reject (unsigned delegation, authenticated absence on a never-signed host, slow-resigning zone) are parked for an out-of-band human confirm. List, confirm, or reject pending candidates from the CLI (each subcommand calls the local node's admin API; provide `--node-url` or `STIGMEM_NODE_URL`, and an `admin:federation` `--api-key`):

```bash
# list quarantined candidates
stigmem federation dnssec pending

# paste-to-confirm a candidate (the fingerprint must match exactly)
stigmem federation dnssec confirm \
  --entity-uri https://memory.acme.example/ \
  --node-id  stigmem://node-a-... \
  --key-fpr  sha256:...

# reject a candidate without trusting it
stigmem federation dnssec reject \
  --entity-uri https://memory.acme.example/ \
  --node-id  stigmem://node-a-...
```

The same operations are available on the admin API:

- `GET  /v1/federation/dnssec/pending` — list the queue.
- `POST /v1/federation/dnssec/pending/confirm` — paste-to-confirm (the body's pasted fingerprint must match the quarantined candidate).
- `POST /v1/federation/dnssec/pending/reject` — clear a pending row without trusting it.

The per-peer queue is bounded by `federation_dnssec_pending_confirm_cap` (default 100) so an untrusted relay cannot flood it; rows expire after `federation_dnssec_pending_confirm_ttl` (default 7 days).

## Troubleshooting

<div className="stigmem-fields">

<div>
<dt>Symptom</dt>
<dt><span className="stigmem-fields__type">Likely cause</span></dt>
<dd>Fix</dd>
</div>

<div>
<dt>Relayed fact fails closed, audit shows <code>relay_origin_unanchored</code></dt>
<dt><span className="stigmem-fields__type">flag off / no candidate</span></dt>
<dd>Confirm <code>STIGMEM_FEDERATION_DNSSEC_TRUST_ENABLED=true</code> AND the relay carried the origin's manifest (the candidate key the binding fingerprint is matched against).</dd>
</div>

<div>
<dt><code>relay_origin_revoked</code> for a key you did not revoke</dt>
<dt><span className="stigmem-fields__type">stale tombstone</span></dt>
<dd>Check the served TXT — a leftover <code>status=revoked</code> record withdraws the key. Re-sign an active record at a higher epoch.</dd>
</div>

<div>
<dt><code>relay_origin_rolled_back</code></dt>
<dt><span className="stigmem-fields__type">epoch went backwards</span></dt>
<dd>The served epoch is below one a downstream already pinned. Always bump <code>epoch</code> monotonically; never reuse a lower value.</dd>
</div>

<div>
<dt><code>relay_origin_recheck_stale</code></dt>
<dt><span className="stigmem-fields__type">aged RRSIG</span></dt>
<dd>Re-sign the binding TXT; the RRSIG is older than <code>federation_dnssec_max_rrsig_age</code>.</dd>
</div>

<div>
<dt>Candidate stuck in the operator-confirm queue</dt>
<dt><span className="stigmem-fields__type">unsigned/absent/aged</span></dt>
<dd>DNSSEC could not anchor it. Verify the candidate out-of-band, then <code>stigmem federation dnssec confirm</code> (or sign the zone and let the binding re-resolve).</dd>
</div>

</div>
