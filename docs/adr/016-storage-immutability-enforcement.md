# ADR-016: Storage immutability enforcement

<p className="stigmem-meta"><span>8 min read</span><span>Accepted</span><span>Recorded 2026-05-07</span></p>

<div className="stigmem-lead">

**What this ADR decides**

A four-layer defense-in-depth immutability stack (architectural,
trigger-level, cryptographic, sequence, external-witness) that makes
fact tampering detectable even under admin compromise. The Sigstore
Rekor anchor at L5 is the layer that makes the "facts are immutable"
claim durable against R-23.

</div>

<div className="stigmem-keypoint">

**Stigmem's spec claims facts are immutable. A code audit reveals the claim is structurally unsupported.**

The <code>facts</code> table in <code>node/migrations/001_init.sql</code>
has no triggers, no permission denials, no mechanism preventing
UPDATE or DELETE. Application code issues <code>UPDATE facts</code> in
at least seven distinct places. Immutability is by convention only,
and the convention is already partially violated by core paths.

</div>

**Date:** 2026-05-07 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), [ADR-003](./003-prompt-injection) (load-bearing dependency on immutability), [ADR-011](./011-cross-cutting-extraction) (CIDs-as-core); threat model R-09, **R-23 (admin-level storage tampering)**

## Context

This is not just a technical-debt issue. **ADR-003's prompt-injection
trust boundary depends on storage immutability.** The L2 rule
(federation cannot promote `interpret_as` on replication) assumes the
storage `interpret_as` value is trustworthy. If an attacker can mutate
facts in place — change `value_v` to malicious payloads, change
`interpret_as` from `content` to `instruction` — ADR-003's structural
defenses are bypassed by storage compromise, not by federation.

<div className="stigmem-keypoint">

**R-23: admin-level storage tampering / fact mutation attack.**

A malicious actor with admin-level privileges on a stigmem node (via
supply-chain compromise, credential theft, insider threat, or operator
error) overwrites existing facts with malicious instruction payloads.
The mutated facts are served through stigmem's federated recall path
to consuming LLM agents, executing data exfiltration or arbitrary
commands.

</div>

This is a credible threat that local enforcement alone cannot defeat:
an attacker with admin privileges controls the database, the
application code, the migrations, the file system, and the verifier.
**Every layer that lives entirely on the compromised node is
theoretically bypassable.** The only durable defense is anchoring
fact integrity to evidence the attacker does not control.

## Decision

Adopt a four-layer immutability stack as the v1.0 baseline.

<div className="stigmem-fields">

<div>
<dt>Layer</dt>
<dt><span className="stigmem-fields__type">Defends against</span></dt>
<dd>Mechanism</dd>
</div>

<div>
<dt>L1 · architectural</dt>
<dt><span className="stigmem-fields__type">application bugs, accidental mutation</span></dt>
<dd>Append-only journal + projection tables.</dd>
</div>

<div>
<dt>L2 · engine</dt>
<dt><span className="stigmem-fields__type">code-path violations going around L1</span></dt>
<dd>SQLite triggers blocking UPDATE/DELETE on <code>facts</code>.</dd>
</div>

<div>
<dt>L3 · per-record cryptographic</dt>
<dt><span className="stigmem-fields__type">content tampering on a record</span></dt>
<dd>Content-addressed fact IDs (CIDs) recomputed on read.</dd>
</div>

<div>
<dt>L4 · sequence integrity</dt>
<dt><span className="stigmem-fields__type">removal, reordering, insertion</span></dt>
<dd>Local hash chain over fact inserts.</dd>
</div>

<div>
<dt>L5 · external transparency log</dt>
<dt><span className="stigmem-fields__type">admin-level whole-table rewrite (R-23)</span></dt>
<dd>Chain checkpoints anchored to Sigstore Rekor.</dd>
</div>

</div>

### Layer 1 (L1) · Append-only journal + projection tables

The `facts` table becomes append-only by application architecture.
Mutating paths refactor to write to projection tables that are
explicitly mutable, while the source-of-truth `facts` table accepts
only INSERT.

<div className="stigmem-fields">

<div>
<dt>Projection table</dt>
<dt><span className="stigmem-fields__type">Replaces</span></dt>
<dd>Mutation site</dd>
</div>

<div>
<dt><code>fact_validity_overrides</code></dt>
<dt><span className="stigmem-fields__type">decay sweep</span></dt>
<dd>Was <code>UPDATE facts SET valid_until</code>.</dd>
</div>

<div>
<dt><code>fact_embedding_status</code></dt>
<dt><span className="stigmem-fields__type">embedding cache</span></dt>
<dd>Was <code>UPDATE facts SET embedding_missing</code>.</dd>
</div>

<div>
<dt><code>fact_recall_signals</code></dt>
<dt><span className="stigmem-fields__type">recall pipeline</span></dt>
<dd>Was <code>UPDATE facts ...</code> from <code>recall_pipeline.py</code>.</dd>
</div>

<div>
<dt><code>fact_cid_backfill</code></dt>
<dt><span className="stigmem-fields__type">CID assignment</span></dt>
<dd>Was <code>UPDATE facts SET cid</code> from <code>cli.py</code>.</dd>
</div>

<div>
<dt><code>fact_quarantine_status</code></dt>
<dt><span className="stigmem-fields__type">quarantine state</span></dt>
<dd>Was <code>UPDATE facts ...</code> from <code>quarantine.py</code>.</dd>
</div>

<div>
<dt><code>fact_garden_membership</code></dt>
<dt><span className="stigmem-fields__type">garden assignment</span></dt>
<dd>Was <code>UPDATE facts ...</code> from <code>gardens.py</code>.</dd>
</div>

</div>

Retraction model unchanged: retraction stays as a new fact assertion
per spec; the retraction *event* lands in `fact_retractions` (already
append-only per the comment in `routes/facts.py:171`). Read-path
queries against `facts` join projection tables for derived state.

~1–2 weeks; touches every read path and every mutation site. Eliminates
the entire class of accidental-mutation bugs.

### Layer 2 (L2) · SQLite triggers

```sql
CREATE TRIGGER facts_no_update
    BEFORE UPDATE ON facts
    BEGIN SELECT RAISE(ABORT, 'facts are append-only (ADR-016)'); END;

CREATE TRIGGER facts_no_delete
    BEFORE DELETE ON facts
    BEGIN SELECT RAISE(ABORT, 'facts are append-only (ADR-016)'); END;
```

Catches any code path that goes around L1's discipline — application
bugs, contributor mistakes, third-party library interactions. Does not
defeat an admin-level attacker (who can `DROP TRIGGER` or edit the
database file directly), but raises the cost and makes non-admin
tampering immediately visible.

Audit events: `fact_mutation_attempted` fires on trigger activation.
Operators monitor this; non-zero counts are anomalous.

### Layer 3 (L3) · Content-addressed fact IDs

Every fact carries a CID (per spec §25): a hash computed
deterministically over the fact's canonical body. On read, the CID is
recomputed and compared.

<div className="stigmem-grid">

<div><h4>Mutation detection</h4><p>If <code>value_v</code> or any CID-covered field is mutated post-insert, the recomputed CID does not match the stored CID. Read path returns an integrity error.</p></div>
<div><h4>Federation included</h4><p>The CID is included in the fact when it federates to peers. Peers can recompute CIDs from canonical body and compare.</p></div>
<div><h4>CID-keyed federation</h4><p>Federation operates on CIDs, not opaque IDs — peers verify content matches expectations.</p></div>

</div>

<div className="stigmem-keypoint">

**This requires moving CIDs from a plugin (per ADR-011 C1 architecture) back to core.**

ADR-011 commits to that move. CIDs are no longer opt-in; they are part
of the v1.0 critical path because R-23 mitigation depends on them.

</div>

The CID computation (CID v2) covers exactly eight fields (spec §25.2.1; see
`node/src/stigmem_node/cid.py`): `confidence`, `entity`, `interpret_as`,
`relation`, `scope`, `source`, `value_type`, `value_v`. Mutation of any of
these by an attacker breaks the CID.

**R-23 / ADR-003 closed (CID v2, 2026-06-06): `interpret_as` is covered by the
CID.** The critical attack this ADR cites — flipping `interpret_as` from
`content` to `instruction` — changes the CID and is detected as a mismatch on
the read path and on federation ingest. (`timestamp` remains excluded so the
same assertion shares one CID across times.) CID v2 is a breaking,
version-gated change; pre-v2 facts are upgraded by the backfill (see the
amendment below).

### Layer 4 (L4) · Local hash chain

A `fact_chain` table records a hash chain over fact insert events:

```
chain_index | fact_cid              | prev_chain_hash | this_chain_hash
0           | <CID of first fact>   | (genesis)       | h(genesis || cid_0)
1           | <CID of second fact>  | h(genesis|cid_0)| h(prev || cid_1)
...
```

Each new fact append produces a new chain entry. Sequence tampering
(removal, reordering, insertion at an arbitrary point) breaks the
chain at the tampered index.

Per-read overhead: optional verification — clients can request the
chain proof for a returned fact and verify locally. Not all reads
require verification; cross-org / federated reads should verify by
default.

L4 is included in v1.0 because it pairs with L5 cleanly (the chain
checkpoints are what get committed to the external witness).

### Layer 5 (L5) · Sigstore Rekor anchor

The crucial layer for R-23. Stigmem commits chain checkpoints (every
Nth fact, or at minimum every minute under sustained writes) to
Sigstore Rekor or an equivalent transparency log.

<div className="stigmem-grid">

<div><h4>Independently operated</h4><p>Rekor's append-only log is operated independently. The stigmem node operator does not control it.</p></div>
<div><h4>Witnessed externally</h4><p>The Rekor log is itself transparency-logged and witnessed by external parties (Sigstore's network of monitors).</p></div>
<div><h4>Divergence detectable</h4><p>If an attacker mutates facts and rewrites the local chain, post-attack chain checkpoints will not match the Rekor entries committed before the attack. Anyone comparing local state to Rekor sees the divergence immediately.</p></div>

</div>

The attacker cannot modify or remove Rekor entries previously
committed, nor backdate new ones. The attacker can continue serving
consistent local lies until someone checks against Rekor —
**mitigated by mandatory verification on cross-org / federated
reads.**

### Client / peer verification (operationalizing L5)

Recall responses include, in addition to the fact body, the fact's
CID, the chain proof (chain_index, prev_chain_hash, this_chain_hash),
and the Rekor inclusion proof for the most recent checkpoint covering
this fact's chain index.

<ol className="stigmem-steps">
<li>Recompute CID from fact body; check it matches.</li>
<li>Recompute chain hash for the fact's chain entry; check it links correctly.</li>
<li>Verify Rekor inclusion proof against Rekor's known root.</li>
</ol>

Federation peers do this verification automatically on inbound
replication. Clients can opt in via a `Stigmem-Verify: full` header
(per ADR-008 §Version exposure's `Stigmem-Version` model).

<div className="stigmem-keypoint">

**Without client/peer verification, L5 provides no defense in practice.**

This is the most-overlooked part of transparency-log architectures:
the witness is only useful if someone checks it.

</div>

### Optional · hardware enforcement (deployment-specific)

For adopters with regulatory requirements (HIPAA, SOX, FedRAMP,
regulated finance), additional hardware-level options are documented
but not required:

<div className="stigmem-grid">

<div><h4>WORM storage</h4><p>S3 Object Lock, write-once disks. Hardware-level append-only enforcement. Even root cannot overwrite.</p></div>
<div><h4>TEE / enclave</h4><p>SGX, AMD SEV, ARM TrustZone. Code runs in a protected boundary the host OS cannot reach.</p></div>
<div><h4>HSM-backed signing</h4><p>For chain checkpoints. Keys cannot be extracted even by privileged users. Strengthens L4.</p></div>

</div>

Stigmem core ships compatibly with them but does not require them.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Local enforcement only (L1 + L2; skip L3, L4, L5)</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Defends against application bugs and non-admin threats but provides no defense against R-23.</dd>
</div>

<div>
<dt>Cryptographic per-record only (L3; skip chain + witness)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>CIDs catch content tampering but not removal or whole-table rewrites. An attacker with admin recomputes CIDs locally; the local view is consistent.</dd>
</div>

<div>
<dt>Local chain only (L4; skip external witness)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>A local hash chain is rewritable by an attacker with admin privileges. Without an external party who saw earlier checkpoints, the rewrite is undetectable.</dd>
</div>

<div>
<dt>Defer immutability to v2.0; document gap in LIMITATIONS.md</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>ADR-003's defenses already accepted with the assumption storage is immutable. Deferring means ADR-003's claims are aspirational, not architecturally enforced — a mismatch between claimed and enforced guarantees that the immutability stack exists to close.</dd>
</div>

<div>
<dt>Different external transparency log (not Sigstore Rekor)</dt>
<dt><span className="stigmem-fields__type">considered</span></dt>
<dd>Rekor is the most mature option, has external witnesses, has a Python SDK, and has growing adoption. Architecture is generic enough to swap if needed.</dd>
</div>

<div>
<dt>Use a blockchain instead of a transparency log</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Blockchain consensus is overkill. Stigmem doesn't need decentralized writes, just tamper-evident audit. Operating costs far exceed Rekor for the same security property.</dd>
</div>

<div>
<dt>Require WORM storage as the default</dt>
<dt><span className="stigmem-fields__type">rejected for v1.0</span></dt>
<dd>Adds adopter friction (special hardware or cloud configuration) without addressing the threat model proportionally — Rekor-anchored chain provides similar tamper-detection without specific storage hardware.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Immutability claim is enforceable</h4><p>L1+L2 catches bugs and accidents; L3 catches content tampering; L4+L5 catch admin-level tampering.</p></div>
<div><h4>R-23 mitigation is structural</h4><p>Operators don't need to trust admin discipline; the architecture itself constrains what an admin-level attacker can silently do.</p></div>
<div><h4>ADR-003 holds against storage compromise</h4><p>The <code>interpret_as</code> field is part of the CID; mutating it breaks integrity. The L2 federation rule is now backstopped by L3 storage tamper-detection.</p></div>
<div><h4>Federation peers verify independently</h4><p>No need to trust a peer's claim about a fact's content; CIDs + chain proofs let any peer verify against Rekor.</p></div>
<div><h4>Audit log integrity inherits the pattern</h4><p>R-09 gets the same treatment. This ADR establishes the pattern for facts and audit logs alike.</p></div>
<div><h4>Compliance posture improves</h4><p>Tamper-evident audit with external attestation is the standard for HIPAA, SOX, FedRAMP, and regulated finance.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Phase B timeline grows ~6–9 weeks</h4><p>L1 ~1–2w, L2 ~3d, L3 ~1w, L4 ~2w, L5 ~2–3w (Rekor), verification ~1w.</p></div>
<div><h4>Application refactor is real</h4><p>Seven existing mutation paths redesigned around projection tables. ~10 files touched, comprehensive test coverage for behavioral parity.</p></div>
<div><h4>Read-path overhead</h4><p>Every read with verification costs CID recompute + chain hash + Rekor inclusion proof. Acceptable for federated cross-org; optional for trusted-local.</p></div>
<div><h4>Operator complexity</h4><p>Rekor key management, witness availability, retention policy, monitoring of <code>fact_mutation_attempted</code>. Documented in <code>docs/Operate/Hardening</code>.</p></div>
<div><h4>Storage growth</h4><p>Chain table grows monotonically; Rekor entries cost (Sigstore is free for OSS, rate-limited at volume).</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-IMM-1</code> · Rekor unavailable at write time</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Writes proceed locally; checkpoints commit asynchronously with retry; operators alerted on sustained unavailability. The fact is still locally chained; it's the external witness that's delayed.</dd>
</div>

<div>
<dt><code>R-IMM-2</code> · client doesn't verify</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A naive client that doesn't check CIDs / chains / Rekor proofs gets no security benefit from L3–L5. Mitigation: verification is on-by-default in official SDKs; <code>Stigmem-Verify: full</code> is documented best practice.</dd>
</div>

<div>
<dt><code>R-IMM-3</code> · Rekor compromise</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>If Sigstore's Rekor is compromised, L5's guarantee weakens. Mitigation: Rekor is itself transparency-logged and witnessed by external monitors; a Rekor compromise is detectable. Stigmem can also support multiple-witness submissions.</dd>
</div>

<div>
<dt><code>R-IMM-4</code> · chain rebuild on legitimate operations</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Storage backend migration or restoration from backup needs to rebuild the chain. Mitigation: backup-and-restore is an explicit operator runbook; chain rebuild requires re-anchoring to Rekor with explicit operator action.</dd>
</div>

<div>
<dt><code>R-IMM-5</code> · projection table drift</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Projection tables can be mutated by application bugs. Mitigation: projection tables are not the immutable source of truth; their drift is recoverable by replaying writes from the journal.</dd>
</div>

<div>
<dt><code>R-IMM-6</code> · WORM storage adoption gap</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>Adopters in regulated workloads that <em>should</em> use WORM may not. Mitigation: operator hardening guide explicitly recommends WORM for regulated workloads; checked at operator soak.</dd>
</div>

</div>

## Implementation plan

The immutability stack lands in Phase B. Sequenced to minimize parallel
risk.

<ol className="stigmem-steps">
<li><strong>B.1 · ADR-011 amendment to ADR-011 (move CIDs to core).</strong> ~1 day. Lands first because it changes the plugin scope of CIDs.</li>
<li><strong>B.2 · L1 architectural refactor.</strong> ~1–2 weeks. Adds projection tables; refactors all seven mutation paths. CI gate: existing tests pass; new property test verifies <code>facts</code> table only ever sees INSERT.</li>
<li><strong>B.3 · L2 SQLite triggers.</strong> ~3 days. New migration. CI gate: triggers exercised by negative tests.</li>
<li><strong>B.4 · L3 CID enforcement.</strong> ~1 week. Per spec §25 design. Verification at read time. CI gate: tamper test mutates a fact's <code>value_v</code> directly via SQL; recall returns integrity error.</li>
<li><strong>B.5 · L4 hash chain.</strong> ~2 weeks. New <code>fact_chain</code> table; chain computation on every insert; chain proof in recall responses. CI gate: chain-rewrite test detects manual rewrite.</li>
<li><strong>B.6 · L5 Rekor integration.</strong> ~2–3 weeks. Rekor SDK in node, checkpoint commit (every Nth fact or every 60 seconds), inclusion proof in recall responses, verification helper in SDK, operator runbook for Rekor unavailability.</li>
<li><strong>B.7 · Client / peer verification.</strong> ~1 week. Verification helpers in Python SDK, federation inbound automatic verification, <code>Stigmem-Verify</code> header support per ADR-008 §Version exposure.</li>
<li><strong>B.8 · Operator hardening doc.</strong> ~3–5 days. <code>docs/Operate/Hardening</code> and <code>docs/Secure/Immutability-and-attestation</code> per ADR-020 §12 (docs IA) IA.</li>
</ol>

**Total Phase B addition:** ~6–9 weeks.

### Cross-references

<div className="stigmem-grid">

<div><h4>ADR-003</h4><p>Storage immutability is named as a precondition; ADR-016 satisfies it. No ADR-003 amendment needed.</p></div>
<div><h4>ADR-011 via ADR-011</h4><p>CIDs to core. Does not invalidate ADR-011's plugin architecture for the other six features.</p></div>
<div><h4>ADR-020 §10 (compatibility matrix)</h4><p>Compatibility matrix gains a feature row for "storage immutability" with required versions.</p></div>
<div><h4>Threat model</h4><p>R-23 added in <code>stigmem/security/threat-model-new-entries.md</code>.</p></div>

</div>

## Open questions

<div className="stigmem-fields">

<div>
<dt>Question</dt>
<dt><span className="stigmem-fields__type">Recommendation</span></dt>
<dd>Reasoning</dd>
</div>

<div>
<dt>Right Rekor checkpoint cadence?</dt>
<dt><span className="stigmem-fields__type">every 1000 facts OR every 60s</span></dt>
<dd>Whichever first. Reconsider with real-world write-load data from operator soak.</dd>
</div>

<div>
<dt>Should non-federation single-tenant deployments require Rekor?</dt>
<dt><span className="stigmem-fields__type">yes by default, override available</span></dt>
<dd><code>STIGMEM_REKOR_REQUIRED=false</code> disables L5 (with loud warning). Single-tenant deployments without external threat model can choose to skip.</dd>
</div>

<div>
<dt>Witness diversity for very-high-assurance deployments?</dt>
<dt><span className="stigmem-fields__type">defer to v1.x</span></dt>
<dd>Multiple-witness commit (Rekor + an additional transparency log) — opt-in feature.</dd>
</div>

</div>

## Amendment process

Changes to this ADR require sign-off per ADR-001 §Contributor approval
rule. Common amendment cases: changing the layer composition (e.g.,
dropping a layer); changing the witness service away from Rekor;
changing default verification posture (verify-by-default vs. opt-in);
adding hardware enforcement requirements at the protocol level.

## Amendments

- **2026-06-06 — tamper-evidence verification correction.** A read-only audit
  of the L1–L5 stack found this ADR overstated CID field coverage: the
  implemented CID (`cid.py`, spec §25.2.1) covers seven fields
  (`confidence`, `entity`, `relation`, `scope`, `source`, `value_type`,
  `value_v`) and does **not** cover `interpret_as` or `timestamp`. The L3
  section above is corrected accordingly. The same audit confirmed L4 (hash
  chain) and L5 (checkpoints) are **unsigned** and the default external anchor
  is a local file, so the stack is tamper-evident against application-level and
  non-privileged tampering but not against an attacker with DB write access in
  the default configuration. Closing that gap (out-of-band signing,
  default/enforced external anchor, SDK verify-by-default, and `interpret_as`
  CID coverage) is tracked in the tamper-evidence hardening plan.

- **2026-06-06 — CID v2: `interpret_as` now covered (R-23 closed).** The CID
  canonical body was extended from seven to eight fields to include
  `interpret_as` (`cid.py`, spec §25.2.1). Flipping a fact's interpretation
  between `content` and `instruction` now changes its CID and is caught on the
  read path and on federation ingest — closing the gap noted in the amendment
  above. This is a breaking, version-gated wire-format change (pre-v2 facts are
  rejected on read until upgraded); the `backfill-cids` admin command repoints
  each fact's CID alias to its v2 CID. `timestamp`/`valid_until` remain excluded
  by design. The remaining tamper-evidence items (out-of-band signing, enforced
  external anchor, SDK verify-by-default) stay tracked for Wave 3.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
