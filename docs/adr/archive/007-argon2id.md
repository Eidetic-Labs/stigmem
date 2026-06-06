# ADR-007: Argon2id migration for API key hashing

> **Archived.** Settled one-time migration (de-contrition consolidation, 2026-06-06). The durable fact (API keys are Argon2id-hashed, OWASP params) lives in the security feature record.

<p className="stigmem-meta"><span>4 min read</span><span>Archived</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Migrate API key storage from SHA-256 to Argon2id with OWASP-recommended
parameters. Use dual-mode verification during v0.9.x so existing keys
continue to work; opportunistically re-hash on first use; force a
bulk re-hash at v1.0.0 stable.

</div>

<div className="stigmem-keypoint">

**Status: Archived.**

Closes the discrepancy where v1.0 documentation said "Argon2id-hashed
at rest" while the implementation used SHA-256.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** threat model §4 Assumption #2, T1-S1, R-03; `stigmem-security-revisions.md` P0-4

## Context

The v1.0 release documented API key storage as "Argon2id-hashed at
rest." The implementation used SHA-256 (`hashlib.sha256` in
`auth.py`). The discrepancy was identified during the Rev 2.0
threat-model update.

The Rev 2.0 threat model resolved the discrepancy by updating the
documentation to match the code — keeping SHA-256 with the rationale
that UUID4-derived keys carry sufficient entropy to make offline
brute-force infeasible regardless of hash speed.

On further review, this argument has three weaknesses:

<div className="stigmem-grid">

<div>
<h4>UUID4 is 122 bits, not 128</h4>
<p>Six bits are reserved for version and variant fields. Minor in absolute terms; the documentation should be precise, and an argument that depends on entropy counts deserves correctness in those counts.</p>
</div>

<div>
<h4>Depends on a permanent invariant</h4>
<p>The moment a future change introduces test keys, custom-format keys, manually-issued keys, or backwards-compat shims with weaker entropy, SHA-256 silently provides no protection. The threat model has to be re-litigated on every key-format change. Argon2id remains correct under all such changes.</p>
</div>

<div>
<h4>Defense-in-depth</h4>
<p>When a database breach exposes 1,000 hashed keys, an attacker can attempt cracking adjacent keys at near-zero marginal cost with SHA-256. Argon2id makes that cost real (~250ms per attempt on 2GB memory). Difference between "all keys compromised" and "attacker can crack maybe the 5 weakest before we rotate."</p>
</div>

</div>

<div className="stigmem-keypoint">

**OWASP-recommended, mature library support, minimal operational cost.**

Argon2id won the
[Password Hashing Competition](https://www.password-hashing.net/),
is the [OWASP-recommended](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
function, and has mature Python support via <code>argon2-cffi</code>.
Switching avoids the structural dependency on key-format invariants.

</div>

## Decision

We migrate API key storage from SHA-256 to Argon2id with dual-mode
verification during the transition window.

### Hash parameters

We adopt the
[OWASP recommended baseline](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id):

<div className="stigmem-fields">

<div>
<dt>Parameter</dt>
<dt><span className="stigmem-fields__type">Value</span></dt>
<dd>Notes</dd>
</div>

<div>
<dt>Algorithm</dt>
<dt><span className="stigmem-fields__type">Argon2id</span></dt>
<dd>Variant resistant to both side-channel and time-memory tradeoff attacks.</dd>
</div>

<div>
<dt>Memory cost</dt>
<dt><span className="stigmem-fields__type">19 MiB</span></dt>
<dd><code>m_cost=19456</code>.</dd>
</div>

<div>
<dt>Time cost</dt>
<dt><span className="stigmem-fields__type">2 iterations</span></dt>
<dd><code>t_cost=2</code>.</dd>
</div>

<div>
<dt>Parallelism</dt>
<dt><span className="stigmem-fields__type">1 lane</span></dt>
<dd><code>parallelism=1</code>.</dd>
</div>

<div>
<dt>Salt</dt>
<dt><span className="stigmem-fields__type">16 random bytes</span></dt>
<dd>Per key, stored alongside the hash.</dd>
</div>

<div>
<dt>Hash output</dt>
<dt><span className="stigmem-fields__type">32 bytes</span></dt>
<dd>Tuned to ~50ms per verification on a typical server CPU.</dd>
</div>

</div>

### Storage format

Hashes are stored in the canonical Argon2 encoded format:

```text
$argon2id$v=19$m=19456,t=2,p=1$<base64 salt>$<base64 hash>
```

The format encodes the algorithm and parameters, allowing future
parameter upgrades without a separate version field.

### Migration: dual-mode verification

For the duration of v0.9.x, the auth module supports verifying keys
against either hash format:

```python
def verify_api_key(presented_key: str, stored_hash: str) -> bool:
 if stored_hash.startswith("$argon2id$"):
 return argon2.verify(presented_key, stored_hash)
 elif looks_like_sha256(stored_hash):
 # Legacy: verify against SHA-256, then opportunistically re-hash with Argon2id
 if hmac.compare_digest(sha256(presented_key), stored_hash):
 background_rehash(presented_key) # Re-hash and update the row
 return True
 return False
 else:
 raise InvalidHashFormat()
```

<div className="stigmem-keypoint">

**Opportunistic re-hashing.**

Existing keys verify against SHA-256 on first use, then are
opportunistically re-hashed with Argon2id and the database row is
updated. Keys not used during the v0.9.x window remain in SHA-256;
v1.0.0 stable adds a one-time bulk re-hash migration that processes
remaining SHA-256 hashes by issuing forced rotations.

</div>

### New key issuance

From v0.9.x onward, all newly issued keys are hashed with Argon2id.
The existing UUID4-based key generation (122-bit entropy) is preserved
— Argon2id strengthens the storage; the high-entropy generation
remains the primary defense.

### Verification of the migration

A new audit event `api_key_rehashed` fires every time a legacy
SHA-256 key is opportunistically re-hashed. Operators can query
migration progress:

```sql
SELECT COUNT(*) FROM audit_events WHERE event_type = 'api_key_rehashed'
```

When this count equals the number of SHA-256 hashes remaining, the
migration is complete for that key.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Stay on SHA-256; document the random-token-only invariant</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Considered (option B in security-revisions P0-4). For uniformly random UUID4 tokens, SHA-256 can be defensible. Rejected because the defense depends on a permanent key-generation invariant that future integrations can accidentally weaken.</dd>
</div>

<div>
<dt>Use bcrypt or scrypt instead</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Argon2id won the Password Hashing Competition explicitly because it improves on bcrypt and scrypt's tradeoffs.</dd>
</div>

<div>
<dt>HMAC-SHA256 with a node-side secret</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>HMAC defeats offline brute-force when the secret stays secret, but the secret lives on the same disk as the database. Adds operational complexity without meaningfully changing the threat model.</dd>
</div>

<div>
<dt>Forced rotation of all keys on v0.9.x release</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Forces every operator to re-issue every API key on upgrade, breaking integrations. Dual-mode with opportunistic re-hashing is operationally smoother.</dd>
</div>

<div>
<dt>Higher Argon2id parameters</dt>
<dt><span className="stigmem-fields__type">considered</span></dt>
<dd>Increases attacker cost but also verification latency on every authenticated request. Chosen parameters are OWASP-recommended; revisit upward if benchmarks show headroom.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Threat-model assumption matches code</h4><p>§4 Assumption #2 can be rewritten without the entropy-dependent argument.</p></div>
<div><h4>R-03 fully closes</h4><p>API key max-age is already enforced; now at-rest hashing matches industry standard. T1-S1's residual narrows to "key revocation must still be performed manually."</p></div>
<div><h4>Future key-format changes are safe</h4><p>Shorter test keys, custom-prefix keys, or any non-UUID4 format — storage layer remains correct.</p></div>
<div><h4>Clean answer for security review</h4><p>"Argon2id with OWASP-recommended parameters" is what security teams expect; "SHA-256 because UUID entropy" triggers follow-up questions.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Latency on first authenticated request</h4><p>Argon2id adds ~50ms vs SHA-256's microseconds. Right cost for the security gain.</p></div>
<div><h4>Dual-mode for one minor version</h4><p>Slightly more complex auth code during v0.9.x; simplifies at v1.0.0.</p></div>
<div><h4>Memory footprint per verification</h4><p>19 MiB per Argon2id verification. 100 concurrent authentications = ~1.9 GB transient. Mitigation: rate limits cap concurrent volume; parameters can be tuned downward with documented tradeoffs.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-A2ID-1</code> · parameter rot</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>OWASP recommendations evolve. Parameters are encoded in the hash format; re-hash on upgrade is the same code path as the SHA-256 → Argon2id migration. Review every 2 years.</dd>
</div>

<div>
<dt><code>R-A2ID-2</code> · <code>argon2-cffi</code> vulnerability</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A CVE would affect every authenticated request. Dependabot alerts; library is widely used and well-maintained.</dd>
</div>

<div>
<dt><code>R-A2ID-3</code> · opportunistic re-hash race</dt>
<dt><span className="stigmem-fields__type">mitigated</span></dt>
<dd>Two concurrent verifications of the same legacy key could both trigger re-hash. Re-hash uses a row-level lock; second attempt is a no-op.</dd>
</div>

</div>

## Implementation plan

Targeted for v0.9.x (alongside Phase B federation hardening).

<div className="stigmem-grid">

<div><h4>Add dependency</h4><p><code>argon2-cffi</code> to <code>pyproject.toml</code>.</p></div>
<div><h4>Update <code>auth.py</code></h4><p>Dual-mode verification per the spec above.</p></div>
<div><h4>Audit event</h4><p>Add <code>api_key_rehashed</code> type.</p></div>
<div><h4>Threat model</h4><p>Update §4 Assumption #2 (per security-revisions P0-4) and T1-S1 in STRIDE.</p></div>
<div><h4>OPERATING.md</h4><p>Migration story for operators upgrading from v1.0 (now superseded by v0.9.0-preview) and earlier v0.9.x.</p></div>
<div><h4>Benchmark tests</h4><p>Confirm verification latency stays under 100ms p99 with chosen parameters.</p></div>

</div>

For v1.0.0:

<div className="stigmem-grid">

<div><h4>Bulk re-hash migration</h4><p>Handle any remaining SHA-256 keys by forcing a rotation.</p></div>
<div><h4>Remove SHA-256 verification</h4><p>Path removed from <code>auth.py</code>.</p></div>

</div>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
