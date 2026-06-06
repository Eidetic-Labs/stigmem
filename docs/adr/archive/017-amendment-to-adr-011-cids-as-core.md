# ADR-017: Amendment to ADR-011 — CIDs as core (not plugin)

> **Superseded by ADR-011.** Content folded into ADR-011 (de-contrition consolidation, 2026-06-06). Full text retained here for history.

<p className="stigmem-meta"><span>4 min read</span><span>Superseded by ADR-011</span><span>Recorded 2026-05-07</span></p>

<div className="stigmem-lead">

**What this ADR decides**

Content-addressed fact IDs (CIDs) move from plugin scope to core
scope. Default install computes CIDs on every fact write and verifies
on every fact read. The other six cross-cutting feature plugins
remain plugins per ADR-011's C1 architecture, which is otherwise
unchanged.

</div>

<div className="stigmem-keypoint">

**Default install must equal secure install.**

ADR-016's analysis showed CIDs are load-bearing for both ADR-003 and
the broader immutability story. Keeping CIDs as an opt-in plugin
means "default install" silently differs from "secure default install"
by a critical layer — exactly the credibility-leak pattern stigmem
should avoid post-retraction.

</div>

**Status:** Accepted · **Date:** 2026-05-07 · **Amends:** [ADR-011](./011-cross-cutting-extraction) (C1 plugin architecture for cross-cutting features) · **Related:** [ADR-003](./003-prompt-injection), [ADR-016](./016-storage-immutability-enforcement); threat model R-23

## Context

ADR-011 (Accepted 2026-05-07) established a C1 plugin architecture for
stigmem's cross-cutting features. Seven features were scoped as
plugins, including content-addressed fact IDs (CIDs, §25). Adopters
who wanted cryptographic content addressing would install
`stigmem-plugin-cids`.

Subsequent threat-modeling work revealed that this classification
undervalues CIDs' role in the security architecture.

<div className="stigmem-grid">

<div><h4>ADR-003 trust boundary depends on storage immutability</h4><p>The L2 federation rule (no receiver-side promotion of <code>interpret_as</code>) assumes the storage <code>interpret_as</code> value is trustworthy.</p></div>
<div><h4>ADR-016 commits CIDs as L3 of the defense-in-depth stack</h4><p>Without CIDs in core, L3 is opt-in and defense-in-depth has a hole.</p></div>
<div><h4>Federation peer integrity verification depends on CIDs</h4><p>Peers verify content integrity by recomputing CIDs from canonical bodies. If CIDs are opt-in, federation between deployments with mismatched plugin install has degraded security.</p></div>

</div>

The original ADR-011 decision treated CIDs as orthogonal to the
security architecture. ADR-016 showed CIDs are load-bearing.

## Decision

**Move CIDs from plugin scope to core scope.**

<ol className="stigmem-steps">
<li>CIDs are no longer one of the seven cross-cutting feature plugins per ADR-011.</li>
<li>CID generation, storage, and verification are part of stigmem core. Default install computes CIDs on every fact write and verifies CIDs on every fact read.</li>
<li>The other six cross-cutting feature plugins (lazy instruction discovery, time-travel, RTBF tombstones, memory garden advanced ACL, source attestation, multi-tenant) remain plugins per ADR-011's C1 architecture. ADR-011's plugin model is otherwise unchanged.</li>
</ol>

### What this changes in ADR-011's scope

<div className="stigmem-fields">

<div>
<dt>Feature</dt>
<dt><span className="stigmem-fields__type">Original / Amended</span></dt>
<dd>Status</dd>
</div>

<div>
<dt>Lazy instruction discovery</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

<div>
<dt><strong>CIDs (§25)</strong></dt>
<dt><span className="stigmem-fields__type"><strong>plugin → core</strong></span></dt>
<dd>This amendment.</dd>
</div>

<div>
<dt>Time-travel queries</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

<div>
<dt>RTBF tombstones</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

<div>
<dt>Memory-garden advanced ACL</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

<div>
<dt>Source attestation</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

<div>
<dt>Multi-tenant</dt>
<dt><span className="stigmem-fields__type">plugin / plugin</span></dt>
<dd>Unchanged.</dd>
</div>

</div>

### What this changes in Phase A scope

<div className="stigmem-grid">

<div><h4>PR 4b rewrite</h4><p>Originally <code>stigmem-plugin-cids</code> implementation. Becomes "implement CIDs as core feature" — same engineering work, different package boundary.</p></div>
<div><h4>No plugin package</h4><p>The <code>stigmem-plugin-cids</code> package is not created.</p></div>
<div><h4>Hooks move to core</h4><p>CID-related hooks (<code>pre_assert_transform</code> for generation, <code>federation_inbound_validate</code> for verification) move from plugin-registered to core-resident.</p></div>
<div><h4>Hook surface intact</h4><p>ADR-011's hook surface remains valid — core-resident handlers register them, not a plugin manifest.</p></div>

</div>

### What this changes in default install behavior

<div className="stigmem-fields">

<div>
<dt>State</dt>
<dt><span className="stigmem-fields__type">Before / After</span></dt>
<dd>Behavior</dd>
</div>

<div>
<dt>Before amendment</dt>
<dt><span className="stigmem-fields__type">plugin-gated</span></dt>
<dd>Facts have no CID. <code>cid</code> field is null on stored rows. No content-addressed federation. Tamper detection requires installing the plugin.</dd>
</div>

<div>
<dt>After amendment</dt>
<dt><span className="stigmem-fields__type">core</span></dt>
<dd>Every fact has a CID computed at write time. CID is a not-null required column. Content-addressed federation works out of the box. Tamper detection is on by default.</dd>
</div>

</div>

Operators cannot disable CIDs. There is no `STIGMEM_CIDS_ENABLED=false`.
The CID is part of the fact identity.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why</dd>
</div>

<div>
<dt>Keep CIDs as plugin but require it for federation deployments</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>ADR-016's L3 applies regardless of federation. "Default install minus plugin" being silently weaker than the spec is exactly the credibility-leak pattern stigmem should avoid.</dd>
</div>

<div>
<dt>Define "secure-by-default" install variant + "lean install" variant</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Two install variants doubles the documentation, conformance testing, and adopter confusion. The lean variant has the worst marketing position imaginable: "this version of stigmem is less secure but smaller."</dd>
</div>

<div>
<dt>Leave ADR-011 as-is; document the caveat in operator docs</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Documentation cannot fix an architectural decision that puts the security floor below the spec's claims. Operators reading "facts are immutable" should not also need to read "...but only if you installed the plugin."</dd>
</div>

<div>
<dt>Wait until ADR-016 is accepted before amending ADR-011</dt>
<dt><span className="stigmem-fields__type">considered</span></dt>
<dd>Decided to draft them concurrently and accept them together. The substance of this amendment is independent of ADR-016's full implementation; CIDs being core matters whether or not the rest of ADR-016 lands.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>ADR-003's claims hold by default</h4><p>No "secure-only-if-plugin-installed" caveat.</p></div>
<div><h4>ADR-016's L3 is universal</h4><p>Defense-in-depth is genuinely defense-in-depth, not optional.</p></div>
<div><h4>Federation peer verification unconditional</h4><p>Peers can always verify content integrity; no need to check whether the peer has the plugin.</p></div>
<div><h4>Operator mental model simplifies</h4><p>The default install is the secure install.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>One fewer plugin to demonstrate C1</h4><p>The pattern is still validated on the remaining six features. CIDs were second-priority after lazy instruction discovery; now second priority becomes time-travel.</p></div>
<div><h4>Default install size grows slightly</h4><p>CID computation, the <code>cid_aliases</code> table, the migration. Marginal.</p></div>
<div><h4>CID computation on every write</h4><p>~10–50μs per write for SHA-256 over the canonical body. Acceptable.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-AMD11-1</code> · ADR-011's architectural commitment weakened</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>A reader of ADR-011 sees seven plugins; a reader of ADR-017 sees six. Cross-references must be tracked. Mitigation: ADR-011 stays untouched (immutability rule); ADR-017 is the canonical statement of six-plugin scope; future readers follow the chain via <code>Amends:</code> reference.</dd>
</div>

<div>
<dt><code>R-AMD11-2</code> · precedent for amending early-Accepted ADRs</dt>
<dt><span className="stigmem-fields__type">tracked</span></dt>
<dd>This is the first amendment to an Accepted ADR. Sets precedent: when a downstream ADR reveals a flaw in an upstream decision, amendment is the right move. Mitigation: amendments are infrequent and require the same sign-off as new ADRs.</dd>
</div>

</div>

## Implementation plan

ADR-017 is a scope change, not a re-engineering effort. The actual CID
work was already planned for Phase A PR 4b. This amendment changes
only:

<div className="stigmem-fields">

<div>
<dt>Aspect</dt>
<dt><span className="stigmem-fields__type">Change</span></dt>
<dd>Detail</dd>
</div>

<div>
<dt>Package boundary</dt>
<dt><span className="stigmem-fields__type">core</span></dt>
<dd>CID code lives in <code>node/src/stigmem_node/cid.py</code> (core), not in <code>experimental/cids/src/</code>.</dd>
</div>

<div>
<dt>Manifest</dt>
<dt><span className="stigmem-fields__type">none</span></dt>
<dd>No <code>stigmem-plugin-cids</code> package created.</dd>
</div>

<div>
<dt>Hook registration</dt>
<dt><span className="stigmem-fields__type">core-resident</span></dt>
<dd><code>pre_assert_transform</code> and <code>federation_inbound_validate</code> for CIDs register with the hook registry as part of node startup, not via plugin discovery.</dd>
</div>

<div>
<dt>Tests</dt>
<dt><span className="stigmem-fields__type">core</span></dt>
<dd>CID tests live in <code>node/tests/test_cids.py</code>, not in plugin tests.</dd>
</div>

<div>
<dt>Documentation</dt>
<dt><span className="stigmem-fields__type">core docs</span></dt>
<dd><code>docs/Build/Concepts/Content-addressing</code> and <code>docs/Secure/Immutability-and-attestation</code> per ADR-005 IA, not <code>docs/Build/Plugins</code>.</dd>
</div>

</div>

### Cascade through master-checklist

<div className="stigmem-grid">

<div><h4>§4.5b PR 4b</h4><p>Rewrite from "implement <code>stigmem-plugin-cids</code>" to "implement CIDs as core feature."</p></div>
<div><h4>§4.5g multi-tenant</h4><p>Unchanged (still a plugin).</p></div>
<div><h4>Issue seed #49</h4><p>Body updated to reflect CIDs as core.</p></div>
<div><h4>ADR-011's path mapping in §3.1</h4><p>Unchanged (the file mapping is by ADR number, not feature).</p></div>

</div>

### Cascade through ADR-011

ADR-011 is Accepted (immutable). It is **not** edited. This amendment
is the canonical record of the scope change. Future readers of
ADR-011 should be directed to ADR-017 via the ADR README index
annotations and via the `Amends:` chain.

## Amendment process

This ADR may itself be amended per ADR-001 §Contributor approval rule
(two contributors or the founder alone). Amendments to ADR-017 would,
in turn, propagate back to ADR-011's effective scope.

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
