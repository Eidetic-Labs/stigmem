# ADR-002: v1 critical-path scope

<p className="stigmem-meta"><span>5 min read</span><span>Accepted</span><span>Recorded 2026-05-06</span></p>

<div className="stigmem-lead">

**What this ADR decides**

The exact list of features on the v1 critical path. Everything not on
the list is — by definition — not in v1.0 and moves to
`experimental/` until it can return through
[ADR-008](./008-experimental-gates)'s re-introduction gates.

</div>

<div className="stigmem-keypoint">

**Status: Accepted.**

Defines the v1.0 critical-path scope as an explicit, amendment-gated
contract.

</div>

**Date:** 2026-05-06 · **Authors:** Eidetic Labs · **Related:** [ADR-001](./001-versioning), `stigmem/plans/version-prioritization.md`, `stigmem/plans/strengthening-plan.md`

## Context

Stigmem's buildable surface is broad — an §1–§25 spec, multiple SDKs,
multiple deployment targets, and a curator dashboard. Breadth is not
the same as a defensible v1.0. The critical path is the focused subset
the project commits to harden, validate, and support as v1.0; the rest
lives in `experimental/` and returns individually through
[ADR-008](./008-experimental-gates)'s gates.

<div className="stigmem-keypoint">

**Trust through surface, not scope.**

A federated knowledge fabric earns trust by being rigorously correct
on a small surface. Every feature past the critical path is a
liability over time — code to maintain, security to audit, behavior
to reason about, operator deployments to support. The marginal cost of
writing code is low; the marginal cost of *correctness* across
existing surface is meaningful and grows with size.

</div>

The right tradeoff for v1.0 is a smaller surface that we can defend,
not a larger surface that we hope to validate later.

## Decision

The v1.0 critical-path scope is the following list. Anything not on
this list is, by definition, not in v1.0.

### Protocol & data model

<div className="stigmem-grid">

<div><h4>Typed facts</h4><p><code>(entity, relation, value)</code> triple with provenance, confidence, scope, HLC timestamp.</p></div>
<div><h4>Scopes</h4><p><code>local</code> · <code>team</code> · <code>company</code> · <code>public</code>, with strict server-side enforcement.</p></div>
<div><h4>Operations</h4><p><code>assert_fact</code> · <code>query_facts</code> · <code>recall</code>. Everything else is built from these.</p></div>
<div><h4>Provenance</h4><p>Every fact carries source, timestamp, confidence at write; immutable in v1.</p></div>

</div>

### Federation

<div className="stigmem-grid">

<div><h4>Two-node mTLS replication</h4><p>TLS 1.3 floor.</p></div>
<div><h4>Ed25519-signed manifests</h4><p>At <code>/.well-known/stigmem-manifest.json</code>.</p></div>
<div><h4>Rekor inclusion proofs</h4><p>For manifest rotation events.</p></div>
<div><h4>Capability tokens</h4><p>Short-lived (≤90d) · Ed25519-signed · verb+object validated at admission.</p></div>
<div><h4>Bounded HLC skew</h4><p>With per-peer drift tracking (R-19).</p></div>
<div><h4>Quarantine garden</h4><p>For federation inbound writes.</p></div>

</div>

### Authentication and authorization

<div className="stigmem-grid">

<div><h4>Argon2id-hashed API keys</h4><p>Per <a href="./007-argon2id">ADR-007</a> migration.</p></div>
<div><h4>API key max-age</h4><p>Enforced default 90 days.</p></div>
<div><h4>Per-principal token-bucket rate limits</h4></div>
<div><h4>Capability-based instruction handling</h4><p><code>interpret_as</code> per <a href="./003-prompt-injection">ADR-003</a>.</p></div>
<div><h4>Per-session read/write graph isolation</h4><p>R-21 mitigation.</p></div>

</div>

### Observability

<div className="stigmem-grid">

<div><h4>WAL-ordered audit log</h4><p>13 event types per §22.3 · 90-day retention.</p></div>
<div><h4>Prometheus metrics</h4><p>Node health · request rates · quota state · federation peer status.</p></div>

</div>

### Storage

<div className="stigmem-grid">

<div><h4>SQLite backend</h4></div>
<div><h4>SQLCipher at-rest encryption</h4><p>Opt-in, documented in OPERATING.md.</p></div>

</div>

### Embedding

<div className="stigmem-grid">

<div><h4>Local <code>nomic-embed-text-v1.5</code></h4><p>Default, offline.</p></div>

</div>

### Adapters

<div className="stigmem-grid">

<div><h4>OpenClaw adapter v0.9</h4><p>Hardened, with handoff allowlist · experimental flag until external operator soak.</p></div>
<div><h4>MCP adapter (minimal)</h4><p><code>assert_fact</code> · <code>query_facts</code> · <code>recall</code> · <code>lint_scope</code>.</p></div>

</div>

### Operations

<div className="stigmem-grid">

<div><h4>Docker Compose reference deployment</h4><p><code>make demo</code> · <code>make demo-attack</code>.</p></div>
<div><h4>Container hardening</h4><p>Distroless base · non-root UID · read-only filesystem · seccomp.</p></div>

</div>

### SDK

<div className="stigmem-grid">

<div><h4>Python SDK</h4><p><code>stigmem-py</code>.</p></div>

</div>

### Documentation

<div className="stigmem-grid">

<div><h4>Top-level files</h4><p>README · LIMITATIONS · SECURITY · OPERATING · THREATS · CHANGELOG · ROADMAP.</p></div>
<div><h4>Threat model &amp; scenarios</h4><p>On docs front page.</p></div>
<div><h4>ADRs</h4><p>ADR-001 through ADR-008.</p></div>
<div><h4>Friday public engineering log</h4></div>

</div>

### Release engineering

<div className="stigmem-grid">

<div><h4>Sigstore-signed releases</h4><p>Phase C · required before v1.0.0 GA per R-22.</p></div>
<div><h4>Reproducible builds &amp; SBOM</h4><p>Phase C.</p></div>
<div><h4>Version-consistency CI check</h4><p>Per <a href="./001-versioning">ADR-001</a>.</p></div>

</div>

### What is NOT in v1.0

Everything else. The complete deferred list is maintained in
`stigmem/plans/version-prioritization.md`. Notably:

<div className="stigmem-grid">

<div><h4>Spec sections</h4><p>§21 lazy instruction discovery · §23 RTBF tombstones · §24 time-travel queries · §25 CIDs · §17 memory garden · §18 source attestation · subscriptions.</p></div>
<div><h4>Auth &amp; tenancy</h4><p>OIDC integration · multi-tenant isolation · fuzzy resolver.</p></div>
<div><h4>Storage backends</h4><p>PostgreSQL · libSQL/Turso.</p></div>
<div><h4>Cloud embedding</h4></div>
<div><h4>Adapters</h4><p>Obsidian · Letta · Zep · Cognee · Gemini · OpenAI-tools · Paperclip.</p></div>
<div><h4>UI</h4><p>Curator dashboard.</p></div>
<div><h4>Deploy targets</h4><p>Helm · Fly · systemd · Grafana dashboards.</p></div>
<div><h4>SDKs</h4><p>Go SDK · TypeScript SDK.</p></div>
<div><h4>Billing hooks</h4></div>

</div>

These items remain in the codebase under `experimental/` and will
return individually under [ADR-008](./008-experimental-gates)'s
re-introduction gates.

## Alternatives considered

<div className="stigmem-fields">

<div>
<dt>Alternative</dt>
<dt><span className="stigmem-fields__type">Disposition</span></dt>
<dd>Why rejected</dd>
</div>

<div>
<dt>Keep everything; harden incrementally</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>Harden-everything-incrementally was attempted in the lead-up to v1.0 and produced more surface than could be independently validated. The cut isn't optional; it's the precondition for hardening to converge.</dd>
</div>

<div>
<dt>Cut more aggressively (drop MCP adapter, drop SQLCipher)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>MCP is the <em>integration</em> contract for the category — without it, stigmem is an isolated database. SQLCipher is opt-in and adds no maintenance burden when off.</dd>
</div>

<div>
<dt>Cut less aggressively (keep §21 lazy instruction discovery; just label it experimental in v1.0)</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>§21 is the prompt-injection surface (R-15, R-21). Until ADR-003 lands and is operator-validated, instruction-typed facts that flow into agent context are a category-defining risk. Shipping §21 in v1.0 — even with a warning label — invites exactly the deployments that will hit the worst-case failure modes.</dd>
</div>

<div>
<dt>Defer the cut decision until after a beta period</dt>
<dt><span className="stigmem-fields__type">rejected</span></dt>
<dd>The question "what's in v1?" is upstream of every other planning question. Deferring it leaves the strengthening plan and the security docs uncalibrated.</dd>
</div>

</div>

## Consequences

### What gets easier

<div className="stigmem-grid">

<div><h4>Strengthening plan converges</h4><p>Every week's deliverables map to specific items on this list.</p></div>
<div><h4>Threat model calibrates cleanly</h4><p>The v1.0 risk register can drop §21/§23/§24/§25 risks (R-15–R-18) into an <code>experimental-risks.md</code> companion.</p></div>
<div><h4>Adopter confusion drops</h4><p>"Is X supported?" has a yes/no answer for every X.</p></div>
<div><h4>Operator surface fits in your head</h4><p>External operator soak (Phase B) becomes feasible because the surface fits in an operator's head.</p></div>
<div><h4>CI becomes meaningful</h4><p>Conformance vectors and adversarial vectors target a defined surface; coverage metrics mean something.</p></div>

</div>

### What gets harder

<div className="stigmem-grid">

<div><h4>Some users of v1.0 lose features</h4><p>Anyone who integrated against §23 tombstones or the libSQL backend must either pin to the yanked release or migrate to v0.9.0-preview.</p></div>
<div><h4>Saying no to features</h4><p>Internal and external pressure to add scope becomes recurring conversations. ADR-008 provides the structured answer.</p></div>
<div><h4><code>experimental/</code> maintenance</h4><p>Code that compiles but isn't on the critical path still needs not to bitrot. Mitigation: build-but-don't-test policy until the re-introduction process.</p></div>

</div>

### New risks

<div className="stigmem-fields">

<div>
<dt>Risk</dt>
<dt><span className="stigmem-fields__type">Status</span></dt>
<dd>Mitigation</dd>
</div>

<div>
<dt><code>R-SCOPE-1</code> · scope creep via "small additions"</dt>
<dt><span className="stigmem-fields__type">accepted</span></dt>
<dd>Each individual proposal sounds reasonable in isolation. The sum reproduces v1.0 surface area. Mitigation: any change to this list requires an ADR-002 amendment with sign-off (two contributors or the founder alone, per ADR-001 §Contributor approval rule).</dd>
</div>

<div>
<dt><code>R-SCOPE-2</code> · experimental features rotting</dt>
<dt><span className="stigmem-fields__type">accepted</span></dt>
<dd>Code that nobody touches develops bugs that emerge years later. Mitigation: experimental features stay buildable but are not part of the test matrix. Re-introduction (ADR-008) requires bringing them up to v1.x quality, including tests.</dd>
</div>

</div>

### Cross-references to security docs

The threat model and scenarios reflect this scope. Risks associated
with deferred §21–§25 features live with those features (per
[ADR-018](./018-security-documentation-colocation)); cross-cutting
risks (HLC, embedding, worm vector, supply chain) stay on the v1.0
register. The OpenClaw v0.9 adapter is a v1.0 deliverable; its audit
findings are in v1.0 scope.

## Amendment process

This ADR is the contract that defines v1.0. Changes to the list
require:

<ol className="stigmem-steps">
<li>A new ADR (<code>ADR-NNN</code>) titled "Amendment to ADR-002: [feature name]".</li>
<li>Two contributors' sign-off on the amendment.</li>
<li>A corresponding update to <code>stigmem/plans/version-prioritization.md</code>.</li>
<li>A corresponding update to the strengthening plan if the amendment affects timeline.</li>
</ol>

<div className="stigmem-keypoint">

**The amendment process is deliberately costly. It is a feature, not a bug.**

</div>

---

*Accepted by: @offbyonce (founder), 2026-05-07. Per ADR-001 §Contributor
approval rule (founder solo-approval; second contributor sign-off
welcome but not required).*
