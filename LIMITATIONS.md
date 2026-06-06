# LIMITATIONS

> **Stigmem v0.9.0a10.** Scoped for single-organization, single-node deployment. Cross-organizational federation is on the roadmap, not yet production-ready. Read this before deploying.
>
> Last updated: 2026-05-26 · Applies to: v0.9.0a10

---

## What this document is

A plain-English statement of what stigmem cannot safely do in its current state, organized by deployment scenario. It is the operator's companion to the formal [threat model](spec/security/threat-model.md) and the disclosure policy in [SECURITY.md](SECURITY.md).

If the threat model tells you *what the threats are*, this document tells you *what to actually do or not do today*. It is updated on every release. The contents below apply to **v0.9.0a10** specifically; future versions will close some of these gaps and may open new ones (each new feature lands with its own limitations entry).

If after reading this you're unsure whether your use case is safe, ask in [Discussions](https://github.com/eidetic-labs/stigmem/discussions) before deploying.

---

## Current state in one sentence

Stigmem v0.9.0a10 is a working federated-memory reference node with a documented threat model. Several controls the threat model identifies as required for cross-organizational deployment have not yet shipped; they are on the roadmap (see [ROADMAP.md](ROADMAP.md)). Until they ship, the deployment recommendations below are the responsible defaults.

---

## What stigmem is **not** safe for today

These are unambiguous "do not" recommendations as of v0.9.0a10.

### 1. Cross-organizational federation in adversarial settings

**Status:** mTLS for federation peering is not on by default. Capability-token validation at admission is partial. HLC bounded-skew enforcement is not yet shipped. Per-peer drift tracking does not exist.

**What this means:** if you peer with a stigmem node operated by an organization you do not already fully trust, a malicious peer can:

- Impersonate a legitimate peer (no client-cert verification by default).
- Push HLC values forward to corrupt fact ordering across the federation.
- Replay capability tokens within a window we have not yet fuzz-tested adequately.
- Write instruction-shaped facts that flow into your agents' context without a structural quarantine boundary.

**What to do today:** do not federate across organizational boundaries until the future hardened-core controls ship and complete operator validation. Single-organization federation between nodes you operate yourself is safer, but still subject to the limitations below.

---

### 2. LLM agents holding admin-scope API keys

**Status:** No structural prevention. The adapter contract treats this as an "operator configuration" concern.

**What this means:** if an LLM-driven agent is configured with an admin-scope API key (for example, by mounting it into an MCP adapter), a successful prompt injection on that agent grants the attacker full administrative control of your stigmem node — manifest publishing, key rotation, quarantine override, all of it.

**What to do today:** never issue admin-scope keys to anything an LLM can drive. Admin keys are for human operators and automation under human supervision only. Agent keys should be scoped to the minimum necessary (typically `local` or `team`, write access only to the relations the agent specifically needs). We are working on a structural fix that refuses such configurations at the API layer as future hardened-core work.

---

### 3. Treating recalled facts as instructions to your agent

**Status:** Improved on `main`, but not yet release-certified or operator-soak validated. The old recall-time sanitizer remains defense-in-depth only. The ADR-003 structural design has landed for the core protocol surfaces: facts now carry `interpret_as`, instruction-typed writes require `instruction:write`, cross-org instruction-typed inbound facts are quarantined, `recall()` returns separate `content` and `instructions` channels, and MCP/OpenClaw consume the channel-separated response. ADR-015 `corpus-v1` now contains 80 validated prompt-injection patterns, and the certification runner supports deterministic offline runs plus OpenAI, Anthropic, and local Ollama provider adapters; reviewed public model results are still pending.

**What this means:** the protocol can now distinguish content from authorized instructions, but downstream safety still depends on adapter compliance, session propagation, and the consuming LLM honoring the system-prompt directive. Until the certification runner, public model results, and operator soak complete, this remains a hardening-in-progress surface rather than a production recommendation for adversarial cross-org workloads.

**What to do today:** treat recalled fact `value` fields as untrusted external data, the same way you would treat a user-uploaded document. Specifically:

- Do not concatenate fact values directly into a system prompt without a clear, structurally-delimited "untrusted data" framing.
- Do not allow agents to act on instructions found in fact values without a separate authorization step that does not depend on the fact's content.
- If you build adapters that consume `recall()` output, preserve the `content` / `instructions` separation and include the ADR-003 system-prompt directive. Treat uncertified models as an accepted operator risk.

The capability-based redesign is present on `main`; release posture, certification evidence, and operator validation remain future hardened-core gates.

---

### 4. The agent feedback loop (read-injected → write-poisoned → replicate)

**Status:** In review on `main`. Same-session read/write graph tracking rejects writes back into scopes a session has read unless the write carries explicit source-fact provenance, and `summarize_with_provenance` supports legitimate derived writes. Supported MCP/OpenClaw/Python/TypeScript surfaces now propagate sessions and provenance, and outbound federation pull excludes provenance-derived facts.

**What this means:** the most direct same-session worm path is structurally blocked for supported clients and adapters when they use the shipped session/provenance contract. The risk stays in review until release certification and operator validation exercise those controls.

**What to do today:**

- Restrict agent writer keys to the narrowest possible scope. Agents should not hold writer keys for any scope they also read from where they consume cross-org content, period.
- If your agent must both read company-scope facts and write company-scope facts, the read content must come from sources you trust (your own organization's writes, not federated peers).
- Use session headers and `derived_from` provenance for any agent write derived from recalled facts.
- Treat OpenClaw as alpha/evaluation-only. The adapter now has audit-mapped C1-C4/H1-H5 regression coverage, fail-closed boot behavior, visible partial-write failures, channel-separated recall handling, handoff-target allowlisting, stable session propagation, and provenance-carrying handoff writes, but the broader R-21 risk remains in review until certification and operator validation complete.

---

### 5. Storing regulated data without explicit at-rest encryption

**Status:** SQLCipher at-rest encryption is supported but **not on by default**.

**What this means:** the default deployment writes facts to a plaintext SQLite file. Anyone with read access to the disk can read all facts.

**What to do today:** if you are storing PHI, PII, financial data, or anything else governed by regulation, you must explicitly enable SQLCipher per the [hardening guide](docs/security/hardening.md). The default setup is not appropriate for regulated workloads.

---

### 6. Cloud embedding with sensitive fact content

**Status:** Cloud embedding (OpenAI, Cohere, etc.) is opt-in. The default deployment uses a local `nomic-embed-text-v1.5` model and never sends fact content to third parties.

**What this means:** if you opt into cloud embedding, **every fact's `entity + relation + value` string is sent to the embedding provider** during recall pipeline operation. Embedding providers may log, cache, or use that data per their terms of service.

**What to do today:** keep cloud embedding off for any deployment that handles sensitive data. If you need cloud embedding for performance or quality reasons, classify your data first and ensure your provider's terms align with your data-handling requirements. We do not yet check returned embeddings for adversarial manipulation by a hostile provider; that is a separate open risk (will be tracked in the next threat-model revision).

---

### 7. Production deployments without rate limits or audit logs

**Status:** Per-principal rate limits are not yet enforced. The audit log exists conceptually but is not yet WAL-ordered or persistent across the 13 documented event types.

**What this means:**

- A compromised API key can issue unbounded writes/recalls until you notice and rotate.
- A misbehaving agent can exhaust your storage or your CPU.
- You cannot reconstruct who-did-what from logs in a way suitable for incident response.

**What to do today:** treat v0.9.0a10 as a development and evaluation release. Production deployment is not recommended until rate limits and persistent audit-log controls complete and are release-validated. If you must deploy to production now, run behind a reverse proxy with its own rate limiting, and pipe stigmem's structured output to a SIEM you trust.

---

### 8. Long-lived API keys with weak hashing and no rotation

**Status:** New API keys use Argon2id hashing at rest (`node/src/stigmem_node/auth.py:_hash_key`) with the [ADR-007](docs/adr/archive/007-argon2id.md) parameters. Legacy v0.9.0a1 SHA-256 rows remain valid during the v0.9.x migration window and are opportunistically rehashed to Argon2id on first successful use. **Separately:** automated rotation and an "expiring soon" admin surface are not yet available.

**What this means:** an attacker who obtains the api_keys table (e.g., via R-23 admin-level storage compromise, or via a separate exfiltration vector) faces Argon2id for new keys. Any legacy SHA-256 rows that have not been used or explicitly rotated still retain the older fast-hash posture until migration completes.

**What to do today:**

- **Treat the api_keys table as a high-value secret.** Restrict filesystem access to it. Don't back it up in clear-text. If you're using SQLCipher (`STIGMEM_AT_REST_KEY_PASSPHRASE_ENV` set — see Limitation 5), the table is encrypted at rest with an Argon2id-derived key, which substantially raises the bar — recommended for any deployment with regulated data or sensitive workloads.
- **Generate API keys at sufficient length** (the default caller-generated recommendation is 256-bit; don't override to anything shorter). Argon2id is defense-in-depth, not permission to use short or predictable keys.
- **Rotate keys manually on your own schedule** (recommend ≤90 days). Treat any key issued for testing or demo purposes as compromised once you've shared it with anyone outside the issuance context.

Future hardened-core work brings: automated rotation runbooks and an "expiring soon" admin surface.

**Why this changed:** release-readiness review for v0.9.0a1 caught that the implementation still used raw SHA-256 despite earlier prose saying Argon2id. The current alpha line corrects the implementation while retaining dual-mode verification for already-issued keys.

---

### 9. Running the OpenClaw bundled adapter as-is

**Status:** Most immediate OpenClaw safety issues have hardened-core fixes landed. The
adapter separates retrieved content from instruction-channel recall output and
requires callers to place `SYSTEM_PROMPT_DIRECTIVE` above the delimited
`UNTRUSTED STIGMEM CONTENT` summary. Audit-mapped C1-C4/H1-H5 regression tests
now cover the known critical/high adapter findings. Broader R-21 hardening has
landed for supported-adapter session propagation and outbound replication
exclusion, but still needs release certification and operator validation.

**What this means:** recent hardening has addressed API-key fail-closed behavior,
boot failure handling, target allowlists, visible multi-fact write failures, and
the OpenClaw content/instruction channel boundary. Recalled content is still
untrusted data. Do not treat retrieved facts as instructions unless a future
instruction-channel contract explicitly authorizes that use.

**What to do today:** treat the OpenClaw adapter as `experimental/` and outside
the supported production surface until certification and operator validation complete. If you've
integrated against it, use private nodes, least-privilege keys, explicit handoff
allowlists, and avoid high-stakes workflows that inject recalled facts into an
LLM prompt.

---

### 10. Federation patterns not supported by the four-scope model

**Status:** The current scope model (`local` / `team` / `company` / `public`) is sufficient for single-organization deployments and trusted bilateral peering. It does not express several federation patterns that operators with multi-org or coalition deployments may need. Richer expressivity is planned for v1.x via memory gardens (currently experimental, see `Spec-X5`).

**What this means:** the following federation patterns are **not** supported in v0.9.0a1 and require either custom integration on top of stigmem or waiting for a future ADR-008 promotion of the basic memory-garden primitive:

- **Selective sharing with specific peers.** No way to express "shared with Partner Org B but not Partner Org C." Workaround: use `public` (over-shares to every peer) or run separate stigmem deployments per peering relationship.
- **Coalition or consortium membership.** No way to express a multi-org shared scope (e.g., a three-university research consortium). Workaround: separate stigmem deployment for the coalition.
- **Asymmetric trust between peers.** Trust is symmetric per peering agreement; capability tokens authorize *write* asymmetry but the four-scope model does not express *visibility* asymmetry between peers.
- **Project-bounded collaboration.** No way to express a per-project shared scope across orgs (e.g., "facts about Joint Project X are visible to both Org A and Org B; everything else stays internal"). Workaround: separate deployment per project.
- **Hierarchical organization relationships.** No native parent-subsidiary modeling. Each org is independent in the federation graph; a parent company cannot natively express "share these facts with all my subsidiaries but not external peers."
- **Compliance-aware scopes.** Regulated data (PHI, PII, financial) must be handled by operator-layer policy. The scope model is not compliance-aware; operators must layer classification, retention, and audit-trail requirements on top.
- **Time-bounded shared scopes.** Per-fact `valid_until` covers fact-level expiry; the four-scope model does not express "this scope's contents are visible to peer X for time T."
- **Read-vs-write asymmetry per peer at the scope level.** Capability tokens distinguish read from write at the verb level, but combining scope + token to express "Peer B can read scope X, but not write to it" is awkward and requires careful operator configuration.

**What to do today:** if your federation use case is single-organization or trusted bilateral peering, the four-scope model is sufficient. For coalition, multi-peer, or project-bounded patterns, evaluate whether stigmem v0.9.0a1 meets your needs before deploying. The basic memory-garden primitive that addresses these patterns is targeted for v1.x after `Spec-X5` passes the ADR-008 gate process and is promoted from experimental into the supported surface. Operators with these requirements who want to influence prioritization should [open an issue](https://github.com/eidetic-labs/stigmem/issues) tagged `area/federation-expressivity`.

**Why we chose this for v0.9.0a1:** expanding the scope model in v1.0.0 would be exactly the kind of scope churn [ADR-002](docs/adr/002-v1-scope.md) is designed to prevent. The decision is to ship the smaller defensible thing (four scopes, simple federation) and grow expressivity through gardens once they pass the ADR-008 gates.

---

## Install footguns specific to v0.9.0a1

These are pre-release-era install behaviors that surprise adopters who don't expect them. Each is the *correct* behavior for a pre-stable release; documenting so the surprise is named, not eliminated.

### `pip install stigmem` returns "no matching distribution found"

**Cause:** v0.9.0a1 is a PEP 440 pre-release (`a1` = alpha 1). `pip` excludes pre-releases from default resolution; it returns a "no matching distribution found" error rather than installing the alpha.

**Fix:** add `--pre`:

```bash
pip install --pre stigmem            # SDK only (default)
pip install --pre stigmem[node]      # SDK + reference node service
pip install --pre stigmem[all]       # everything published from this monorepo
```

This is intentional — adopters running `pip install <pkg>` in CI shouldn't accidentally pull in pre-stable software. It will go away when v1.0.0 ships (no `--pre` needed for stable releases).

### `stigmem` is a meta-package, not the actual code

**What you get:** `pip install --pre stigmem` installs an empty wheel called `stigmem` plus its declared dependency `stigmem-py>=0.9.0a1,<1.0.0`. The actual SDK code is in `stigmem-py`. Adopters who run `pip show stigmem` see ~5 metadata files and no Python source — that's correct.

**Why:** the canonical name `stigmem` should resolve to a useful install. Most adopters want the SDK (the most common use case in client/server software). Operators self-hosting want the server, available via `stigmem[node]` or `pip install --pre stigmem-node` directly. Mirrors the pattern of `redis`/`psycopg`/`elasticsearch` — bare-name install always = client SDK.

**If you want the actual SDK code path:** `import stigmem` in Python imports from `stigmem-py`'s installed location. The meta-package's empty wheel doesn't intercept anything.

### npm SDK is scoped under `@eidetic-labs`

**What works:**
```bash
npm install @eidetic-labs/stigmem-ts                 # gets the most recent published version (currently a prerelease)
npm install @eidetic-labs/stigmem-ts@alpha           # gets the most recent 0.9.0-alpha.* prerelease
npm install @eidetic-labs/stigmem-ts@0.9.0-alpha.10   # explicit pin
```

**Why scoped:** npm's free-tier organization permissions don't allow team-bound package access controls; scoping under `@eidetic-labs` sidesteps that limitation entirely.

### npm `latest` dist-tag — what it means in this project

npm requires every package to have a `latest` dist-tag; there is no way to publish without one. By **standard npm convention** `latest` is interpreted as "the recommended stable version" — but the wire-mandatory rule means `latest` *exists* as soon as a package is published, regardless of stability tier.

**Our convention is different and explicit:**

> Until v1.0.0 GA ships, `latest` tracks the **most recent published version** — stable or prerelease. It walks forward through `0.9.0aN` and `0.9.0bN` releases automatically, then locks onto the v1.0.0 line at GA.

**What this means concretely:**

| Adopter command | What you get today (v0.9.0a10) | What you'll get over time |
|---|---|---|
| `npm install @eidetic-labs/stigmem-ts` | `0.9.0-alpha.10` | The most recent published version, advancing through the active alpha line first. Future beta/RC/GA tags are created only when those release lines are explicitly opened and published. |
| `npm install @eidetic-labs/stigmem-ts@alpha` | `0.9.0-alpha.10` | The most recent alpha. |
| `npm install @eidetic-labs/stigmem-ts@beta` | (no version yet) | No active beta line today. |
| `npm install @eidetic-labs/stigmem-ts@rc` | (no version yet) | No active release-candidate line today. |

**Stability signal lives in the version string,** not the dist-tag. Any version ending in `-alpha.N`, `-beta.N`, or `-rc.N` is pre-stable and carries no compatibility guarantee. Adopters who need stability **must** pin a v1.x version once the v1.0.0 line ships. Until then, the version string is the only honest stability indicator.

This convention deviates from typical npm projects (where `latest` = stable). It exists because the alternative — leaving `latest` pinned at the very first prerelease until v1.0.0 GA — is worse for adopters: they'd silently get the oldest preview build forever, instead of tracking the most recent.

### pip `--pre` flag is required for pre-1.0 installs

**Why:** PyPI considers any version with `aN` / `bN` / `rcN` suffix a pre-release. `pip install` excludes pre-releases by default unless `--pre` is passed.

```bash
pip install --pre stigmem                     # required for the alpha/beta/rc lines
pip install --pre stigmem==0.9.0a1            # explicit pin
```

This is intentional — adopters running `pip install` in CI without `--pre` shouldn't accidentally pull in pre-stable software. It will go away when v1.0.0 ships (no `--pre` needed for stable releases).

### Pre-release packages don't auto-upgrade silently

**What this means:**

- **PyPI:** if you pin to `stigmem==0.9.0a1` and we publish `0.9.0a2` next week, `pip install --upgrade stigmem` won't pick up `a2` unless you also pass `--pre`.
- **npm:** `npm update @eidetic-labs/stigmem-ts` will resolve to whatever `latest` points at — i.e., the most recent published version under our convention above. If you want to stay on the alpha line specifically (and not jump to a beta when one ships), use `npm install @eidetic-labs/stigmem-ts@alpha`.

**Recommendation:** during the v0.9.0a* and v0.9.0b* pre-stable lines, explicitly pin (e.g., `0.9.0a1`) or explicitly request the line-specific dist-tag (`@alpha`, `@beta`). Auto-upgrade across release tiers is unsafe for pre-stable software anyway — we may break the wire format between alphas.

---

## What stigmem **is** reasonable for today

These are use cases where v0.9.0a1 is genuinely useful and the limitations above don't materially affect you:

### Single-node, single-organization, non-regulated experimentation

Running one stigmem node on your own infrastructure, populated by your own agents and tools, with no federation peers — this is the use case the current code base supports well. Recall works, scopes are enforced at the SQL layer, the typed-fact model with provenance is functional, and the local-only deployment removes most of the federation-specific risks above.

### Local development and prototyping

Developers building agent applications who want to evaluate whether typed-fact memory is the right shape for their problem. Pin to a specific v0.9.0a* version, expect breaking changes during the alpha hardening window and any future pre-stable release, and treat the data as throwaway.

### Internal tooling within a single trust boundary

Memory for developer tools, internal agents, and automation that lives entirely inside your organization's existing security perimeter, where the adversary model is "honest mistakes by colleagues" rather than "active attacker." The single-organization default is reasonable for this audience.

### Threat-model evaluation

Reading our threat model, comparing it to your own requirements, and giving us feedback. This is genuinely the most valuable thing the broader community can do for the project right now. The [threat model](spec/security/threat-model.md) and the [risk register](spec/security/threat-model.md#7-risk-register) are open for issue-by-issue scrutiny.

---

## What we recommend right now

### If you are evaluating stigmem

Read this document, read the threat model, run `make demo` locally, and decide whether the design fits your problem. Don't deploy yet.

### If you integrated against an earlier version

Your code does not need to change today; the wire format hasn't changed. **Do not deploy in cross-org federation configurations.** Pin to the current alpha line and expect breaking changes before any stable release.

### If you want to help drive stigmem toward 1.0

External operator validation is one of the gates for the v1.0.0 stable release (see [ADR-001](docs/adr/001-versioning.md)). We're looking for organizations willing to run a stigmem node against a real (non-critical) workload, with public bug reporting. We'll help you set up, surface issues we couldn't anticipate ourselves, and credit you in the v1.0.0 release notes. [Open an issue](https://github.com/eidetic-labs/stigmem/issues) tagged `operator-candidate`.

### If you are auditing the security posture

Start with the [threat model](spec/security/threat-model.md). Cross-reference findings here. File issues for anything we've missed. Especially welcome: scenarios we haven't modeled, attacks our risk register doesn't cover, controls we claim that aren't actually enforced in code.

---

## Closing the gaps

The [`ROADMAP.md`](ROADMAP.md) at repo root is the public sequencing for closing the gaps named above. A condensed view, by version line:

| Limitation | Closes in | Tracked as |
|---|---|---|
| Cross-org federation safety (mTLS-default, HLC bounds, capability validation) | future hardened-core line | R-01, R-14, R-16 |
| Prompt-injection structural defense | future hardened-core line | R-05 (replaces sanitizer with capability model) |
| Agent feedback-loop attack | future hardened-core line | R-15 (new) |
| Persistent audit log | future hardened-core line | R-09 |
| Per-principal rate limits | future hardened-core line | R-02 |
| API key max-age & rotation | future hardened-core line | R-03 |
| OpenClaw adapter hardening | future hardened-core line | OpenClaw audit C-series |
| At-rest encryption defaults | future stable-readiness line | R-04 |
| Embedding poisoning detection | the v1.x post-GA expansion (post-v1.0) | new entry |
| Federation expressivity (selective peer sharing, coalitions, project scopes) | the v1.x post-GA expansion (gardens via ADR-008 gates) | Spec-X5 |

After hardened-core controls ship and a 30-day operator soak completes, this document will be updated to reflect what is actually safe, what remains opt-in, and what is still on the roadmap.

---

## Default-install scope and the plugin boundary

The default install matches the v1.0 critical-path scope from [ADR-002](docs/adr/002-v1-scope.md): cross-cutting features are expressed through the hook registry and ship as opt-in plugins per [ADR-011](docs/adr/011-cross-cutting-extraction.md)'s C1 plugin architecture, with content-addressed fact IDs (CIDs) the one deliberate exception that stays in core.

**The extraction train is complete.** As of the v0.9.0a8 → v0.9.0a9 line, lazy instruction discovery, time-travel queries, RTBF tombstones, memory-garden advanced ACL, source attestation, and multi-tenant isolation are extracted into opt-in plugin source packages under `experimental/`. Core no longer carries this feature-specific behavior in the default request path.

**What this means for you as an adopter today.** A single-org adopter running `make demo` gets single-tenant behavior with no tombstones, time-travel, lazy-instruction-discovery, advanced memory-garden ACL, or source-attestation activated. Each of those requires explicit experimental plugin registration; for example, `as_of` requests fail closed without `stigmem-plugin-time-travel`. The v1.0 critical-path scope claim describes user-visible *behavior* as well as code architecture.

**Plugin runtime status.** Core ships the registry foundation, stable 22-hook call surface, entry-point discovery, dependency ordering, lifecycle health checks, operator CLI inspection, production signing/trust policy, and author/operator documentation. The v0.9.0a10 line validates the standalone plugin artifacts (package metadata, conformance, release evidence) ahead of publication; see [ROADMAP.md](ROADMAP.md) for the publication-readiness workstream.

| Cross-cutting feature | Home | Spec reference | Extracted in |
|---|---|---|---|
| Lazy instruction discovery | `experimental/lazy-instruction-discovery/` plugin; default routes require plugin registration | `Spec-X1-Lazy-Instruction-Discovery` | v0.9.0a2 |
| Content-addressed fact IDs | `node/src/stigmem_node/cid.py` | `Spec-21-Content-Addressed-IDs`; **stays in core** ([ADR-011](docs/adr/011-cross-cutting-extraction.md)) | core (n/a) |
| Time-travel queries | `experimental/time-travel/` plugin; default `as_of` requests fail closed without plugin registration | `Spec-X3-Time-Travel-Queries` | v0.9.0a4 |
| RTBF tombstones | `experimental/tombstones/` plugin; default routes and filters require plugin registration | `Spec-X2-RTBF-Tombstones` | v0.9.0a5 |
| Memory-garden advanced ACL | `experimental/memory-garden-acl/` plugin; default deployments enforce only direct `garden_id` guards | `Spec-X5-Memory-Garden-Advanced-ACL` | v0.9.0a6 |
| Source attestation | `experimental/source-attestation/` plugin; default installs are source-attestation-inert | `Spec-X6-Source-Attestation` | v0.9.0a7 |
| Multi-tenant isolation | `experimental/multi-tenant/` plugin; default installs collapse callers to the `default` tenant | Deferred plugin work; no supported protocol spec yet | v0.9.0a8 |

The CID exception is deliberate. CIDs are load-bearing for the storage immutability stack ([ADR-016](docs/adr/016-storage-immutability-enforcement.md) L3) and the prompt-injection trust boundary ([ADR-003](docs/adr/003-prompt-injection.md) L1–L2). Keeping CIDs as a plugin would mean default install lacks integrity verification that the spec's claims depend on; ADR-011 corrects that.

---

## How to read this document over time

Every release of stigmem ships with an updated LIMITATIONS.md. Each entry has one of three lifecycle states:

- **Open** — the limitation is real for this version. Follow the "What to do today" guidance.
- **Closed** — the underlying risk has been mitigated. The entry is removed from this document and a `CHANGELOG.md` entry records the closure with a link to the relevant PR or ADR.
- **Accepted** — we have decided not to mitigate, with stated rationale. The entry stays in this document indefinitely with a "Why we accept this" note.

If a limitation moves from Open to Closed in your installed version, you can read the threat-model risk register's status column to confirm. If you find a behavior in production that this document doesn't cover, please open an issue tagged `limitations-doc`. Documents like this one are only useful when they're complete, and we cannot be complete without your reports.

---

— Eidetic Labs · [github.com/eidetic-labs/stigmem](https://github.com/eidetic-labs/stigmem)
