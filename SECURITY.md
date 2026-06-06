# Security Policy

**Security resources:**
- [Community Pen-Test Handbook](https://docs.stigmem.dev/security/pen-test) — scope, safe harbor, report template, disclosure timeline, and recognition.
- [Threat Model](https://github.com/eidetic-labs/stigmem/blob/main/spec/security/threat-model.md) — trust boundaries, STRIDE analysis, risk register.
- [Memory Garden ACL posture](#memory-garden-acl-posture) — direct garden
  guards are core; advanced tenant-wide filtering is opt-in.

## Supported Versions

Stigmem follows the alpha-beta-rc pre-release convention per [ADR-001](docs/adr/001-versioning.md). The first build of stigmem is `v0.9.0a1`; stable v1.0 has not shipped.

| Version | Supported |
| ------- | --------- |
| `0.9.0a*` (the v0.9.0aN alpha series — current) | Yes — current pre-release line. **No stability guarantee.** Breaking changes during the hardening window are expected and documented in [CHANGELOG.md](CHANGELOG.md). |
| Future beta line | Will be supported if and when a beta artifact is published; no active beta milestone exists today. |
| Future release-candidate / GA lines | Will be supported if and when those artifacts are published; no active RC or GA milestone exists today. |
| `< 0.9.0a1` (earlier development checkpoints) | **No.** These were internal development checkpoints, not tagged releases. The canonical version line begins at `v0.9.0a1`. |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via GitHub's private advisory path:

1. Go to the [Security Advisories](https://github.com/eidetic-labs/stigmem/security/advisories) page.
2. Click **"Report a vulnerability"**.
3. Fill in the details: description, reproduction steps, potential impact, and suggested fix if known.

We will acknowledge your report within **48 hours** and aim to release a patch within **14 days** for critical vulnerabilities.

## Scope

In-scope:

- Remote code execution or injection vulnerabilities
- Authentication or authorization bypasses
- Data exposure or exfiltration
- Supply chain attacks on our published packages

Out-of-scope:

- Issues in third-party dependencies (report to the upstream project)
- Rate limiting or resource exhaustion without a clear security impact

## Disclosure Policy

We follow coordinated disclosure. We ask reporters to give us 90 days before public disclosure, except for issues already being actively exploited in the wild.

## Advisory Publication Policy

Stigmem uses **CVSS 4.0** as the primary severity signal for GitHub Security Advisories (GHSAs). For the supported alpha line:

- Critical and High vulnerabilities that affect a published artifact are disclosed with a GitHub repository security advisory after a patched version is available.
- Medium and Low vulnerabilities are documented in release notes, security posture docs, or operator guidance unless there is known exploitation, third-party reporter coordination, or a downstream compliance need that makes a formal advisory appropriate.
- CVE requests are optional. Stigmem reserves CVE requests for broadly deployed stable releases, known exploitation, third-party reporter coordination, or explicit partner/customer compliance needs.

## Feature Security Records

Feature-specific security analysis lives with the feature record. This section
is an index, not the canonical analysis body; update the linked
`features/<feature>/security.md` file first, then keep this projection current.

| Feature | Security refs | Canonical feature security record |
| --- | --- | --- |
| Async jobs | None | [`features/async-jobs/security.md`](features/async-jobs/security.md) |
| Content-addressed fact IDs | R-18 | [`features/content-addressed-ids/security.md`](features/content-addressed-ids/security.md) |
| Decay semantics | R-02, R-16 | [`features/decay/security.md`](features/decay/security.md) |
| Fuzzy resolver | None | [`features/fuzzy-resolver/security.md`](features/fuzzy-resolver/security.md) |
| Gemini adapter | None | [`features/gemini-adapter/security.md`](features/gemini-adapter/security.md) |
| Go SDK | None | [`features/sdk-go/security.md`](features/sdk-go/security.md) |
| Intent envelope | R-05, R-15 | [`features/intent-envelope/security.md`](features/intent-envelope/security.md) |
| Lazy instruction discovery | R-15, R-21 | [`features/lazy-instruction-discovery/security.md`](features/lazy-instruction-discovery/security.md) |
| Letta adapter | None | [`features/letta-adapter/security.md`](features/letta-adapter/security.md) |
| Memory Garden advanced ACL | R-21 | [`features/memory-garden-acl/security.md`](features/memory-garden-acl/security.md) |
| MCP adapter | R-05, R-15, R-21 | [`features/mcp-adapter/security.md`](features/mcp-adapter/security.md) |
| Multi-tenant boundaries | R-01, R-02, R-21 | [`features/multi-tenant/security.md`](features/multi-tenant/security.md) |
| Obsidian adapter | R-07 | [`features/obsidian-adapter/security.md`](features/obsidian-adapter/security.md) |
| Cognee adapter | None | [`features/cognee-adapter/security.md`](features/cognee-adapter/security.md) |
| Dashboard | None | [`features/dashboard/security.md`](features/dashboard/security.md) |
| Fly.io deployment | None | [`features/deploy-fly/security.md`](features/deploy-fly/security.md) |
| Grafana deployment | None | [`features/deploy-grafana/security.md`](features/deploy-grafana/security.md) |
| Helm deployment | None | [`features/deploy-helm/security.md`](features/deploy-helm/security.md) |
| PaaS deployment | None | [`features/deploy-paas/security.md`](features/deploy-paas/security.md) |
| systemd deployment | None | [`features/deploy-systemd/security.md`](features/deploy-systemd/security.md) |
| Evaluation harness | None | [`features/eval-harness/security.md`](features/eval-harness/security.md) |
| OIDC SSO | None | [`features/oidc-sso/security.md`](features/oidc-sso/security.md) |
| Ollama/LiteLLM adapter | None | [`features/ollama-litellm-adapter/security.md`](features/ollama-litellm-adapter/security.md) |
| OpenAI tools adapter | None | [`features/openai-tools-adapter/security.md`](features/openai-tools-adapter/security.md) |
| Paperclip adapter | None | [`features/paperclip-adapter/security.md`](features/paperclip-adapter/security.md) |
| Recall graph | R-13, R-20, R-21 | [`features/recall-graph/security.md`](features/recall-graph/security.md) |
| Source attestation | R-22 | [`features/source-attestation/security.md`](features/source-attestation/security.md) |
| Storage backends | R-04, R-08 | [`features/storage-backends/security.md`](features/storage-backends/security.md) |
| libSQL storage | R-04, R-08 | [`features/storage-libsql/security.md`](features/storage-libsql/security.md) |
| Zep adapter | None | [`features/zep-adapter/security.md`](features/zep-adapter/security.md) |
| Subscriptions | R-14, R-16 | [`features/subscriptions/security.md`](features/subscriptions/security.md) |
| Synthesis | R-05, R-21 | [`features/synthesis/security.md`](features/synthesis/security.md) |
| Time-travel queries | R-17, R-18 | [`features/time-travel/security.md`](features/time-travel/security.md) |
| RTBF tombstones | R-16, R-17 | [`features/tombstones/security.md`](features/tombstones/security.md) |

---

## Memory Garden ACL Posture

**Memory Garden ACL is opt-in.** Default deployments enforce direct
`garden_id` reads and writes through the core `require_garden_read` and
`require_garden_write` guards. Tenant-wide queries, recall ranking, push
subscriptions, OIDC permission ceilings, and graph traversal do **not** filter
by garden membership unless `stigmem-plugin-memory-garden-acl` is installed and
registered, `STIGMEM_MEMORY_GARDEN_ACL_ENABLED=1` is set, and the relevant
per-surface enablement flag is enabled.

The `/v1/doctor` endpoint exposes the active
`memory_garden_acl_filtering` state as `disabled`, `enabled-partial`, or
`enabled-full`. `/v1/doctor` is intentionally unauthenticated in v0.9.0a10 and
therefore exposes this coarse posture value to anonymous HTTP callers as
standard ops-endpoint disclosure. It does not expose garden names, membership
rows, tenant identifiers, or policy subjects. Future hardening can auth-gate
the whole endpoint or return the posture field only to authenticated callers
while preserving `{"status": "ok"}` for anonymous health probes.

A startup warning is emitted when garden membership rows exist but the
advanced ACL plugin is not registered. See
[`features/memory-garden-acl/security.md`](features/memory-garden-acl/security.md)
for the full feature-owned disposition.

## Security Posture — v0.9.0a10 (2026-05-26)

`v0.9.0a10` is the adapter-batch publication alpha release. It packages the
Cognee, Gemini, Letta, OpenAI-compatible tools, and Zep adapters as
independently versioned `0.1.0` experimental plugins with feature-owned specs,
evidence, security records, changelogs, manifests, and package metadata.

The newly published adapters remain opt-in. Installing an adapter package makes
it discoverable through the `stigmem.plugins` entry point group; adapter
behavior still requires explicit operator configuration and does not change the
default node security posture.

Dependabot #52 / `CVE-2025-69872` flagged Cognee's transitive
`diskcache==5.6.3` dependency for unsafe pickle deserialization when an
attacker can write to the cache directory. The Cognee adapter removed its
`cognee` optional dependency extra before v0.9.0a10 tagging, so default plugin
installs, `stigmem[cognee-adapter]`, `stigmem[plugins-all]`, and
`stigmem[all]` no longer resolve Cognee or DiskCache. Live Cognee deployments
remain operator-owned until Cognee or DiskCache publishes an audited
non-vulnerable dependency path.

The standing publication policy remains: Critical and High vulnerabilities that
affect supported published artifacts are handled through GHSA where applicable
after a patched version is available; Medium and Low findings are documented in
this file unless a documented risk-profile, reporter-coordination, or
downstream-compliance carve-out applies.

## Security Posture — v0.9.0a9 (2026-05-24)

`v0.9.0a9` is the plugin-discovery alpha release. It does not graduate any
experimental plugin, turn any plugin on by default, or add an HTTP plugin
enumeration endpoint. The release adds operator-facing discovery surfaces:
README catalog entries, meta-package extras, docs catalog pages, and CLI
diagnostics for installed/enabled plugin state.

The six published security-sensitive plugin artifacts remain independently
versioned at `0.1.0` and remain opt-in. Installing a package makes the plugin
discoverable through the `stigmem.plugins` entry point group; behavior still
requires the matching `STIGMEM_*_ENABLED` gate and a node restart. This keeps
default deployments aligned with ADR-011 while making the available plugin
surface easier for operators to inspect.

The standing publication policy remains: Critical and High vulnerabilities that
affect supported published artifacts are handled through GHSA where applicable
after a patched version is available; Medium and Low findings are documented in
this file unless a documented risk-profile, reporter-coordination, or
downstream-compliance carve-out applies.

## Security Posture — v0.9.0a8 (2026-05-23)

`v0.9.0a8` is a shipped alpha release. The release validates
multi-tenant scoping as an experimental, opt-in plugin boundary: default
installs collapse every caller into the `default` tenant, while non-default
tenant resolution remains inactive unless `stigmem-plugin-multi-tenant` is
registered and `STIGMEM_MULTI_TENANT_ENABLED=true`.

The feature-owned security record documents the a8 disposition for default
identity collapse, plugin-enabled tenant resolution, fact/garden/recall/audit
and observability scoping, subscription fan-out scoping, hook payload tenant
context, and node-level federation pull default-tenant-only behavior.
Multi-tenant scoping contributes to R-01, R-02, and R-21 because shared-node
deployments amplify peer-authentication, quota, and feedback-loop risks.

This release does not claim stable shared-node readiness. Tenant-aware
non-default federation, per-tenant quota/resource controls, external operator
soak evidence, and signed standalone plugin artifacts remain future work.

The standing publication policy remains: Critical and High vulnerabilities that
affect supported published artifacts are handled through GHSA where applicable
after a patched version is available; Medium and Low findings are documented in
this file unless a documented risk-profile, reporter-coordination, or
downstream-compliance carve-out applies.

## Post-a8 Dependency Advisory — qs CVE-2026-8723 (2026-05-24)

`qs` CVE-2026-8723 / GHSA-q8mj-m7cp-5q26 is a Moderate denial-of-service issue
in `qs.stringify` when callers combine `arrayFormat: "comma"` with
`encodeValuesOnly: true` on arrays containing `null` or `undefined` entries.

Stigmem's root pnpm workspace was already pinned to the patched `qs@6.15.2`
release. The remaining exposure was the Docusaurus documentation build
toolchain lockfile, where transitive dependencies resolved `qs@6.15.1` and
`qs@6.14.2`. This is a build-time documentation dependency, not the Python
reference node, TypeScript SDK, MCP adapter runtime, or published static docs
browser bundle.

Remediation: `docs/package.json` now overrides `qs` to `>=6.15.2`, and
`docs/package-lock.json` resolves all docs-site `qs` copies to `6.15.2`.
`npm ls qs` from `docs/` confirms Docusaurus, Express/body-parser, and
`docusaurus-theme-openapi-docs` all resolve to `qs@6.15.2`.

Publication disposition: documented here per the Medium/Low publication policy.
No Stigmem GHSA is opened because the affected package advisory is already
public upstream, the vulnerable dependency is patched before the next Stigmem
release, and no supported Stigmem runtime endpoint used the vulnerable
`qs.stringify` option combination.

Evidence: [`docs/internal/security-evidence-registry-2026-05-24.md`](docs/internal/security-evidence-registry-2026-05-24.md).

## Security Posture — v0.9.0a7 (2026-05-23)

`v0.9.0a7` validated Source Attestation as an experimental, opt-in plugin
boundary: default installs keep existing fact write, recall, and federation
behavior, while assertion source checks, recall source-trust contribution, and
inbound federation source guards remain inactive unless
`stigmem-plugin-source-attestation` is registered and operator gates are
enabled.

The feature-owned security record documents the a7 disposition for direct
source matches, normalized source matches, identity-provided delegated source
entities, recall source-trust contribution, federation inbound source guards,
and R-22 residual risk. Source Attestation helps operators reason about fact
authorship claims in plugin-loaded deployments, but it does not prove release
artifact provenance. Release supply-chain evidence remains owned by the
release process: signed tags, detached artifact signatures, SBOMs, image
digests, provenance, and Rekor/Sigstore verification where applicable.

Accepted facts are not marked as locally re-attested, federated facts are not
silently re-attested, durable API-backed delegation persistence remains future
hardening, and standalone plugin artifact evidence is deferred to the plugin
launch train.

## Security Posture — v0.9.0a6 (2026-05-22)

`v0.9.0a6` was the previous alpha release. The release validates Memory Garden
advanced ACL as an experimental, opt-in plugin boundary: default installs keep
basic garden CRUD, membership, direct `garden_id` read/write guards, scope
mismatch rejection, and quarantine moderation in core, while advanced
cross-surface behavior remains inactive unless the
`stigmem-plugin-memory-garden-acl` package is registered and operator gates are
enabled.

The feature-owned security record documents the a6 cross-surface disposition
for assertion authorization, fact query filtering, recall ranking, graph
traversal, OIDC permission ceilings, subscription delivery/replay, quarantine
moderation, and R-21 residual risk. Memory Garden advanced ACL supports and
coexists with R-21 mitigation work, but it does not itself close same-session
read/write graph isolation; that closure still requires session, graph, and
audit evidence outside this feature boundary.

## Security Posture — v0.9.0a5 (2026-05-22)

`v0.9.0a5` was the previous alpha release. The release validates RTBF
tombstones as an experimental, opt-in plugin boundary: default installs do not
mount tombstone admin or federation routes and do not apply tombstone filters
unless `stigmem-plugin-tombstones` is registered and the explicit operator
gates are enabled.

R-16 and R-17 remain open feature-owned risks. The a5 validation work improves
their evidence posture by covering admin-only issuance, federation signer
authority, forged-signature rejection, tombstone audit events, selective
revocation recovery, legal-hold silence for non-admin callers, and count/header
side-channel suppression. Graduation still requires operator soak, documented
revocation runbooks, high-blast-radius approval policy, and narrower
legal-hold access separation.

No new public GHSA is introduced by the a5 tombstone validation work. The
standing publication policy remains: Critical and High vulnerabilities that
affect supported published artifacts are handled through GHSA where applicable
after a patched version is available; Medium and Low findings are documented in
this file unless a documented risk-profile, reporter-coordination, or
downstream-compliance carve-out applies.

The public disposition index for the current audit batch remains the
`v0.9.0a2` section below. The dated internal evidence registry remains a proof
ledger with path, PR, and regression-test lineage; it is not a second public
advisory index.

## Security Posture — v0.9.0a4 (2026-05-22)

`v0.9.0a4` was the previous alpha release. The release validates the
time-travel read path as an experimental, opt-in plugin boundary: default
installs fail closed for `as_of`, operators must explicitly enable the
fact-query and recall surfaces, tombstoned facts are suppressed retroactively,
and non-admin callers do not receive legal-hold existence signals.
The release also closes R-18 for the time-travel boundary: federation ingest
rejects `valid_until` extension attempts and records
`federation_valid_until_extension_rejected` audit events with the stored and
incoming values.
Maintainer audit finding NF-A1 / PYSEC-2026-161 was triaged before a4
publication and remediated in-tree by requiring `starlette>=1.0.1` for
`stigmem-node` and refreshing the locked Starlette artifact from `1.0.0` to
`1.0.1`. No vulnerable a4 artifact was published before this remediation.

The standing publication policy remains: Critical and High vulnerabilities that
affect supported published artifacts are handled through GHSA where applicable
after a patched version is available; Medium and Low findings are documented in
this file unless a documented risk-profile, reporter-coordination, or
downstream-compliance carve-out applies.

## Security Posture — v0.9.0a3 (2026-05-22)

`v0.9.0a3` carried artifact-readiness and documentation-alignment work rather
than a new advisory set. Its publication used the same advisory policy stated
above.

## Security Posture — v0.9.0a2 (2026-05-18)

> **Open security gaps named explicitly:** several controls the threat model identifies as required for cross-organizational production deployment — mTLS-default federation, persistent audit log, per-principal rate limits, capability-level validation for cross-org instructions, bounded HLC skew enforcement — are not yet in effect. (The storage-immutability stack [ADR-016](docs/adr/016-storage-immutability-enforcement.md) has since landed on `main`.) Do not federate across organizational boundaries until the remaining controls ship; see [LIMITATIONS.md](LIMITATIONS.md).

This section documents the current security posture of the stigmem `v0.9.0a2` release, including Dependabot and CodeQL triage carried forward from the 2026-05-03 dependency sweep plus follow-up dependency patches through 2026-05-18.

### Summary

| Category | Source | Count |
| -------- | ------ | ----- |
| Dependabot — alerts addressed by the 2026-05-03 dep upgrade sweep + follow-up patch sweeps | Dependency advisories | 27 |
| Dependabot — alerts in docs build toolchain (non-exploitable, suppressed) | Dependency advisories | 7 |
| CodeQL — conditional SQL-fragment assembly (false positives, closed by structural constant-SQL refactor) | Static dataflow analysis | 8 |
| Unaddressed / escalated blockers | — | 0 |

**Net result: zero unaddressed security alerts at v0.9.0a2.** Dependabot alerts are a *dependency* concern and CodeQL alerts are a *static-analysis* concern — both are separate from the threat-model risks named in the open-security-gaps note above.

### Internal audit dispositions — v0.9.0a2

The v0.9.0a2 hardening release includes a batch of findings identified during internal audit. Critical and High findings that affect published artifacts are disclosed as GitHub Security Advisories (GHSAs). Medium and Low findings are documented here rather than published as formal GHSAs unless their risk profile changes. All listed findings are patched by `stigmem-node 0.9.0a2`; upgrade with:

```bash
pip install --upgrade --pre stigmem-node
```

If you install through the meta-package, use:

```bash
pip install --upgrade --pre 'stigmem[node]'
```

| Finding | Severity | Advisory | Affected | Fixed | Resolution |
| ---- | -------- | -------- | -------- | ----- | ------- |
| C1 — Federation peer token timestamp handling | High (CVSS 4.0 — 7.1) | [GHSA-xh5j-xjfq-qvvx](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-xh5j-xjfq-qvvx) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Canonical millisecond token contract with regression coverage for valid and seconds-shaped tokens. |
| C2 — Non-loopback insecure federation startup | Critical (CVSS 4.0 — 9.1) | [GHSA-jmfc-hfjq-pxcp](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-jmfc-hfjq-pxcp) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Startup refuses insecure federation mode on non-loopback deployments. |
| H1 — Non-loopback auth-disabled deployment | Critical (CVSS 4.0 — 9.2) | [GHSA-fp6w-8wpg-74g5](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-fp6w-8wpg-74g5) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Startup refuses anonymous full-permission mode outside local development. |
| H2 — Federation peer registration approval gate | Critical (CVSS 4.0 — 9.1) | [GHSA-9vp8-3hmv-8fgh](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9vp8-3hmv-8fgh) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Peer registration requires explicit out-of-band approval before activation. |
| H3 — Unsigned plugin override acknowledgement | High (CVSS 4.0 — 7.3) | [GHSA-w7pm-9g55-mxfm](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-w7pm-9g55-mxfm) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Unsigned plugin override requires explicit operator acknowledgement. |
| H5 — Postgres schema identifier handling | High (CVSS 4.0 — 7.5) | [GHSA-9pc9-4crj-mhpj](https://github.com/eidetic-labs/stigmem/security/advisories/GHSA-9pc9-4crj-mhpj) | `stigmem-node 0.9.0a1` | `0.9.0a2` | Backend schema handling uses identifier-safe SQL composition and validation. |
| M1 — Federation nonce cache lifetime | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Nonce cache lifetime is at least as long as the accepted token lifetime. |
| M2 — Federation token issuer validation | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Issuer handling has explicit validation coverage. |
| M3 — Federation token time-claim validation | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Time-claim handling has explicit validation coverage, including Hypothesis fuzz coverage. |
| M4 — Legacy SHA-256 API key acceptance deadline | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Legacy SHA-256 API key acceptance has a configurable deadline and regression coverage. |
| M5 — OIDC ID-token algorithm allowlist | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | OIDC ID-token algorithm handling uses a configurable allowlist. |
| M6 — SQLite database and sidecar permissions | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | SQLite database and sidecar files use restrictive permissions at creation time. |
| M7 — CLI write-out path permissions | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | CLI write-out paths use restrictive permissions. |
| M8 — Rate-limit kill-switch acknowledgement | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Production-risky quota-disablement requires explicit operator acknowledgement and remains covered by deployment guidance. |
| M9 — Federation message validation | Medium | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Federation message state transitions have validation coverage and are documented as a Medium security disposition. |
| L1 — Development CORS startup warning | Low | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Development CORS posture emits a startup warning when enabled. |
| L2 — Embedding-provider error redaction | Low | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Embedding-provider errors no longer log sensitive provider detail. |
| L3 — Audit posture documentation by trust mode | Low | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Audit evidence posture is documented by trust mode and backend. |
| L4 — Federation clock-skew leeway | Low; folded into M2/M3 | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | Clock-skew behavior is covered by federation token validation hardening. |
| L5 — OIDC discovery URL validation | Low | None; documented per policy | `stigmem-node 0.9.0a1` | `0.9.0a2` | OIDC discovery URL handling validates outbound locations and is documented as a Low security disposition. |

Detailed PR, path, test, and evidence lineage for this audit is recorded in [`docs/internal/security-evidence-registry-2026-05-17.md`](docs/internal/security-evidence-registry-2026-05-17.md). Architectural risk classes derived from C2, H1, and H2 are registered as R-24, R-25, and R-26 in [`spec/security/threat-model.md`](spec/security/threat-model.md).

On 2026-06-03, the six published Critical/High advisory records above were
corrected from the broad affected range `<0.9.0a2` to the exact affected range
`==0.9.0a1`. The implementation and patched-version disposition did not
change; the correction prevents later alpha versions such as `0.9.0a10` from
being misclassified by dependency scanners that compare pre-release suffixes
conservatively or treat editable workspace lockfile entries as external
packages.

---

### Group A — Resolved by dependency upgrade sweeps (27 alerts)

The dependency upgrade sweeps upgraded the following packages to patched versions. Dependabot alerts will auto-close on the next GitHub rescan after the relevant branch merges.

#### Next.js (`experimental/dashboard/`, deferred per ADR-002) — 18 alerts

The Next.js curator dashboard (`experimental/dashboard/`) was pinned at Next.js 14 and accumulated CVEs from three major Next.js disclosure cycles. The pre-v0.9.0a1 dep sweep upgraded it to `next@15.5.15`. Follow-up upgrades to `next@15.5.16` and then `next@16.2.6` landed the patches for [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj) and [GHSA-26hh-7cqf-hhc6](https://github.com/advisories/GHSA-26hh-7cqf-hhc6).

| Alert | Severity | CVE / GHSA | Summary | Resolution |
| ----- | -------- | --- | ------- | ---------- |
| #44 | HIGH | GHSA-26hh-7cqf-hhc6 / CVE-2026-45109 | Middleware / Proxy bypass in App Router applications via segment-prefetch routes | `next@16.2.6` ≥ patched `16.2.6` |
| #38, #39 | HIGH | GHSA-8h8q-6873-q5fj | (See advisory) | `next@15.5.16` ≥ patched `15.5.16` |
| #17 | HIGH | — | DoS with Server Components | `next@15.5.15` ≥ patched `15.5.15` |
| #16 | MEDIUM | CVE-2026-27980 | Unbounded next/image disk cache growth | `next@15.5.15` ≥ patched `15.5.14` |
| #15 | MEDIUM | CVE-2026-29057 | HTTP request smuggling in rewrites | `next@15.5.15` ≥ patched `15.5.13` |
| #14 | HIGH | — | DoS via insecure React Server deserialization | `next@15.5.15` ≥ patched `15.5.10` |
| #13 | MEDIUM | CVE-2025-59471 | DoS via Image Optimizer remotePath | `next@15.5.15` ≥ patched `15.5.10` |
| #12 | HIGH | — | DoS with Server Components (incomplete fix follow-up) | `next@15.5.15` ≥ patched `15.5.9` |
| #11 | HIGH | — | DoS with Server Components | `next@15.5.15` ≥ patched `15.5.8` |
| #10 | LOW | CVE-2025-32421 | Race condition → cache poisoning | `next@15.5.15` ≥ patched `15.1.6` |
| #9 | MEDIUM | CVE-2025-57822 | Improper middleware redirect → SSRF | `next@15.5.15` ≥ patched `15.4.7` |
| #8 | MEDIUM | CVE-2025-55173 | Content injection via Image Optimization | `next@15.5.15` ≥ patched `15.4.5` |
| #7 | MEDIUM | CVE-2025-57752 | Cache key confusion for Image Optimization routes | `next@15.5.15` ≥ patched `15.4.5` |
| #6 | LOW | CVE-2025-48068 | Info exposure via missing origin check in dev server | `next@15.5.15` ≥ patched `15.2.2` |
| #5 | CRITICAL | CVE-2025-29927 | Authorization bypass in Next.js middleware | `next@15.5.15` ≥ patched `15.2.3` |
| #4 | MEDIUM | CVE-2024-56332 | DoS via Server Actions | `next@15.5.15` ≥ patched `15.1.2` |
| #3 | HIGH | CVE-2024-51479 | Authorization bypass | `next@15.5.15` ≥ patched `14.2.15` |
| #2 | MEDIUM | CVE-2024-47831 | DoS via image optimization | `next@15.5.15` ≥ patched `14.2.7` |
| #1 | HIGH | CVE-2024-46982 | Cache poisoning | `next@15.5.15` ≥ patched `14.2.10` |

> **Deployment gate:** The dashboard at `experimental/dashboard/` is deferred per ADR-002 and is not deployed to production at v0.9.0a2. Even so, all CVEs above are fixed in the installed version. No deployment should occur on any prior version.

#### vite — 1 alert

| Alert | Severity | CVE | Summary | Resolution |
| ----- | -------- | --- | ------- | ---------- |
| #27 | MEDIUM | CVE-2026-39365 | Path traversal in optimized deps `.map` handling | `vite@6.4.2` in `pnpm-lock.yaml` ≥ patched `6.4.2` |

This vulnerability requires the Vite dev server to be explicitly exposed to the network (`--host`). Stigmem does not use `vite --host` in any deployed environment.

#### esbuild — 1 alert

| Alert | Severity | CVE | Summary | Resolution |
| ----- | -------- | --- | ------- | ---------- |
| #26 | MEDIUM | — | esbuild dev server allows cross-origin requests | `esbuild@0.25.12` and `0.27.7` in `pnpm-lock.yaml` ≥ patched `0.25.0` |

esbuild's dev server is never exposed in production builds. This is exclusively a local development tooling concern.

#### Mermaid (`docs/package-lock.json`) — 4 alerts

The documentation site uses Mermaid through Docusaurus to render diagrams from repository-controlled Markdown/MDX sources. A 2026-05-12 follow-up lockfile refresh resolves Mermaid to `11.15.0`, which contains the upstream fixes for the following advisories.

| Alert | Severity | CVE / GHSA | Summary | Resolution |
| ----- | -------- | ---------- | ------- | ---------- |
| #43 | MEDIUM | GHSA-6m6c-36f7-fhxh / CVE-2026-41150 | Gantt chart infinite loop denial of service | `mermaid@11.15.0` ≥ patched `11.15.0` |
| #42 | MEDIUM | GHSA-ghcm-xqfw-q4vr / CVE-2026-41149 | State diagram `classDef` HTML injection | `mermaid@11.15.0` ≥ patched `11.15.0` |
| #41 | MEDIUM | GHSA-xcj9-5m2h-648r / CVE-2026-41148 | Diagram `classDef` CSS injection | `mermaid@11.15.0` ≥ patched `11.15.0` |
| #40 | MEDIUM | GHSA-87f9-hvmw-gh4p / CVE-2026-41159 | Mermaid configuration CSS injection | `mermaid@11.15.0` ≥ patched `11.15.0` |

**No new R-XX risk entries** in the threat model: these were dependency advisories that have been patched in the installed dependency tree. The docs build still renders trusted, repository-controlled sources; there is no new residual architectural risk to track in `spec/security/threat-model.md`.

---

### Group B — Docs build toolchain (7 alerts, suppressed)

These 7 alerts exist in transitive dependencies of `docusaurus-plugin-openapi-docs@5.0.2`, which is used to generate the API reference section of the documentation site. All are **build-time only** — they are not included in the static HTML/JS output that browsers load from the deployed docs site.

The vulnerable code paths all require **attacker-controlled input** to be processed by these libraries (prototype-pollution gadgets, YAML parser depth bombs, etc.). In the stigmem docs build, the only input to these parsers is our own OpenAPI spec committed to source control. There is no user-supplied input pathway.

`npm audit fix` can resolve these only by downgrading `docusaurus-plugin-openapi-docs` to `2.1.3`, which is a breaking change incompatible with Docusaurus 3.10. The fix will be taken when an upstream non-breaking patch is released.

| Alert | Severity | CVE | Package | Suppression rationale |
| ----- | -------- | --- | ------- | --------------------- |
| #18 | MEDIUM | CVE-2025-64718 | `js-yaml@4.1.0` (via openapi-to-postmanv2) | Build-time parser; input is trusted OpenAPI spec in source control. No user-controlled input path. |
| #19 | MEDIUM | CVE-2025-13465 | `lodash@4.17.21` (via openapi-to-postmanv2) | Build-time utility; prototype-pollution requires attacker-controlled object key. Source input is trusted. |
| #20 | HIGH | — | `serialize-javascript@6.0.2` (via copy-webpack-plugin) | Webpack serialization; runs only in CI build environment. RCE requires attacker-controlled input to the serializer during build — not applicable to our trusted-source docs build. |
| #21 | MEDIUM | CVE-2026-33532 | `yaml@1.10.2` (via openapi-to-postmanv2) | Build-time YAML parser; stack overflow requires a deeply-nested YAML file. Our OpenAPI spec is a trusted static file. |
| #22 | MEDIUM | CVE-2026-34043 | `serialize-javascript@6.0.2` (via copy-webpack-plugin) | Same as #20. CPU-exhaustion DoS requires crafted input to build step — not applicable. |
| #23 | MEDIUM | CVE-2026-2950 | `lodash@4.17.23` (via postman-collection) | Same rationale as #19. `_.unset`/`_.omit` not called on attacker-supplied keys during docs build. |
| #24 | HIGH | CVE-2026-4800 | `lodash@4.17.21` (via openapi-to-postmanv2) | Same rationale as #19. `_.template` code-injection requires attacker-controlled template string. Docs build uses fixed templates. |

**Tracking:** These suppressed findings will be re-evaluated when `docusaurus-plugin-openapi-docs@5.x` ships a version that resolves its `openapi-to-postmanv2` and `postman-collection` dependency pins.

---

### Group C — CodeQL static-analysis alerts (8 alerts, closed by structural refactor)

GitHub code-scanning (CodeQL) raised 8 open high-severity alerts against `node/src/stigmem_node/routes/` and `node/src/stigmem_node/storage/`. All 8 were **false positives** caused by a single root cause: CodeQL's taint analyzer cannot reason about Python's conditional-string-fragment assembly pattern (`if entity: conditions.append("AND f.entity = ?")`) — it treats any f-string concatenation reachable from a FastAPI `Query` param as a SQL sink, even though the user values themselves are parameter-bound and only literal SQL fragments are interpolated.

The existing `# nosec B608` suppression comments satisfied bandit but **CodeQL does not honor `# nosec` or `# noqa`**. The durable remediation is structural: refactor the SQL builders so the SQL text is a module-level constant and optional filters are gated by bound parameters using the `(? IS NULL OR col = ?)` pattern (or a `? = 1` sentinel for boolean flags). The constant-SQL form makes safety obvious to the analyzer and removes the need for any suppression comment.

The structural refactor landed on main; CodeQL re-scan closed all 8 alerts at the source.

| Alert | Rule | Location | Rationale | Resolution |
| ----- | ---- | -------- | --------- | ---------- |
| #18 | `py/sql-injection` | `routes/lint.py:124` (was) | Stale-fact check builder; conditional-fragment assembly. Safe at runtime — only literal SQL fragments interpolated; user values parameter-bound. | Constant-SQL refactor using the `_STALE_SQL` module constant. |
| #19 | `py/sql-injection` | `routes/lint.py:185` (was) | Broken-ref check builder; same pattern as #18. | Constant-SQL refactor using the `_REF_SQL` module constant. |
| #21 | `py/polynomial-redos` | `storage/postgres_backend.py:146` | Transitive taint: CodeQL traced f-string-built SQL from routes into `_pg_translate`'s `_STRFTIME_EPOCH_RE.sub()` call. In practice the regex only sees migration-file SQL (developer-authored, trusted), but the analyzer cannot prove that. | Closed by breaking the false taint chain. Belt-and-suspenders: bounded quantifiers on the regex (`\s{0,16}`, `[^)]{1,256}?`) to satisfy the polynomial-ReDoS heuristic permanently. |
| #22 | `py/sql-injection` | `routes/facts.py:246` (was) | `as_of` facts query builder; conditional-fragment assembly. | Constant-SQL refactor using the `_AS_OF_SELECT_SQL` module constant; `_build_as_of_query()` returns `(sql, params)` directly with no caller-side f-string. |
| #23 | `py/sql-injection` | `routes/lint.py:94` (was) | Contradiction check builder; same pattern as #18. | Constant-SQL refactor using the `_CONFLICT_SQL` module constant. |
| #24 | `py/sql-injection` | `routes/lint.py:220` (was) | Namespacing check builder; same pattern. | Constant-SQL refactor using the `_NS_SQL` module constant. |
| #25 | `py/sql-injection` | `routes/lint.py:254` (was) | Fact-count query; same pattern. | Constant-SQL refactor using the `_COUNT_SQL` module constant. |
| #26 | `py/sql-injection` | `routes/synthesize.py:105` (was) | Scope synthesize query; boolean `include_expired` toggled a fragment. | Constant-SQL refactor using the `_SYNTHESIZE_SQL` module constant; `? = 1` sentinel for the boolean toggle. |

**No new R-XX risk entries** in the threat model: the conditions for exploitation do not exist (every user value parameter-bound; every interpolated fragment a string literal). The alerts were precision-gap artifacts, not vulnerabilities. See [`spec/security/threat-model.md`](spec/security/threat-model.md) § 10 Rev 2.2 and [`spec/security/audit-triage.md`](spec/security/audit-triage.md) for the permanent rationale.

**Tracking:** Future CodeQL alerts on Python source paths will be triaged under this Group C pattern. Path-level CodeQL config exclusions are deliberately avoided so that real future bugs remain visible.

#### Group C, sub-category: acknowledged risks (ADR-tracked remediation)

Some CodeQL alerts are **not** precision-gap false positives — the analyzer is correct, but the flagged code is a deliberate, documented choice whose retirement is committed in an ADR. These are tracked separately because their lifecycle is different: they remain open or dismissed-as-acknowledged until the ADR's retirement milestone, at which point the code disappears and the alert auto-closes on the next scan.

| Alert | Rule | Location | Severity | Rationale | Retirement milestone |
| ----- | ---- | -------- | -------- | --------- | -------------------- |
| [#34](https://github.com/eidetic-labs/stigmem/security/code-scanning/34) | `py/weak-sensitive-data-hashing` | `auth.py:67` — `_legacy_sha256(raw)` and the legacy branch in `_verify_key_hash` | High | [PR #172](https://github.com/eidetic-labs/stigmem/pull/172) implemented the [ADR-007](docs/adr/archive/007-argon2id.md) Argon2id migration with a dual-mode verification window. New keys use Argon2id; legacy v0.9.0a1 SHA-256 rows verify against `_legacy_sha256` on first use, then opportunistically re-hash to Argon2id (`api_key_rehashed` audit event). Deleting the function today would invalidate every v0.9.0a1-issued API key. | **v1.0.0 GA** — bulk re-hash migration deletes `_legacy_sha256`; CodeQL re-scan auto-closes alert. |

**Disposition:** Alert #34 dismissed in GitHub UI with reason `won't fix`; dismissal comment points at [`spec/security/audit-triage.md`](spec/security/audit-triage.md) § "CodeQL — acknowledged risks" for the full rationale.

**Audit-trail visibility for operators:** track Argon2id migration progress with
```sql
SELECT COUNT(*) FROM fact_audit_log WHERE event_type = 'api_key_rehashed';
```
Every legacy row that gets used at least once during the v0.9.x window contributes one row. At v1.0.0 GA the remaining un-used legacy rows are forced through rotation as part of the retirement migration.

---

### Core Node (Python/FastAPI)

The stigmem reference node (`stigmem/node/`) is implemented in Python with FastAPI and SQLite. It has no JavaScript dependency tree. No Python Dependabot alerts are open as of 2026-05-03. Python dependencies are managed via `uv` and `pyproject.toml`; `uv.lock` is checked in.

---

### Security Controls in Effect (v0.9.0a2)

> The controls listed here are **dependency- and code-level controls** that are in effect at v0.9.0a2. **Federation-level controls** named in the open-security-gaps note at the top of this section (mTLS-default, audit log, rate limits, capability validation, bounded HLC skew) are **not yet in effect** and remain on the roadmap. The storage-immutability stack ([ADR-016](docs/adr/016-storage-immutability-enforcement.md)) has since landed on `main`.

- **Authentication:** API keys enforced on all write endpoints; per-scope restrictions supported by `Spec-02-Scopes-and-ACL` and `Spec-06-Capability-Tokens`.
- **Federation:** Peer handshake uses Ed25519 signing; replay attack resistance via HLC timestamps per `Spec-05-Federation-Trust` and `Spec-11-Replay-Protection`.
- **Input validation:** Pydantic models on all HTTP endpoints; malformed payloads return 422 before reaching business logic.
- **Secrets:** No credentials are committed to the repository. Docker Compose uses environment variable injection.
- **Container image retention:** Every released container image (`:0.9.0aN`, `:0.9.0bN`, `:1.0.0rcN`, `:1.0.0`, plus the semver-strict spellings) is **retained on GHCR indefinitely**, so an audit trail back to any historical release remains verifiable. Rolling pointers (`:latest`, `:edge`) are retained forever; short-SHA forensics tags are pruned after 90 days. Sigstore signatures are retained alongside their target image. See the [tag-selection guide](https://docs.stigmem.dev/operators/deployment/install#image-tags) for choosing the right pin for your deployment.
- **CI:** Dependabot alerts are monitored; `pip-audit`, `pnpm audit`, `bandit`, and CodeQL run as blocking CI steps on every PR (see Audit Tooling below).

---

### Audit Tooling

All four tools run as blocking steps in `.github/workflows/ci.yml` on every push and pull request.

| Tool | Scope | What it checks | CI step |
| ---- | ----- | -------------- | ------- |
| `pip-audit` | Python dependencies (`uv.lock`) | Known CVEs in installed packages via PyPI advisory database | `python-tests` job — exits non-zero on any moderate+ finding |
| `pnpm audit` | Node.js dependencies (`pnpm-lock.yaml`) | Known CVEs via npm advisory database | `node-tests` job — `--audit-level=moderate` |
| `bandit` | Python source (`node/src/`, `sdks/stigmem-py/src/`) | Common Python security anti-patterns (injection, weak crypto, unsafe deserialization) | `python-tests` job — configured via `[tool.bandit]` in `pyproject.toml`; `B101` (assert usage) suppressed for test code |
| `CodeQL` | Python + JavaScript/TypeScript + Go + GitHub Actions sources | Semantic dataflow / taint analysis: SQL injection, ReDoS, hardcoded secrets, prototype pollution, … (via GitHub Advanced Security) | `analyze (python / javascript-typescript / go / actions)` jobs — alerts surfaced in [Security → Code scanning](https://github.com/eidetic-labs/stigmem/security/code-scanning); triage rationale recorded in Group C above and in [`spec/security/audit-triage.md`](spec/security/audit-triage.md) |

**Running locally:**

```bash
# Python dependency audit
uv run pip-audit

# Python static analysis
uv run bandit -r node/src/ sdks/stigmem-py/src/ -c pyproject.toml

# Node.js dependency audit
pnpm audit --audit-level=moderate
```

The docs build toolchain (`docusaurus-plugin-openapi-docs` and its transitive dependencies) generates known alerts in `pnpm audit` output. These are suppressed per the Group B analysis above — they are build-time only and have no user-controlled input pathway. The root `turbo` development tool advisory [GHSA-hcf7-66rw-9f5r](https://github.com/advisories/GHSA-hcf7-66rw-9f5r) is also suppressed until a patched stable package is available on npm; it is a local/CI orchestration dependency and is not included in published Stigmem artifacts.
