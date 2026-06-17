# Changelog

All notable changes to Stigmem are documented here.
This file covers the reference node (`stigmem-node`), Python SDK (`stigmem-py`), TypeScript SDK (`stigmem-ts`), and MCP adapter. Spec changes are in [`spec/CHANGELOG.md`](spec/CHANGELOG.md).

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Pre-release version strings follow [PEP 440](https://peps.python.org/pep-0440/) (Python artifacts) and [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) (npm/Helm artifacts) per [ADR-001](docs/adr/001-versioning.md).

---

## [Unreleased]

### Security

- **Dependency advisory sweep** — cleared the open Dependabot dependency alerts
  across all four lockfiles (38 of 41 resolved by version bumps/overrides; 3
  no-upstream-patch residuals documented as unreachable or build-time-only).
  Python runtime (`uv.lock`): `starlette`→1.3.1, `aiohttp`→3.14.1,
  `cryptography`→49.0.0, `python-multipart`→0.0.32. SDK/MCP workspace:
  `hono`→4.12.25, `vite`→6.4.3, `ws`→8.21.0, `js-yaml`→4.2.0. Docs toolchain:
  `ws`/`dompurify`/`js-yaml`/`launch-editor`/`@babel/core`. Obsidian plugin:
  `vite`→6.4.3. Residuals (`nltk`, `dompurify`#83 by ceiling, `gray-matter`'s
  `js-yaml` 3.x) are dispositioned in [SECURITY.md](SECURITY.md).

## [0.9.0a11] — 2026-06-11

### Added

- **Federation Multi-Tenancy Phase 2c — multi-hop relay** (#724), default-OFF
  behind `federation_relay_enabled`. A node may re-federate inbound facts,
  tombstones, and revocations to its peers under a zero-transitive-trust key
  resolver (operator-pin → stored-binding → fetch-on-first → fail-closed);
  per-fact origin signatures are carried verbatim across hops (never re-signed),
  and relay is additionally gated per peer by `relay_trusted`. The capability is
  inert unless explicitly enabled with trusted peers — egress stays self-only
  and ingest fail-closes for a default node. Migrations 045–050 are additive.

### Changed

- **`/metrics` now requires admin authentication by default** (#726).
  **Breaking:** set `STIGMEM_METRICS_REQUIRE_AUTH=false` to restore the previous
  unauthenticated Prometheus scrape for trusted-network deployments.
- Terminal `subscription_events` past the retention window are now pruned,
  bounding table growth on the delivery path (#726).
- Tightened the a11 eval-harness quality gate documentation and release
  readiness posture around `make eval-fast`, path-filtered CI, recall baseline
  behavior, and generated eval result artifacts.
- Opened the post-`v0.9.0a10` release-prep lane after the adapter publication
  batch.
- **ADR consolidation + de-contrition.** Consolidated the ADR set from 20 to 10
  living records (amendments/clusters folded into their surviving ADR;
  superseded originals retained in `docs/adr/archive/`), and removed the
  post-v1.0-retraction "contrition" framing from the public docs while keeping
  the honest per-scenario scoping. The `0.x` version line is the sole
  pre-stability signal. Added `scripts/check_adr_references.py` as a CI guard
  against dangling/stale ADR references.
- **ADRs are now living documents** (previously: immutable after acceptance).
  Editorial edits are made in place — git holds the history; material decision
  changes are recorded as dated `## Amendments` entries, never silent
  overwrites — mirroring Stigmem's own supersede-with-a-record model for facts.
- **Feature graduation Gate 4** (ADR-008) changed from a mandatory 30-day
  external-operator soak to an internal-quality bar; external-operator
  validation relocated to the 1.0 GA stability gate (ADR-001).

### Fixed

- Removed stale recall consecutive-failure wording and tracked state now that
  recall regressions block immediately once a non-zero baseline is frozen.
- Made the tag coverage workflow tolerate the release-creation race by keeping
  the generated artifacts and coverage branch green when `coverage.xml` cannot
  be attached to the GitHub release before the publish workflow creates it.

### Security

- **GHSA-5p3m-vhh6-9236 — blind SSRF via webhook `delivery_address`.**
  Completed remediation of the webhook delivery SSRF. `delivery_address` is now
  validated at subscription-creation time (https-only by default), and webhook
  delivery resolves the host once and pins the connection to the validated IP,
  closing a DNS-rebinding TOCTOU window while preserving the `Host` header and
  TLS SNI so certificate verification still binds to the original hostname.
  Reported by [@chaitanyagarware](https://github.com/chaitanyagarware) — thank
  you for the responsible disclosure. (#726)
- Hardened the outbound SSRF address filter to classify IPv4-in-IPv6 embeddings
  (IPv4-mapped `::ffff:`, 6to4, NAT64) and RFC 6598 CGNAT space as non-public,
  closing a bypass where an attacker-controlled `AAAA` record could smuggle a
  blocked IPv4 (loopback, cloud IMDS, or RFC 1918) past the guard. Classification
  now uses the stdlib address flags in addition to the explicit denylist.
- Bumped the `hono` workspace override from `>=4.12.18` to `>=4.12.23`
  (resolving `hono@4.12.18` → `4.12.23`), clearing the four moderate Hono
  advisories surfaced by `pnpm audit` (IP-restriction static-deny bypass,
  cookie `sameSite` sanitization, JWT-middleware Authorization-scheme
  acceptance, and `app.mount()` undecoded-prefix handling). `pnpm audit`
  now reports no known vulnerabilities.
- Updated the locked `aiohttp` transitive dependency from `3.13.5` to
  `3.14.0`, resolving Dependabot alerts GHSA-hg6j-4rv6-33pg and
  GHSA-jg22-mg44-37j8 in optional adapter/provider dependency paths.
- Corrected the six published `v0.9.0a2` Critical/High GitHub Security
  Advisory affected ranges from `<0.9.0a2` to `==0.9.0a1`, matching the
  reset-line vulnerable artifact and preventing false-positive Dependabot
  alerts against later alpha lockfile entries.

## [0.9.0a10] — 2026-05-26

### Added

- `stigmem-plugin-cognee-adapter` v0.1.0 — Cognee memory-graph bridge
  adapter, experimental opt-in. Discoverable via `stigmem plugins list` and
  installable via `pip install stigmem-plugin-cognee-adapter`. See
  [feature record](features/cognee-adapter/).
- `stigmem-plugin-gemini-adapter` v0.1.0 — Gemini FunctionDeclaration bridge
  adapter, experimental opt-in. Discoverable via `stigmem plugins list` and
  installable via `pip install stigmem-plugin-gemini-adapter`. See
  [feature record](features/gemini-adapter/).
- `stigmem-plugin-letta-adapter` v0.1.0 — Letta archival-memory bridge
  adapter, experimental opt-in. Discoverable via `stigmem plugins list` and
  installable via `pip install stigmem-plugin-letta-adapter`. See
  [feature record](features/letta-adapter/).
- `stigmem-plugin-openai-tools-adapter` v0.1.0 — OpenAI-compatible tool-use
  adapter, experimental opt-in. Discoverable via `stigmem plugins list` and
  installable via `pip install stigmem-plugin-openai-tools-adapter`. See
  [feature record](features/openai-tools-adapter/).
- `stigmem-plugin-zep-adapter` v0.1.0 — Zep session-memory bridge adapter,
  experimental opt-in. Discoverable via `stigmem plugins list` and installable
  via `pip install stigmem-plugin-zep-adapter`. See
  [feature record](features/zep-adapter/).
- `stigmem[adapters]` meta-package extra for installing the five
  host-application adapter plugins as a single group.

### Changed

- Prepared the `v0.9.0a10` adapter batch publication release line.
- Pointed the previous-release SDK compatibility smoke at the shipped
  `v0.9.0a9` baseline until a later tagged baseline supersedes it.
- Kept the previous-release SDK compatibility smoke focused on SDK behavior by
  disabling plugin auto-discovery during its local node startup.

### Fixed

- Hardened `stigmem mcp install` operator output: dry runs now show the planned
  Stigmem server entry while omitting the credential field, `--write`
  identifies whether the credential came from the environment, a flag, or the
  placeholder, and POSIX backup files are written owner-only.
- Clarified that `stigmem mcp config <editor>` intentionally prints metadata
  and guide links rather than a copy-paste config snippet.
- Extended the MCP catalog consistency guard to validate the
  `/v1/mcp/connectors` payload alongside README, adapter README, docs, and CLI
  editor surfaces.
- Added federation-soak startup diagnostics so failed node health checks print
  Compose state and recent per-node logs before the nightly job exits.
- Restored the local federation soak harness by explicitly marking its
  container-only HTTP federation topology as insecure local/dev/test mode with
  Docker's non-loopback dev override, generated node signing keys, and an eval
  tombstone-signer manifest while writing local transparency-log artifacts to
  the writable eval data volume.
- Updated the federation soak harness for the current peer approval lifecycle
  and admin-only tombstone endpoints.
- Mounted the tombstone admin API router so RTBF tombstone endpoints are
  available on the reference node.
- Fixed tombstone status lookups for URI entities whose percent-encoded form
  contains path separators.
- Mounted federation tombstone poll and ingest routes on the federation router.

## [0.9.0a9] — 2026-05-25

### Changed

- Advanced live release-version surfaces toward `v0.9.0a9` for the plugin
  discovery release line.
- Opened the post-`v0.9.0a8` plugin publication readiness track, marked the
  alpha extraction train as complete through `v0.9.0a8`, and added the
  standalone experimental plugin publication contract.
- Added operator-facing plugin discovery surfaces: README plugin catalog,
  meta-package plugin extras, docs-site catalog pages, and `stigmem plugins`
  search/enable/disable/doctor CLI commands.
- Added MCP enablement surfaces: README editor integration table, docs-site
  MCP connector catalog, `stigmem mcp` doctor/detect/config/install/status/smoke
  CLI commands, and `GET /v1/mcp/connectors` catalog discovery.
- Added a structural guard that keeps README, PyPI extra definitions, and docs
  plugin catalog entries aligned for the six published experimental plugins.
- Added a structural guard that keeps README, adapter README, docs-site MCP
  connector pages, and the `stigmem mcp` editor catalog aligned.

### Security

- Remediated `qs` CVE-2026-8723 / GHSA-q8mj-m7cp-5q26 in the documentation
  build toolchain by forcing `qs>=6.15.2` in `docs/package.json` and refreshing
  `docs/package-lock.json`. The root pnpm workspace was already pinned to the
  patched `qs@6.15.2` release.

## [0.9.0a8] — 2026-05-23

**Status:** alpha (pre-stable). Multi-tenant scoping remains experimental,
opt-in, and operator-gated.

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a8`, `stigmem-py 0.9.0a8`, `stigmem-node 0.9.0a8`, and `stigmem-openclaw 0.9.0a8` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.8` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a8` and `:0.9.0-alpha.8`.
- Git tag, GitHub release, prose: `v0.9.0a8` (shorthand).

### Changed

- Advanced the enforced release-version surfaces to the `v0.9.0a8` alpha line
  across Python packages, npm packages, API metadata, conformance metadata,
  plugin compatibility defaults, release documentation, and current-facing
  adopter guidance.
- Validated the `v0.9.0a8` multi-tenant alpha horizon in the feature-owned
  records. Default installs collapse callers to the `default` tenant;
  non-default tenant isolation requires `stigmem-plugin-multi-tenant`
  registration and explicit operator enablement.

### Security

- Recorded the multi-tenant scoping disposition for default identity collapse,
  plugin-enabled tenant resolution, fact/garden/recall/audit/observability and
  subscription scoping, and node-level federation pull default-tenant-only
  behavior.
- Added tenant-ID normalization and validation, explicit TenantContext source
  metadata, and a structural CI guard that rejects unclassified tenant context
  construction.
- Clarified that multi-tenant scoping is experimental and does not yet claim
  stable shared-node readiness, tenant-aware non-default federation,
  per-tenant quota/resource isolation, external operator soak evidence, or a
  signed standalone plugin artifact.

## [0.9.0a7] — 2026-05-23

**Status:** alpha (pre-stable). Source attestation remains experimental,
opt-in, and operator-gated.

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a7`, `stigmem-py 0.9.0a7`, `stigmem-node 0.9.0a7`, and `stigmem-openclaw 0.9.0a7` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.7` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a7` and `:0.9.0-alpha.7`.
- Git tag, GitHub release, prose: `v0.9.0a7` (shorthand).

### Changed

- Advanced the enforced release-version surfaces to the `v0.9.0a7` alpha line
  across Python packages, npm packages, API metadata, conformance metadata,
  plugin compatibility defaults, release documentation, and current-facing
  adopter guidance.
- Validated the `v0.9.0a7` source-attestation alpha horizon in the
  feature-owned records. Default installs remain source-attestation-inert;
  assertion source checks, source-trust recall signals, and inbound federation
  source validation require `stigmem-plugin-source-attestation` registration
  and explicit operator gates.

### Security

- Recorded the source-attestation disposition for direct source matches,
  normalized source matches, identity-provided delegated source entities,
  recall source-trust contribution, and federation inbound source guards.
- Clarified that source attestation validates fact authorship claims in
  plugin-loaded deployments and does not prove release artifact provenance.
  Signed tags, detached artifact signatures, SBOMs, image digests, provenance,
  and Rekor/Sigstore evidence remain release-process responsibilities.
- Documented residual source-attestation gaps: accepted facts are not marked
  as locally re-attested, federated facts are not silently re-attested, durable
  API-backed delegation persistence remains future hardening, and standalone
  plugin artifact evidence is deferred to the plugin launch train.

## [0.9.0a6] — 2026-05-22

**Status:** alpha (pre-stable). Memory Garden advanced ACL remains
experimental, opt-in, and operator-gated.

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a6`, `stigmem-py 0.9.0a6`, `stigmem-node 0.9.0a6`, and `stigmem-openclaw 0.9.0a6` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.6` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a6` and `:0.9.0-alpha.6`.
- Git tag, GitHub release, prose: `v0.9.0a6` (shorthand).

### Changed

- Advanced the enforced release-version surfaces to the `v0.9.0a6` alpha line
  across Python packages, npm packages, API metadata, conformance metadata,
  plugin compatibility defaults, release documentation, and current-facing
  adopter guidance.
- Validated the `v0.9.0a6` Memory Garden advanced ACL alpha horizon in the
  feature-owned records. Basic garden CRUD, membership, direct `garden_id`
  guards, and quarantine moderation remain core; advanced cross-surface ACL
  behavior remains opt-in behind `stigmem-plugin-memory-garden-acl`
  registration and operator gates.

### Security

- Recorded the Memory Garden advanced ACL cross-surface disposition for fact
  query filtering, recall ranking, graph traversal, OIDC permission ceilings,
  subscription delivery/replay, and quarantine moderation. The feature supports
  and coexists with R-21 mitigation work but does not itself close
  same-session read/write graph isolation.
- Documented Memory Garden ACL posture explicitly: default deployments enforce
  direct `garden_id` read guards but do not filter tenant-wide queries, recall
  ranking, push subscriptions, OIDC permission ceilings, or graph traversal
  unless `stigmem-plugin-memory-garden-acl` is installed, registered, and the
  per-surface enablement flags are set. `SECURITY.md`, quickstart, a startup
  warning, and the `/v1/doctor` endpoint now surface the opt-in posture.
- Recorded the `/v1/doctor` disclosure disposition: the unauthenticated
  endpoint exposes only coarse `memory_garden_acl_filtering` posture in
  v0.9.0a6; future hardening can auth-gate the endpoint or suppress the
  posture field for anonymous callers.
- Plugin scaffold handlers in `stigmem-plugin-memory-garden-acl` now carry
  docstrings explaining stub behavior, failure modes, and core fallback.
- Quarantine moderator node-admin bypass is now documented in code and in the
  Memory Garden advanced ACL feature security record.
- Release signing key hygiene now excludes `stigmem-release-signing-key*.asc`
  and private/secret signing-key `.asc` files from the repository.

## [0.9.0a5] — 2026-05-22

**Status:** alpha (pre-stable). RTBF tombstones remain experimental, opt-in,
and operator-gated.

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a5`, `stigmem-py 0.9.0a5`, `stigmem-node 0.9.0a5`, and `stigmem-openclaw 0.9.0a5` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.5` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a5` and `:0.9.0-alpha.5`.
- Git tag, GitHub release, prose: `v0.9.0a5` (shorthand).

### Changed

- Advanced the enforced release-version surfaces to the `v0.9.0a5` alpha line
  across Python packages, npm packages, API metadata, conformance metadata,
  plugin compatibility defaults, release documentation, and current-facing
  adopter guidance.

### Security

- Validated the `v0.9.0a5` RTBF tombstone alpha scope as an opt-in
  `stigmem-plugin-tombstones` feature. Default installs remain inert until the
  plugin is registered and operator gates are enabled; admin issuance,
  federation signer authority, forged-signature rejection, audit events,
  selective revocation, legal-hold silence, and no-leak behavior are covered in
  the feature-owned evidence record.
- Consolidated admin determination to use `Identity.is_admin()` across
  tombstone admin routes, instruction admin routes, and provenance tombstone
  filtering. This removes the `can_write() and can_federate()` proxy so admin
  checks consult the dedicated `admin` capability and `capability_check` voting
  hook consistently.
- Added `scripts/check_admin_determination_consistency.py` to reject future
  capability-combination-as-admin-proxy patterns in the Python node source.

## [0.9.0a4] — 2026-05-22

**Status:** alpha (pre-stable). Time-travel historical reads remain
experimental, opt-in, and operator-gated.

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a4`, `stigmem-py 0.9.0a4`, `stigmem-node 0.9.0a4`, and `stigmem-openclaw 0.9.0a4` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.4` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a4` and `:0.9.0-alpha.4`.
- Git tag, GitHub release, prose: `v0.9.0a4` (shorthand).

### Changed

- Advanced the enforced release-version surfaces to the `v0.9.0a4` alpha line
  across Python packages, npm packages, API metadata, conformance metadata,
  plugin compatibility defaults, release documentation, and current-facing
  adopter guidance.
- Validated `v0.9.0a4` time-travel behavior: `as_of` remains experimental and
  opt-in behind `stigmem-plugin-time-travel`, requires explicit operator gates,
  fails closed by default, and now has aligned feature, compatibility,
  security, and public-doc projections for the a4 release horizon.

### Security

- Validated the time-travel read path against tombstone and legal-hold
  disclosure risks: historical reads suppress tombstoned facts retroactively
  and non-admin callers do not receive legal-hold existence signals.
- Closed R-18 federation `valid_until` extension rejection. Federation ingest
  now compares incoming `valid_until` against the locally stored value on
  re-ingest and raises `FederationValidUntilExtensionError` when the incoming
  value would extend visibility beyond the locally observed bound. Rejections
  emit a `federation_valid_until_extension_rejected` audit event with stored
  and incoming values for forensic inspection. Combined with local source-trust
  recomputation, R-18 is now closed.
- Consolidated `is_admin_caller` derivation across `as_of` recall and
  fact-query paths to consistently use `Identity.is_admin()`.
- Tightened plugin handler docstrings in `stigmem-plugin-time-travel` to
  clarify the gate-only role and prevent duplicate authorization at the wrong
  layer.
- Removed orphan `retention_floor` configuration from the time-travel plugin;
  retention floor remains a single core setting
  (`STIGMEM_AS_OF_RETENTION_FLOOR`).
- Remediated maintainer-audit finding NF-A1 / PYSEC-2026-161 before a4
  publication by adding an explicit `starlette>=1.0.1` node dependency floor
  and refreshing `uv.lock` from `starlette 1.0.0` to `1.0.1`.
- Retained the standing advisory publication policy: Critical and High
  vulnerabilities use GHSA where applicable after a patched artifact is
  available; Medium and Low findings remain in `SECURITY.md` unless a
  documented carve-out applies.

## [0.9.0a3] — 2026-05-22

**Status:** alpha (pre-stable).

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a3`, `stigmem-py 0.9.0a3`, `stigmem-node 0.9.0a3`, and `stigmem-openclaw 0.9.0a3` (PEP 440).
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.3` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a3` and `:0.9.0-alpha.3`.
- Git tag, GitHub release, prose: `v0.9.0a3` (shorthand).

### Added

- Validated content-addressed fact IDs as a core alpha feature across the
  feature record, modular spec projection, compatibility matrix, and release
  evidence surfaces.
- Captured a3 release-readiness evidence for the core Python packages,
  TypeScript SDK package, OpenClaw adapter package, GHCR tag posture, and docs
  publication posture.

### Changed

- Advanced the enforced release-version surfaces to the active `v0.9.0a3`
  alpha line so package, API metadata, conformance, plugin fallback, and
  release-documentation surfaces use consistent per-ecosystem spellings.
- Align roadmap, security, operator, SDK, and spec documentation around the current release horizon: `v0.9.0a3` is the only active release target; beta, release-candidate, and GA lines remain future gates until explicitly opened.
- Prepared the OpenClaw adapter and ClawHub skill metadata for the a3 alpha
  artifact line while preserving the alpha/evaluation-only posture.

### Security

- Reconciled a3 release notes and security posture with the standing
  publication policy: Critical and High findings use GHSA where applicable;
  Medium and Low dispositions remain in `SECURITY.md` unless a documented
  carve-out applies.
- Kept the dated security evidence registry as a proof ledger and `SECURITY.md`
  as the public disposition index, avoiding duplicate advisory tables in a3
  release notes.

### Feature Change Records

Feature-local change history is canonical in feature records. This table is the
root changelog projection used during release prep.

| Feature | Status | Release lines | Feature changelog |
| --- | --- | --- | --- |
| Async jobs | active | `v0.9.0a1`, `0.9.xA` | [`features/async-jobs/changelog.md`](features/async-jobs/changelog.md) |
| Content-addressed fact IDs | active | `v0.9.0a1`, `v0.9.0a3` | [`features/content-addressed-ids/changelog.md`](features/content-addressed-ids/changelog.md) |
| Decay semantics | deferred | `v0.9.0a1`, `0.9.xA` | [`features/decay/changelog.md`](features/decay/changelog.md) |
| Dashboard | deferred | `v0.9.0a1`, `0.9.xA` | [`features/dashboard/changelog.md`](features/dashboard/changelog.md) |
| Fly.io deployment | deferred | `v0.9.0a1`, `0.9.xA` | [`features/deploy-fly/changelog.md`](features/deploy-fly/changelog.md) |
| Grafana deployment | deferred | `v0.9.0a1`, `0.9.xA` | [`features/deploy-grafana/changelog.md`](features/deploy-grafana/changelog.md) |
| Helm deployment | deferred | `v0.9.0a1`, `0.9.xA` | [`features/deploy-helm/changelog.md`](features/deploy-helm/changelog.md) |
| PaaS deployment | deferred | `v0.9.0a1`, `0.9.xA` | [`features/deploy-paas/changelog.md`](features/deploy-paas/changelog.md) |
| systemd deployment | deferred | `v0.9.0a1`, `0.9.xA` | [`features/deploy-systemd/changelog.md`](features/deploy-systemd/changelog.md) |
| Evaluation harness | active | `v0.9.0a1`, `v0.9.0a11` | [`features/eval-harness/changelog.md`](features/eval-harness/changelog.md) |
| Fuzzy resolver | active | `v0.9.0a1`, `0.9.xA` | [`features/fuzzy-resolver/changelog.md`](features/fuzzy-resolver/changelog.md) |
| Gemini adapter | active | `v0.9.0a1`, `v0.9.0a10` | [`features/gemini-adapter/changelog.md`](features/gemini-adapter/changelog.md) |
| Go SDK | active | `v0.9.0a1`, `0.9.xA` | [`features/sdk-go/changelog.md`](features/sdk-go/changelog.md) |
| Intent envelope | deferred | `v0.9.0a1`, `0.9.xA` | [`features/intent-envelope/changelog.md`](features/intent-envelope/changelog.md) |
| Lazy instruction discovery | active | `v0.9.0a1`, `0.9.xA` | [`features/lazy-instruction-discovery/changelog.md`](features/lazy-instruction-discovery/changelog.md) |
| Letta adapter | active | `v0.9.0a1`, `v0.9.0a10` | [`features/letta-adapter/changelog.md`](features/letta-adapter/changelog.md) |
| Memory Garden advanced ACL | active | `v0.9.0a1`, `v0.9.0a6`, `0.9.xA` | [`features/memory-garden-acl/changelog.md`](features/memory-garden-acl/changelog.md) |
| MCP adapter | active | `v0.9.0a1`, `0.9.xA` | [`features/mcp-adapter/changelog.md`](features/mcp-adapter/changelog.md) |
| Multi-tenant scoping | active | `v0.9.0a8`, `0.9.xA` | [`features/multi-tenant/changelog.md`](features/multi-tenant/changelog.md) |
| Obsidian adapter | active | `v0.9.0a1`, `0.9.xA` | [`features/obsidian-adapter/changelog.md`](features/obsidian-adapter/changelog.md) |
| Cognee adapter | active | `v0.9.0a1`, `v0.9.0a10` | [`features/cognee-adapter/changelog.md`](features/cognee-adapter/changelog.md) |
| OIDC SSO | active | `v0.9.0a1`, `0.9.xA` | [`features/oidc-sso/changelog.md`](features/oidc-sso/changelog.md) |
| Ollama/LiteLLM adapter | superseded | `v0.9.0a1`, `0.9.xA` | [`features/ollama-litellm-adapter/changelog.md`](features/ollama-litellm-adapter/changelog.md) |
| OpenAI tools adapter | active | `v0.9.0a1`, `v0.9.0a10` | [`features/openai-tools-adapter/changelog.md`](features/openai-tools-adapter/changelog.md) |
| Paperclip adapter | deferred | `v0.9.0a1`, `0.9.xA` | [`features/paperclip-adapter/changelog.md`](features/paperclip-adapter/changelog.md) |
| Recall graph | deferred | `v0.9.0a1`, `0.9.xA` | [`features/recall-graph/changelog.md`](features/recall-graph/changelog.md) |
| Source attestation | active | `v0.9.0a1`, `0.9.xA` | [`features/source-attestation/changelog.md`](features/source-attestation/changelog.md) |
| Storage backends | active | `v0.9.0a1`, `0.9.xA` | [`features/storage-backends/changelog.md`](features/storage-backends/changelog.md) |
| libSQL storage | active | `v0.9.0a1`, `0.9.xA` | [`features/storage-libsql/changelog.md`](features/storage-libsql/changelog.md) |
| Zep adapter | active | `v0.9.0a1`, `v0.9.0a10` | [`features/zep-adapter/changelog.md`](features/zep-adapter/changelog.md) |
| Subscriptions | deferred | `v0.9.0a1`, `0.9.xA` | [`features/subscriptions/changelog.md`](features/subscriptions/changelog.md) |
| Synthesis | deferred | `v0.9.0a1`, `0.9.xA` | [`features/synthesis/changelog.md`](features/synthesis/changelog.md) |
| Time-travel queries | active | `v0.9.0a1`, `v0.9.0a4` | [`features/time-travel/changelog.md`](features/time-travel/changelog.md) |
| RTBF tombstones | active | `v0.9.0a1`, `v0.9.0a5`, `0.9.xA` | [`features/tombstones/changelog.md`](features/tombstones/changelog.md) |

---

## [0.9.0a2] — 2026-05-18

**Status:** alpha (pre-stable). See [LIMITATIONS.md](LIMITATIONS.md).

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a2`, `stigmem-py 0.9.0a2`, `stigmem-node 0.9.0a2`, and `stigmem-openclaw 0.9.0a2` (PEP 440). The `stigmem` meta-package now depends on the alpha.2 package line by default.
- npm / Node: `@eidetic-labs/stigmem-ts@0.9.0-alpha.2` (semver).
- GHCR: `ghcr.io/eidetic-labs/stigmem-node:0.9.0a2` and `:0.9.0-alpha.2`, plus `:latest` on the release tag.
- Git tag, GitHub release, prose: `v0.9.0a2` (shorthand).

### Added

- **Configurable CORS middleware for browser UI clients.** CORS remains disabled by default. Operators can enable it with `STIGMEM_CORS_DEV_LOCALHOST=1` for local development with any localhost port, `STIGMEM_CORS_ALLOWED_ORIGINS=<csv>` for production with known origins, or `STIGMEM_CORS_ALLOWED_ORIGIN_REGEX=<regex>` for advanced patterns. See the node README for full configuration reference.
- **Plugin registry foundation.** Main now includes the stable 22-hook surface, typed voting/filter-chain/score-delta/fire-and-forget semantics, deterministic `HookRegistry` dispatch, manual/core handler registration, minimum `PluginManifest` and capability-restricted `PluginContext`, hook-site wiring across assertion/recall/federation/auth/migration/audit paths, registry audit/metrics plumbing, `TestPluginRegistry`, focused plugin tests, and a hook-firing benchmark gate.
- **Docs-site AI authorship disclosure.** The README and CONTRIBUTING AI-assisted authorship disclosure is now mirrored in the docs site under Community / Disclosure & policy so adopters and reviewers can find the review-calibration guidance outside the repository root.
- **ADR-020 §9 (modular specs) modular spec foundation.** Core spec frontmatter stubs now live under `spec/specs/`, with generated `spec/PROTOCOL.md` composition metadata and a contract gate that fails on protocol-index drift.
- **ADR-010 experimental spec indexing.** Experimental spec files now carry `Spec-XN` frontmatter and appear in generated `spec/PROTOCOL.md`; archived monolithic snapshots point readers to the modular index.
- **Grade duplication audit tooling.** The workspace now installs `jscpd` as a root dev dependency and exposes `pnpm run grade:duplication`, so the grade duplication signal reports a numeric percentage instead of `unknown`.

### Changed

- **Version surfaces advanced to alpha.2.** Python, npm, FastAPI, OpenAPI, conformance, plugin fallback, Docker Compose, and release-documentation surfaces now agree on the `v0.9.0a2` line.
- Plugin infrastructure scope is now explicit: package discovery, dependency lifecycle, health polling, operator CLI, production signing/trust, plugin author/operator docs, and full plugin migration lifecycle/checksum tracking remain future alpha-series work.
- Grade duplication cleanup now keeps `pnpm run grade:duplication` under the Phase A scoring threshold by replacing duplicated experimental status boilerplate with shared gate language, removing a duplicate Helm chart copy, and delegating the OpenClaw skill adapter to the packaged `stigmem-openclaw` implementation.

### Security

- Dependency and static-analysis release gates are clean for alpha.2: Dependabot alerts, CodeQL alerts, Python dependency audit, npm audit, and pnpm audit all report no open vulnerabilities at release-prep time.
- Documented the v0.9.0a2 GitHub Security Advisory publication policy:
  Critical and High CVSS 4.0 findings in supported published artifacts receive
  GHSAs once patched; Medium and Low findings are documented in release notes
  or security posture docs unless their risk profile changes.
- Added the public v0.9.0a2 audit disposition index to `SECURITY.md`, including
  six Critical/High GHSAs and Medium/Low findings documented without formal
  advisories per policy.
- Added the v0.9.0a2 audit evidence ledger under `docs/internal/` and
  registered R-24/R-25/R-26 as mitigated architectural risks in the threat
  model and evidence registry.

---

## Pre-1.0 history note (2026-05-08)

The version markers below (`v0.2` through `v2.0`, plus `1.0.0-rc`) labeled internal development checkpoints, not tagged releases anyone deployed in production. The canonical version line of stigmem is being reset to `v0.9.0a1` as the *first build* per [ADR-001](docs/adr/001-versioning.md) and [ADR-001](docs/adr/001-versioning.md). The historical entries below are preserved as the development record; they do not represent prior public releases.

---

## [0.9.0a1] — 2026-05-08

**Status:** alpha (pre-stable). See [LIMITATIONS.md](LIMITATIONS.md).

**Per-ecosystem version strings (per ADR-001):**
- PyPI / Python: `stigmem 0.9.0a1` (PEP 440) — **meta-package**: empty wheel that depends on `stigmem-py>=0.9.0a1,<1.0.0` by default. Extras: `stigmem[node]` adds the server, `stigmem[openclaw]` adds the adapter, `stigmem[all]` adds everything. Real code ships under `stigmem-py`, `stigmem-node`, `stigmem-openclaw`. The bare `stigmem` name is the convenience entry-point for adopters who want the SDK with one command (matches the convention of `redis`, `psycopg`, `elasticsearch`, `pymongo` — bare-name = client SDK).
- npm / Node:    `@eidetic-labs/stigmem-ts@0.9.0-alpha.1` (semver) — **first npm release.** Scoped under `@eidetic-labs` so all org Owners can manage the package without npm's free-tier limitation on team-bound package permissions. Root `package.json` is `private: true` (workspace root). Adopters install via `npm install @eidetic-labs/stigmem-ts`.
- Helm `appVersion`: `0.9.0-alpha.1` (semver)
- Git tag, GitHub release, prose: `v0.9.0a1` (shorthand)

### Added

- **Repository artifacts establishing the reset:**
  - `LIMITATIONS.md` at repo root — adopter-facing constraints, known gaps, deployment-pattern guidance.
  - `MAINTAINERS.md` at repo root — current maintainers and the [ADR-001 §Contributor approval rule](docs/adr/001-versioning.md).
  - `release/version-surfaces.yaml` — canonical inventory of release surfaces and their per-ecosystem spellings; consumed by `scripts/check_version_consistency.py`.
  - `scripts/check_version_consistency.py`, `scripts/validate_version_surfaces.py`, and `.github/workflows/version-consistency.yml` — CI gate enforcing version-state consistency across release surfaces.
  - 19 ADRs committed under `docs/adr/` (per [ADR-020](docs/adr/020-feature-owned-product-structure.md) §12 (docs IA), [ADR-020](docs/adr/020-feature-owned-product-structure.md) §13 (repo structure)).
  - **README §Security posture** — at-a-glance security entry point with links to LIMITATIONS, threat-model, SECURITY.md, security architecture, and operator hardening.
  - **README §AI-authorship disclosure** — names which paths have been human-reviewed in depth and which haven't.
- **Spec section §25 — Content-addressed fact IDs (CIDs)** retained as a core feature (per [ADR-011](docs/adr/011-cross-cutting-extraction.md), amending [ADR-011](docs/adr/011-cross-cutting-extraction.md)). CIDs are load-bearing for the storage-immutability stack ([ADR-016](docs/adr/016-storage-immutability-enforcement.md)) and the prompt-injection trust boundary ([ADR-003](docs/adr/003-prompt-injection.md) L2).

### Changed

- **Canonical version line reset.** `pyproject.toml`, `package.json`, `sdks/stigmem-py/pyproject.toml`, `sdks/stigmem-ts/package.json`, `node/pyproject.toml`, `adapters/openclaw/pyproject.toml`, README status banner, SECURITY.md "Applies to" line, and threat model "Applies to" line all updated to v0.9.0a1 (PEP 440) or 0.9.0-alpha.1 (semver) per their per-surface convention. The pre-reset Helm Chart.yaml files were retired in `release/version-surfaces.yaml` rather than re-stamped. `adapters/openclaw/pyproject.toml` `stigmem-py` dependency range bumped from `>=1.0.0rc1` (the never-published constraint) to `>=0.9.0a1,<1.0.0`. `adapters/openclaw` Development Status classifier dropped from "5 - Production/Stable" to "3 - Alpha" to match actual maturity.
- **LICENSE replaced** with canonical Apache-2.0 SPDX template. Verified ~10 substantive deviations from canonical Apache-2.0 in the previous LICENSE; replaced wholesale.
- **SECURITY.md** "Supported versions" table updated: `1.0.0-rc` retired; `0.9.0a1` listed as the current supported pre-release. v0.9.0a1 carries no stability guarantee — breaking changes during the v0.9.0aN alpha and v0.9.0bN beta series hardening window are expected and called out in this changelog.
- **Default install scope shrunk.** Multi-tenant, RTBF tombstones, time-travel queries, lazy instruction discovery, advanced memory-garden ACL, and source attestation move to `experimental/` as opt-in plugins per [ADR-011](docs/adr/011-cross-cutting-extraction.md). The default install matches the v1.0 critical-path scope from [ADR-002](docs/adr/002-v1-scope.md). Operators who need experimental features install them via the plugin system.
- **Spec content under earlier version markers preserved.** The protocol-spec content from `stigmem-spec-v0.2.md` through `stigmem-spec-v2.0.md` is being reviewed section-by-section against the actual implementation and migrated forward into the v0.9.0a1 canonical structure. Earlier evolutionary spec files move to `spec/archive/evolution/` after their content has been forward-migrated. Nothing is being deleted.

### Security

- **Threat model status header** updated to v0.9.0a1 posture. The controls required for cross-organizational production deployment (mTLS-default federation, persistent audit log, per-principal rate limits, capability validation, bounded HLC skew) are listed as Open or Residual and tracked on [`ROADMAP.md`](ROADMAP.md).
- **R-23** (admin-level storage tampering / fact mutation) added to the risk register; mitigation is the [ADR-016](docs/adr/016-storage-immutability-enforcement.md) L1–L5 storage-immutability stack. The L1–L5 stack has since landed on `main` (migrations `033`–`036`, `fact_chain.py`, `lifecycle/immutability.py`); remaining hardening (Rekor anchoring cadence, mandatory SDK verify-by-default) is still future work.
- **No CVE-class fixes in this release.**

### Deprecated

- **No PyPI deprecation of the canonical packages needed.** Audit on 2026-05-08 confirmed `stigmem 1.0.0rc1` was never actually published to PyPI; the canonical `stigmem` name was unclaimed before the v0.9.0a1 first publish.

- **`stigmem-openclaw` 1.0.3 and 1.0.5 are yanked** (PEP 592). Both versions declared `stigmem-py>=1.0.0rc1` as a hard dependency; `stigmem-py 1.0.0rc1` was never published, so both adapter versions were end-to-end **uninstallable** since publish (verified 2026-05-09 via `uv pip install --dry-run stigmem-openclaw==1.0.5` — fails with "stigmem-py was not found in the package registry"). The yanks correct the record. Pinned installs of `==1.0.3` or `==1.0.5` continue to resolve to those versions (PEP 592 yank does not remove); new resolutions skip them. **`stigmem-openclaw 0.9.0a1`** is the first version that is actually installable.
- **No npm package was previously published**, so there is nothing to deprecate on npm. `@eidetic-labs/stigmem-ts@0.9.0-alpha.1` is the **first** npm release of the TypeScript SDK; it ships in PR 0 alongside the PyPI release.

### Stability commitment

`v0.9.0a1` carries **no stability guarantee**. Wire format, public Python API, and SDK contracts may change during the `v0.9.0aN` alpha and `v0.9.0bN` beta series hardening windows. Stability commitments begin at `v1.0.0` GA, after a 30-day external-operator soak per [ADR-001](docs/adr/001-versioning.md). Pin to specific pre-release versions; auto-upgrade is not safe.

### Current state after v0.9.0a1

The following changes have landed on `main` after the v0.9.0a1 first build and are queued for the next alpha release:

- **Plugin registry foundation.** Core now has the 22-hook registry foundation required by ADR-011. Remaining plugin infrastructure work includes package discovery, dependency lifecycle, health polling, operator CLI, production signing/trust, plugin author/operator documentation, and full plugin migration lifecycle/checksum tracking.
- **Deferred-feature extraction path.** The next alpha releases continue the C1 plugin architecture: lazy instruction discovery first, then time-travel, tombstones, memory-garden advanced ACL, source attestation, and multi-tenant isolation. CIDs remain core per ADR-011.
- **Large-file refactors.** The major `cli.py`, federation-route, and facts-route split work has landed on `main`; it is no longer a blocker for the next alpha.
- **Quality ratchets.** Lint-baseline tightening, coverage lift, and complexity cleanup remain active quality-improvement tracks for the alpha series.
- **Published-artifact follow-ups.** The TypeScript SDK README, npm dist-tag convention, ClawHub skill naming/versioning notes, GHCR `latest` tag policy, Python SDK version literal, and `stigmem-node` wheel migration packaging fix are all tracked for pickup in the next alpha artifacts where applicable. The v0.9.0a1 registry artifacts themselves remain immutable.

---

## Historical development checkpoints (preserved as record, not prior releases)

The entries below labeled `v0.2` through `v2.0` and `1.0.0-rc` documented internal development checkpoints. They are preserved here as the development record. Per [ADR-001](docs/adr/001-versioning.md) and [ADR-001](docs/adr/001-versioning.md), the canonical version line of stigmem begins at `v0.9.0a1` above.

---

## [2.0.0] — 2026-05-05

**Spec:** [v2.0](spec/stigmem-spec-v2.0.md) — §19–§25 promoted to normative.

### Added

- **Federation trust (§19)** — org manifest signing (Ed25519 + RFC 8785 JCS), transparency log integration (Rekor), capability tokens with 6 verbs and 90-day expiry, source-trust scoring, quarantine garden, recall-time content sanitizer.
- **Recall & graph (§20)** — materialized `entity_edges` graph index, vector embeddings via `sqlite-vec` (nomic-embed-text-v1.5 default, 768-dim), hybrid recall pipeline (BM25 + ANN + graph BFS + MMR packing), memory cards (per-entity 4000-token summaries), subscriptions with webhook delivery, causal/derivation links (`derived_from` DAG).
- **Lazy instruction discovery (§21)** — boot stub (≤500 tokens), instruction manifest (≤1000 tokens), `recall_instruction` tool contract, task-type preloads with `guarantee_load`, discovery audit (Recall@k, Hit@k, miss-rate), 5-stage file → stigmem migration, `stigmem instruction migrate` CLI.
- **Security hardening (§22)** — mTLS federation transport (TLS 1.3 floor), Ed25519 key rotation (90-day dual-trust period), structured audit log (13 event types, write-ahead, 90-day retention), per-principal token-bucket quotas (7 dimensions, HTTP 429), replay protection (±5 min window + nonce cache), container baseline (distroless, non-root, seccomp).
- **RTBF tombstones (§23)** — `TombstoneRecord` shape with signed `entity_uri` + scope suppression, recall-time filter (direct + graph reference + memory card), federation propagation with signature verification, `TombstoneRevocation` for legal holds, `GET /v1/federation/tombstones` poll route.
- **Time-travel queries (§24)** — `as_of` parameter on `/v1/recall` and `/v1/facts`, fact visibility at time T, append-only `fact_retractions` log, retroactive tombstone suppression, `legal_hold: true` preserves facts for admin `as_of` access, `tombstone_notices` response annotation.
- **Content-addressed fact IDs (§25)** — CID format (`sha256:` + hex SHA-256 of RFC 8785 canonical body over 6 fields), `fact_cid_aliases` table for dual UUID/CID addressing, 12-month migration window, federation tamper detection (`cid_mismatch` rejection), `stigmem backfill-cids` CLI, `POST /v1/facts/:id/verify-cid` integrity check.
- **Storage backend trait (pre-reset)** — `StorageBackend` abstraction, `LibSQLBackend` for Turso/libSQL embedded-replica, `STIGMEM_STORAGE_BACKEND` env var, backend-parameterized test runner.
- **Conformance vectors** — v2.0 wire-format vectors for §19–§25 in `data/conformance/v2.0/`.
- **Migration guide** — `docs/docs/migration/v1-to-v2.md` with breaking-change matrices, cutover order, and rollback notes.

### Changed

- OpenAPI spec version bumped to 2.0.0.
- `FactRecord` extended with `cid`, `derived_from`, `attestation_chain`, `source_trust` fields.
- Retraction semantics: `confidence = 0.0` in-place retained for live-query compat; authoritative retraction timestamp now in `fact_retractions` table.
- Documentation site information architecture restructured for §19–§25 content.

### Migration

- **013a** — `tombstones` + `tombstone_revocations` tables.
- **013b** — `facts.cid` column + `fact_cid_aliases` table.
- **013c** — `fact_retractions` append-only log.
- Apply order: 013a → 013c → 013b (foreign-key dependencies).
- Run `stigmem backfill-cids` after migrations to populate CIDs for pre-v2.0 facts.

### Breaking

- Federation requires mTLS (TLS 1.3+) and org manifests — plaintext peer connections rejected.
- Mixed v1.x/v2.0 federation is not supported; all peers must upgrade together.
- `STIGMEM_EMBED_DIMENSIONS` is immutable after first embedding write; changing requires full re-index.
- Graph depth capped at 3 (`depth > 3` returns HTTP 400 `graph_depth_exceeded`).

---

## [Unreleased — pre-reset] — Instruction migration + lazy instruction discovery (§21)

### Added

- **`stigmem instruction migrate` CLI** — converts markdown instruction files into atomic
  `instruction:content` facts and publishes a lazy-loaded manifest.  Supports `--role` and
  `--skill` scope selectors, `--dry-run`, `--yes`, and `--db` for local idempotency checks.
- **Instruction manifest API** (`PUT /v1/agents/{agent_id}/instruction-manifest`) — stores
  a versioned manifest of instruction units with load triggers (intents, keywords, task types)
  and token estimates.  Each publish supersedes the previous manifest rather than updating
  it in place.
- **`recall-instruction` endpoint** (`POST /v1/agents/{agent_id}/recall-instruction`) —
  three-phase lazy retrieval: hint resolution → BM25-ranked retrieval → guaranteed units.
  Returns a token-budget-bounded list of instruction chunks with an `audit_token` for
  downstream usage logging.
- **Discovery audit** — `POST /v1/instruction/audit` closes the audit loop; the
  `instruction_audit` table records agent, intent, loaded/used/missed chunks per recall call.
- **`stigmem audit discovery` CLI** — prints Recall@k, Hit@k, and miss-rate metrics for an
  agent from the local `instruction_audit` table.
- **Tombstone semantics** — units removed between migration runs receive `TOMBSTONE` action;
  their manifest entries are dropped while the underlying facts are preserved for audit history.
- **Docs** — Instruction Migration guide (`docs/docs/guides/instruction-migration.md`);
  lazy-instruction endpoint reference in `docs/docs/api-reference/index.md`.

---

## [Unreleased — pre-reset] — Storage adapter trait + libSQL/Turso backend

### Added

- **`StorageBackend` trait** (`node/src/stigmem_node/storage/`) — abstract seam
  covering connection lifecycle, transaction semantics, migration runner, and
  snapshot export/import hooks.  All new persistence backends implement this
  interface; no changes required in route handlers.
- **`SQLiteBackend`** — existing SQLite path refactored to implement
  `StorageBackend`.  Behaviour is identical to pre-trait deployments.
- **`LibSQLBackend`** — libSQL / Turso adapter implementing the trait.
  Supports embedded-replica mode (local file + Turso sync URL).  Drop-in for
  Fly.io persistent volumes.
- **`STIGMEM_STORAGE_BACKEND`** env var — `"sqlite"` (default) or `"libsql"`.
- **`STIGMEM_LIBSQL_URL`** — Turso database endpoint
  (e.g. `libsql://my-db.turso.io`).  Required when backend is `libsql`.
- **`STIGMEM_LIBSQL_AUTH_TOKEN`** — Turso auth token (from
  `turso db tokens create`).
- **`libsql` optional dependency group** — `pip install 'stigmem-node[libsql]'`
  installs `libsql-experimental>=0.3`.
- **Backend-parameterized test runner** — `pytest --backend=libsql` runs the
  full conformance suite against the libSQL backend.  Tests auto-skip when
  `libsql-experimental` is not installed.

### Changed

- `db.py` — `db()`, `apply_migrations()`, `get_or_create_federation_keypair()`,
  and `get_or_create_node_id()` all delegate to `make_backend()`.  The module-
  level `settings` attribute is still the patch point for test fixtures.

### Migration

- No schema changes.  Existing SQLite databases continue to work without any
  action.  To switch to Turso, set `STIGMEM_STORAGE_BACKEND=libsql`,
  `STIGMEM_LIBSQL_URL`, and `STIGMEM_LIBSQL_AUTH_TOKEN`, then run
  `stigmem migrate` to apply pending migrations against the new backend.

---

## [1.0.0-rc] — 2026-05-03

**Spec:** v1.0 stable (see [spec/CHANGELOG.md](spec/CHANGELOG.md#v10--2026-05-03--stable))

### Added

- **Multi-tenant scoping** — `tenant_id` column on facts + indexes; `X-Stigmem-Tenant` header enforced on all write/read routes; tenant-isolated query path (`?scope=tenant:…`).
- **Billing hooks** — `POST /v1/admin/billing/events` webhook emitter; `BillingEventKind` registry (`fact_assert`, `garden_read`, `synthesis_run`); configurable endpoint + HMAC secret via `STIGMEM_BILLING_*` env vars.
- **Memory Garden** (§17 stable) — Named ACL'd partitions; `garden_id` on `FactRecord`; admin/writer/reader role model; ACL enforced at read time.
- **Source Attestation** (§18 stable) — `entity_uri` binding on API keys; three enforcement modes (`enforce|warn|off`); `attested` field on `FactRecord`; attestation audit log (`GET /v1/auth/audit`).
- **Agent keypairs** — Ed25519 key generation via `POST /v1/auth/keys`; key rotation and revocation endpoints.
- **OIDC SSO role gate** — `STIGMEM_OIDC_*` env vars; JWT validation middleware; role-claim mapping to `admin|writer|reader`.
- **Curator dashboard** — Next.js 14 single-page app at `apps/dashboard`; fact browser, garden manager, audit log viewer.
- **Five connector adapters** — Letta, Gemini, OpenAI-tools, Cognee, and Zep adapters under `adapters/`; each ships its own `pyproject.toml` for isolated installs.
- **MCP adapter** (`adapters/mcp`) — `assert_fact`, `query_facts`, `synthesize_scope`, `lint_scope`, `decay_scope` tools; transport-agnostic; versioned at `1.0.0-rc`.
- **Conformance CI gate** — `conformance.yml` workflow; runs the full v1.0 vector suite on every push to `main` and on PRs touching `node/`, `spec/`, `data/conformance/`; zero skips enforced.
- **Docker Compose one-click install** — `docker-compose.yml` with node + Postgres; `make up` / `make down` targets; health-check probe.
- **Helm chart stub** — `charts/stigmem/` with `values.yaml`, `Chart.yaml`, and node deployment template; installable via `helm install`.
- **Docusaurus 3 documentation site** (`docs/`) — Getting Started, Concepts, API Reference (OpenAPI), Architecture diagrams, Federation tutorial, Deployment guide, Conformance guide, Security posture page, v1.0 upgrade guide.
- **Decay Semantics** (§15) and **Synthesis** (§16) — `POST /v1/decay/sweep`, `POST /v1/synthesis`; MCP tools; already stable in v0.9, now documented end-to-end.
- **Lint API** (§14) — `POST /v1/lint`; four lint checks; `lint_scope` MCP tool.
- **Fuzzy entity resolver** (§2.6.6) — semantic alias matching on entity lookup.
- **Async lint/decay job APIs** (§14.5/§15.4) — background job handles with `GET /v1/jobs/:id`.

### Changed

- Spec promoted from v0.9-draft to **v1.0 stable**; all §§1–18 normative.
- `IntentEnvelope` (§4) deferred indefinitely; retained as non-normative appendix.
- Example URIs normalized to `company.example` domain across all test fixtures.
- Per-adapter `pyproject.toml` added for unified pytest discovery.

### Security

- All Python dependencies upgraded; `pip-audit` reports zero known CVEs.
- All TypeScript/Node dependencies upgraded; `npm audit` reports zero vulnerabilities.
- Zero unaddressed Dependabot alerts on the `main` branch.
- Security posture statement published at `docs/docs/reference/security.md`.
- `bandit` static analysis clean on the `node/` package.

### Migration

- Run migration 004 (gardens table) and migration 005 (api_keys extension + attestation_audit) before starting the node. Both are idempotent.
- Set `STIGMEM_TENANT_HEADER_REQUIRED=true` if you want tenant isolation enforced at the ingress layer.
- See the [v1.0 upgrade guide](docs/docs/getting-started/upgrade-v1.md) for the full migration checklist.

---

## [0.9.0] — 2026-04

**Spec:** v0.9-draft

### Added

- Memory Garden primitive (`OIDC exchange bridge`; `garden_id` on facts; garden CRUD routes §5.14–§5.19).
- Source Attestation draft (`entity_uri` on API keys; `attested` field; enforcement modes draft).
- Scope propagation invariants (§6.8): `company`-scoped facts MUST NOT be re-federated.
- N-node backpressure header `X-Stigmem-Replication-Lag` (§6.7).

---

## [0.8.0] — 2026-03

**Spec:** v0.8 stable

### Added

- Decay Semantics (§15): `POST /v1/decay/sweep`; configurable TTL + confidence-decay policies; `DecayPolicy` registry.
- Synthesis (§16): `POST /v1/synthesis`; confidence-weighted snapshot.
- §§1–14 promoted to stable.

---

## [0.4.0] — 2025-11

**Spec:** v0.4

### Added

- Federation protocol (§6): two-node federation, HLC replication, Ed25519 peer tokens.
- Lint API (§14): `POST /v1/lint`; four lint checks.
- Per-scope API key restrictions.
- `PATCH /v1/facts/:id/confidence` retraction; `GET /v1/facts/:id` single-fact route.

---

## [0.2.0] — 2025-09

**Spec:** v0.2 initial

### Added

- Atomic fact shape: `(entity, relation, value, source, confidence, scope, timestamp, valid_until?)`.
- `text` FactValue type.
- Reification pattern (`stigmem:rel:` prefix).
- Federation stub (RFC only).
- API key auth stub.
