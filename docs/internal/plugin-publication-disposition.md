# Plugin Publication Disposition

**Status:** active maintainer tracker
**Applies to:** adapter, tooling, dashboard, evaluation, and deployment helper
surfaces considered during the plugin publication readiness track
**Last updated:** 2026-05-25

This tracker classifies non-security-sensitive adapter and tooling surfaces for
the plugin publication readiness milestone. It does not publish artifacts,
create package promises, or graduate any feature under ADR-008.

> **Note:** This disposition table classifies adapter, tooling, dashboard,
> evaluation, and deployment surfaces. The six security-sensitive plugins
> (`source-attestation`, `multi-tenant`, `memory-garden-acl`, `tombstones`,
> `time-travel`, and `lazy-instruction-discovery`) are the primary publication
> queue and are tracked separately in
> [`plugin-publication-dry-run.md`](plugin-publication-dry-run.md). Both tracks
> must complete before any first publication clearance.

## Disposition Rules

| Disposition | Meaning | Registry action |
| --- | --- | --- |
| `published` | Meets the plugin publication contract, has maintainer clearance, and has completed the approved registry action. | Keep post-publication evidence current; future versions follow the recorded release workflow. |
| `publish-now` | Meets the plugin publication contract and has maintainer clearance. | May move to Goal 5 dry-run and publication clearance. |
| `hold` | Real implementation/package surface exists, but release-line validation is incomplete. | Do not publish until the named gaps close. |
| `internal` | Real implementation exists as internal repo tooling, not a standalone plugin/package publication target for the active track. | Keep validation evidence current; do not publish in this milestone. |
| `defer` | Not a standalone plugin publication target for the active track. | Do not publish in this milestone. |

The MCP adapter is classified as `published` after maintainer clearance,
scoped npm publication, and post-publish install verification for the
independent `0.1.0` version line. Cognee, Gemini, Letta, OpenAI Tools, and Zep
are classified as `published` for the v0.9.0a10 adapter batch after package
metadata, feature records, and mocked adapter validation were brought into the
publication contract. Other adapter, tooling, dashboard, evaluation, and
deployment helper surfaces remain outside the publication queue until their own
publication PRs land.

## Adapter and Tooling Order

| Order | Surface | Feature record | Implementation | Disposition | Missing validation before publication |
| --- | --- | --- | --- | --- | --- |
| 1 | MCP adapter | `features/mcp-adapter/` | `adapters/mcp/`; `experimental/mcp-adapter/` connector guides | `published` | Scoped npm package `@eidetic-labs/stigmem-mcp@0.1.0`; package metadata, live protocol smoke, adapter security regressions, dry-run evidence, Codex CLI / Claude Code host UI smoke, Gemini CLI smoke with caveat, maintainer clearance, registry publication, and post-publish install verification are complete. Continue.dev, Cursor, and Zed remain experimental/unvalidated connector guides, not publication blockers for `0.1.0`. Future versions use `.github/workflows/mcp-publish.yml` with npm Trusted Publisher/OIDC. |
| 2 | Obsidian adapter | `features/obsidian-adapter/` | `experimental/obsidian-adapter/cli/`; `experimental/obsidian-adapter/plugin/` | `hold` | Validate CLI package and Obsidian plugin packaging; run live-vault sync smoke; review key-storage guidance; decide registry/channel ownership. |
| 3 | Cognee adapter | `features/cognee-adapter/` | `experimental/cognee-adapter/` | `published` | `stigmem-plugin-cognee-adapter@0.1.0` package metadata, src-layout package, plugin manifest, README/install/uninstall guidance, security record, feature evidence, and mocked adapter tests are complete for the v0.9.0a10 adapter batch. Live Cognee runtime validation remains design-partner/operator-owned for v0.1.0. |
| 4 | Letta adapter | `features/letta-adapter/` | `experimental/letta-adapter/` | `published` | `stigmem-plugin-letta-adapter@0.1.0` package metadata, src-layout package, plugin manifest, README/install/uninstall guidance, security record, feature evidence, and mocked adapter tests are complete for the v0.9.0a10 adapter batch. Live Letta server validation remains design-partner/operator-owned for v0.1.0. |
| 5 | Zep adapter | `features/zep-adapter/` | `experimental/zep-adapter/` | `published` | `stigmem-plugin-zep-adapter@0.1.0` package metadata, src-layout package, plugin manifest, README/install/uninstall guidance, security record, feature evidence, and mocked adapter tests are complete for the v0.9.0a10 adapter batch. Live Zep Cloud/self-hosted validation remains design-partner/operator-owned for v0.1.0. |
| 6 | Gemini adapter | `features/gemini-adapter/` | `experimental/gemini-adapter/` | `published` | `stigmem-plugin-gemini-adapter@0.1.0` package metadata, src-layout package, plugin manifest, README/install/uninstall guidance, security record, feature evidence, and mocked adapter tests are complete for the v0.9.0a10 adapter batch. Live Gemini API/model validation remains design-partner/operator-owned for v0.1.0. |
| 7 | OpenAI-compatible tools adapter | `features/openai-tools-adapter/` | `experimental/openai-tools-adapter/` | `published` | `stigmem-plugin-openai-tools-adapter@0.1.0` package metadata, src-layout package, plugin manifest, README/install/uninstall guidance, security record, feature evidence, and mocked adapter tests are complete for the v0.9.0a10 adapter batch. Live LiteLLM, OpenAI SDK, and local Ollama validation remains design-partner/operator-owned for v0.1.0. |
| 8 | Paperclip adapter | `features/paperclip-adapter/` | `experimental/paperclip-adapter/` | `defer` | Define an install artifact; add automated tests; run live Paperclip validation; review delegated-agent write policy and credential scope. |

## Non-Plugin Tooling and Deployment Surfaces

| Surface | Feature record | Implementation | Disposition | Reason |
| --- | --- | --- | --- | --- |
| Dashboard | `features/dashboard/` | `experimental/dashboard/` | `defer` | Internal/deployment surface, not a standalone plugin artifact; live-node, auth/session, dependency, and deployment posture gates remain open. |
| Evaluation harness | `features/eval-harness/` | `eval/` | `internal` | Active internal evaluation tooling for the a11 foundation lane; not a standalone plugin/package publication target yet. |
| Fly.io deployment helper | `features/deploy-fly/` | `experimental/deploy-fly/` | `defer` | Deployment recipe, not plugin artifact; live deployment, persistence/restore, secrets, and dashboard validation remain open. |
| PaaS deployment helper | `features/deploy-paas/` | `experimental/deploy-paas/` | `defer` | Deployment recipes, not plugin artifacts; live platform, persistence, secrets, scaling, and cost validation remain open. |
| systemd deployment helper | `features/deploy-systemd/` | `experimental/deploy-systemd/` | `defer` | Deployment helper, not plugin artifact; live distro, hardening, upgrade/rollback, and offline-install validation remain open. |
| Helm deployment helper | `features/deploy-helm/` | `experimental/deploy-helm/` | `defer` | Deployment chart, not plugin artifact; chart publication, live cluster, hardening, and upgrade validation remain open. |
| Grafana deployment helper | `features/deploy-grafana/` | `experimental/deploy-grafana/` | `defer` | Observability seed material, not plugin artifact; live stack, metric contract, alert review, and packaging guidance remain open. |

## Goal 5 Inputs

Only `hold` surfaces may be reconsidered in Goal 5 after a follow-up PR closes
their missing validation. A surface may move from `hold` to `publish-now` only
when its feature record records:

- package metadata and registry/channel ownership
- install and uninstall instructions
- live integration smoke evidence
- security review for credentials, host integration, and write surfaces
- maintainer clearance for a specific registry action

Deferred surfaces remain discoverable in feature records and public
experimental docs, but they are not part of the active publication queue.
