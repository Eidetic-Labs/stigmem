# Feature Record Migration Inventory

This inventory tracks the ADR-020 migration from legacy feature documentation
to canonical feature records under `features/<feature-slug>/`.

It is an operational migration control document, not a second feature dossier.
Rows identify where feature truth lives today, where the feature record will
live, and which release horizon should drive migration order. Once a feature is
marked `migrated`, the feature record owns feature detail and legacy paths must
act only as wrappers, compatibility projections, or implementation directories.

## Public Surfaces

| Surface | Purpose |
| --- | --- |
| [`docs/docs/concepts/features.md`](../docs/concepts/features.md) | Public feature matrix and supported/default-surface summary. |
| [`docs/docs/reference/experimental-features.md`](../docs/reference/experimental-features.md) | Public index of deferred and experimental surfaces. |
| [`experimental/README.md`](../../experimental/README.md) | Repo-level implementation index for experimental directories. |
| [`features/README.md`](../../features/README.md) | Feature record contract and metadata rules. |

## Migration Status Values

| Status | Meaning |
| --- | --- |
| `migrated` | Complete six-file feature record exists and owns feature detail. |
| `pending` | Legacy docs remain the owner until a feature record PR migrates the row. |
| `deferred` | Feature record is not planned for the active alpha horizon. |
| `superseded` | Legacy feature family is intentionally retired or replaced. |

## Feature Record Migration Inventory

| Feature ID | Feature | Type | Stability | Default surface | Canonical spec | Legacy owner | Target record | Migration status | Horizon | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `content-addressed-ids` | Content-addressed fact IDs | `core` | `stable` | `default` | `Spec-21-Content-Addressed-IDs` | `spec/specs/21-content-addressed-ids.md` | `features/content-addressed-ids/` | `migrated` | `v0.9.0a3` | Pilot core feature record. Legacy spec path is a compatibility projection. |
| `time-travel` | Time-travel queries | `plugin` | `experimental` | `opt-in` | `Spec-X3-Time-Travel-Queries` | `experimental/time-travel/` | `features/time-travel/` | `migrated` | `v0.9.0a4` | Pilot plugin-backed feature record. Implementation remains under `experimental/time-travel/`. |
| `lazy-instruction-discovery` | Lazy instruction discovery | `plugin` | `experimental` | `opt-in` | `Spec-X1-Lazy-Instruction-Discovery` | `experimental/lazy-instruction-discovery/` | `features/lazy-instruction-discovery/` | `migrated` | `0.9.xA` | Security-sensitive migration preserves R-15 ownership and R-21 contribution. |
| `tombstones` | RTBF tombstones | `plugin` | `experimental` | `opt-in` | `Spec-X2-RTBF-Tombstones` | `experimental/tombstones/` | `features/tombstones/` | `migrated` | `0.9.xA` | Security-sensitive migration preserves R-16/R-17 ownership. |
| `memory-garden-acl` | Memory Garden advanced ACL | `plugin` | `experimental` | `opt-in` | `Spec-X5-Memory-Garden-Advanced-ACL` | `experimental/memory-garden-acl/` | `features/memory-garden-acl/` | `migrated` | `0.9.xA` | Protocol-bearing experimental plugin candidate. |
| `source-attestation` | Source attestation | `plugin` | `experimental` | `opt-in` | `Spec-X6-Source-Attestation` | `experimental/source-attestation/` | `features/source-attestation/` | `migrated` | `0.9.xA` | Security and release-supply-chain references preserved through R-22 contribution. |
| `subscriptions` | Subscriptions | `protocol` | `experimental` | `opt-in` | `Spec-X7-Subscriptions` | `experimental/subscriptions/` | `features/subscriptions/` | `migrated` | `0.9.xA` | Protocol-bearing experimental feature. |
| `intent-envelope` | Intent envelope | `protocol` | `experimental` | `opt-in` | `Spec-X8-Intent-Envelope` | `experimental/intent-envelope/` | `features/intent-envelope/` | `migrated` | `0.9.xA` | Protocol-bearing experimental feature. |
| `decay` | Decay semantics | `protocol` | `experimental` | `opt-in` | `Spec-X9-Decay-Semantics` | `experimental/decay/` | `features/decay/` | `migrated` | `0.9.xA` | Protocol-bearing experimental feature. |
| `synthesis` | Synthesis | `protocol` | `experimental` | `opt-in` | `Spec-X10-Synthesis` | `experimental/synthesis/` | `features/synthesis/` | `migrated` | `0.9.xA` | Protocol-bearing experimental feature. |
| `recall-graph` | Recall graph | `protocol` | `experimental` | `opt-in` | `Spec-X11-Recall-Graph` | `experimental/recall-graph/` | `features/recall-graph/` | `migrated` | `0.9.xA` | Protocol-bearing experimental feature. |
| `multi-tenant` | Multi-tenant scoping | `plugin` | `experimental` | `opt-in` | `none` | `experimental/multi-tenant/` | `features/multi-tenant/` | `migrated` | `0.9.xA` | Security-contributing cross-cutting feature; assign spec only if protocol work reopens. |
| `async-jobs` | Async jobs | `core` | `experimental` | `opt-in` | `none` | `experimental/async-jobs/` | `features/async-jobs/` | `migrated` | `future alpha` | No Spec-X assigned; feature record owns shared job lifecycle detail. |
| `fuzzy-resolver` | Fuzzy resolver | `core` | `experimental` | `opt-in` | `none` | `experimental/fuzzy-resolver/` | `features/fuzzy-resolver/` | `migrated` | `future alpha` | No Spec-X assigned; feature record owns resolver detail. |
| `oidc-sso` | OIDC SSO | `core` | `experimental` | `opt-in` | `none` | `experimental/oidc-sso/` | `features/oidc-sso/` | `migrated` | `future alpha` | No Spec-X assigned; feature record owns OIDC exchange detail. |
| `billing` | Billing | `core` | `experimental` | `opt-in` | `none` | `experimental/billing/` | `features/billing/` | `deferred` | `future gate` | Business feature outside active alpha release scope. |
| `storage-backends` | Storage backends | `adapter` | `experimental` | `opt-in` | `none` | `experimental/storage-backends/` | `features/storage-backends/` | `migrated` | `future alpha` | Storage-family parent row; feature record owns backend-selection detail. |
| `storage-libsql` | libSQL storage | `adapter` | `experimental` | `opt-in` | `none` | `experimental/storage-libsql/` | `features/storage-libsql/` | `migrated` | `future alpha` | Adapter-specific storage feature. |
| `mcp-adapter` | MCP adapter | `adapter` | `experimental` | `external` | `none` | `experimental/mcp-adapter/` | `features/mcp-adapter/` | `migrated` | `future alpha` | Adapter surface. |
| `sdk-go` | Go SDK | `sdk` | `experimental` | `external` | `none` | `experimental/sdk-go/` | `features/sdk-go/` | `migrated` | `future alpha` | SDK surface. |
| `obsidian-adapter` | Obsidian adapter | `adapter` | `experimental` | `external` | `none` | `experimental/obsidian-adapter/` | `features/obsidian-adapter/` | `migrated` | `future alpha` | Adapter surface. |
| `cognee-adapter` | Cognee adapter | `adapter` | `experimental` | `opt-in` | `none` | `experimental/cognee-adapter/` | `features/cognee-adapter/` | `migrated` | `v0.9.0a10` | Adapter surface packaged as an opt-in plugin. |
| `letta-adapter` | Letta adapter | `adapter` | `experimental` | `opt-in` | `Spec-X7-Letta-Adapter` | `experimental/letta-adapter/` | `features/letta-adapter/` | `migrated` | `v0.9.0a10` | Adapter surface packaged as an opt-in plugin. |
| `zep-adapter` | Zep adapter | `adapter` | `experimental` | `opt-in` | `Spec-X7-Zep-Adapter` | `experimental/zep-adapter/` | `features/zep-adapter/` | `migrated` | `v0.9.0a10` | Adapter surface packaged as an opt-in plugin. |
| `gemini-adapter` | Gemini adapter | `adapter` | `experimental` | `opt-in` | `Spec-X7-Gemini-Adapter` | `experimental/gemini-adapter/` | `features/gemini-adapter/` | `migrated` | `v0.9.0a10` | Adapter surface packaged as an opt-in plugin. |
| `ollama-litellm-adapter` | Ollama/LiteLLM adapter | `adapter` | `experimental` | `external` | `none` | `experimental/ollama-litellm-adapter/` | `features/ollama-litellm-adapter/` | `migrated` | `future alpha` | Compatibility identity for OpenAI-compatible tools adapter. |
| `openai-tools-adapter` | OpenAI tools adapter | `adapter` | `experimental` | `opt-in` | `Spec-X7-OpenAI-Tools-Adapter` | `experimental/openai-tools-adapter/` | `features/openai-tools-adapter/` | `migrated` | `v0.9.0a10` | OpenAI-compatible tool-use adapter packaged as an opt-in plugin. |
| `paperclip-adapter` | Paperclip adapter | `adapter` | `experimental` | `external` | `none` | `experimental/paperclip-adapter/` | `features/paperclip-adapter/` | `migrated` | `future alpha` | Lifecycle/event adapter; live Paperclip validation remains future alpha work. |
| `dashboard` | Dashboard | `tooling` | `experimental` | `internal` | `none` | `experimental/dashboard/` | `features/dashboard/` | `migrated` | `future alpha` | Curator UI/tooling surface; live-node validation remains future alpha work. |
| `eval-harness` | Evaluation harness | `tooling` | `experimental` | `internal` | `none` | `experimental/eval-harness/` | `features/eval-harness/` | `migrated` | `v0.9.0a11` | Active internal evaluation tooling lives under `eval/`; the legacy concept directory remains a compatibility pointer, and standalone package publication remains deferred. |
| `deploy-helm` | Helm deployment | `deployment` | `experimental` | `external` | `none` | `experimental/deploy-helm/` | `features/deploy-helm/` | `migrated` | `future alpha` | Kubernetes deployment recipe; live cluster validation remains future alpha work. |
| `deploy-fly` | Fly.io deployment | `deployment` | `experimental` | `external` | `none` | `experimental/deploy-fly/` | `features/deploy-fly/` | `migrated` | `future alpha` | Fly.io deployment recipe; live deployment, persistence, dashboard validation, and ownership remain future alpha work. |
| `deploy-grafana` | Grafana deployment | `deployment` | `experimental` | `external` | `none` | `experimental/deploy-grafana/` | `features/deploy-grafana/` | `migrated` | `future alpha` | Observability deployment seed; live stack validation, metric review, alert review, packaging, and ownership remain future alpha work. |
| `deploy-paas` | PaaS deployment | `deployment` | `experimental` | `external` | `none` | `experimental/deploy-paas/` | `features/deploy-paas/` | `migrated` | `future alpha` | Managed-platform deployment recipes; live platform validation, persistence, secrets, scaling/cost review, and ownership remain future alpha work. |
| `deploy-systemd` | systemd deployment | `deployment` | `experimental` | `external` | `none` | `experimental/deploy-systemd/` | `features/deploy-systemd/` | `migrated` | `future alpha` | Bare-metal deployment recipe; live distro validation, installer review, hardening review, upgrade/rollback, offline install, and ownership remain future alpha work. |

## Maintenance Rules

- Do not add feature behavior, security analysis, or release-note detail to this
  inventory. Put that material in the feature record once migrated.
- Keep `Migration status` accurate when a feature record PR lands.
- `migrated` rows must point to a real `features/<feature-slug>/` directory and
  pass `scripts/check_feature_records.py`.
- `pending` rows identify the current legacy owner until migration.
- `deferred` rows remain visible so future-horizon work is not lost.
- Public docs may summarize feature status, but this inventory remains internal.
