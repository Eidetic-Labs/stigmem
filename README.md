# Stigmem - Federated Knowledge Fabric + Intent Protocol

[![CI](https://github.com/eidetic-labs/stigmem/actions/workflows/ci.yml/badge.svg)](https://github.com/eidetic-labs/stigmem/actions/workflows/ci.yml)
[![Conformance](https://github.com/eidetic-labs/stigmem/actions/workflows/conformance.yml/badge.svg)](https://github.com/eidetic-labs/stigmem/actions/workflows/conformance.yml)
[![Coverage](https://stigmem.dev/coverage-badge.svg)](https://stigmem.dev/coverage/)
[![PyPI version](https://img.shields.io/pypi/v/stigmem?include_prereleases&label=pypi)](https://pypi.org/project/stigmem/)
[![npm version](https://img.shields.io/npm/v/@eidetic-labs/stigmem-mcp/alpha?label=npm%3A%40eidetic-labs%2Fstigmem-mcp)](https://www.npmjs.com/package/@eidetic-labs/stigmem-mcp)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Discord](https://img.shields.io/discord/1502847943118684331?label=discord&logo=discord&logoColor=white&color=5865F2)](https://discord.gg/Z47Re7FjjV)

> **Status: `v0.9.0a12` - Apache-2.0**
> **Repository:** [github.com/eidetic-labs/stigmem](https://github.com/eidetic-labs/stigmem)
> **Single-org, single-node, audit-first memory.** Cross-organizational federation is on the roadmap. See [LIMITATIONS.md](LIMITATIONS.md) for current scope.

Stigmem is the shared, persistent layer where AI agents and humans write typed,
traceable facts that travel across tools, platforms, and organizations. Every
fact is an immutable record: `(entity, relation, value, source, timestamp,
confidence, scope)`, with full provenance, a hybrid logical clock timestamp,
and a defined expiry. Nodes peer via a signed handshake; facts replicate under
explicit scope permission; contradictions surface as first-class records, not
silent overwrites. Stigmem is audit-first: the guarantee is not that an agent
will do the right thing, but that every fact it asserted is attributable,
replayable, and revocable.

---

> Pre-1.0: the wire format and public APIs may change between releases. Pin to a specific version.

## Quickstart - 60 seconds to a running node

```bash
# 1. Pull and start signed multi-arch images from GHCR.
git clone https://github.com/eidetic-labs/stigmem && cd stigmem
docker compose up -d

# 2. Assert a fact.
curl -s -X POST http://localhost:8765/v1/facts \
  -H 'Content-Type: application/json' \
  -d '{"entity":"user:alice","relation":"memory:prefers",
       "value":{"type":"string","v":"dark mode"},
       "source":"agent:settings","confidence":1.0,"scope":"company"}' | jq .

# 3. Recall it.
curl -s 'http://localhost:8765/v1/facts?entity=user:alice&scope=company' | jq .facts
```

`docker compose up` brings up two federated nodes (`node-a` on 8765, `node-b`
on 8766) so you can run federation handshakes immediately. The full
[two-node federation tutorial](docs/docs/get-started/quickstart-tutorial.md)
takes about 10 minutes and includes the PeerDeclaration handshake, scope
replication, adversarial demo, and post-tear-down inspection recipes.

## Install

### Docker (recommended)

```bash
git clone https://github.com/eidetic-labs/stigmem
cd stigmem
docker compose up -d
```

`docker compose up` pulls pre-built multi-arch images from GHCR
(`ghcr.io/eidetic-labs/stigmem-node:0.9.0a12`, signed via Sigstore cosign with
attached SBOMs). The recipe pins to the version tag for reproducibility; use
`docker compose up --build -d` when you are contributing local code changes.

Two federated nodes start immediately:

| Node | Host port | Interactive API | Node metadata |
| --- | --- | --- | --- |
| `node-a` | 8765 | `http://localhost:8765/docs` | `http://localhost:8765/.well-known/stigmem` |
| `node-b` | 8766 | `http://localhost:8766/docs` | `http://localhost:8766/.well-known/stigmem` |

Key environment variables (`STIGMEM_` prefix, set in `docker-compose.yml`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `STIGMEM_NODE_URL` | `http://localhost:8765` | Public URL included in PeerDeclarations |
| `STIGMEM_FEDERATION_ENABLED` | `false` | Enable pull replication |
| `STIGMEM_FEDERATION_PULL_INTERVAL_S` | `30` | Seconds between pull cycles |
| `STIGMEM_AUTH_REQUIRED` | `true` | Require Bearer token on every request. Set `false` for local dev only |
| `STIGMEM_DB_PATH` | `stigmem.db` | SQLite database path |

Full environment variable reference:
[Operating Stigmem - Install](docs/docs/operators/deployment/install.md).

### Python via uv

```bash
cd stigmem/node
uv run python -m stigmem_node
```

### Pre-release via pip

Because `v0.9.0a12` is a PEP 440 pre-release, `pip install stigmem` will not
pick it up by default. Use `--pre` and choose the scope:

```bash
pip install --pre stigmem                          # SDK only
pip install --pre stigmem[node]                    # SDK + reference node service
pip install --pre stigmem[openclaw]                # SDK + alpha adapter package
pip install --pre 'stigmem[adapters]'              # SDK + host-application adapters
pip install --pre 'stigmem[plugins-all]'           # SDK + every published plugin
pip install --pre stigmem[all]                     # everything published from this repo
```

Individual plugin extras: `stigmem[lazy-instruction-discovery]`,
`stigmem[memory-garden-acl]`, `stigmem[multi-tenant]`,
`stigmem[source-attestation]`, `stigmem[time-travel]`,
`stigmem[tombstones]`, `stigmem[cognee-adapter]`,
`stigmem[gemini-adapter]`, `stigmem[letta-adapter]`,
`stigmem[openai-tools-adapter]`, and `stigmem[zep-adapter]`.
Each is an independently versioned PyPI package (`stigmem-plugin-<name>`)
released under [ADR-011](docs/adr/011-plugin-independent-versioning.md).
Use `stigmem[adapters]` to install the five host-application adapter plugins
without the node behavior plugins.

The MCP server is a separate npm package:

```bash
npm install -g @eidetic-labs/stigmem-mcp
# or, ephemeral:
npx -y @eidetic-labs/stigmem-mcp@0.1.0
```

## Plugins

Eleven experimental plugins are published as independent PyPI packages
(`stigmem-plugin-<name>@0.1.0`). Installing makes a plugin discoverable through
the `stigmem.plugins` entry-point group. Node behavior plugins still require
their plugin-specific `STIGMEM_*_ENABLED` environment variable and a node
restart; adapter packages require host-application opt-in.

| Plugin | What it adds | Package / extra | Enable gate |
| --- | --- | --- | --- |
| Lazy instruction discovery | Boot context resolves instructions on demand | `stigmem-plugin-lazy-instruction-discovery` / `stigmem[lazy-instruction-discovery]` | `STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ENABLED` |
| Time travel | Historical handoff and decision queries | `stigmem-plugin-time-travel` / `stigmem[time-travel]` | `STIGMEM_TIME_TRAVEL_ENABLED` |
| Tombstones | Hides retracted facts from recall and boot context | `stigmem-plugin-tombstones` / `stigmem[tombstones]` | `STIGMEM_TOMBSTONES_ENABLED` |
| Memory Garden ACL | Membership controls which gardens boot reads | `stigmem-plugin-memory-garden-acl` / `stigmem[memory-garden-acl]` | `STIGMEM_MEMORY_GARDEN_ACL_ENABLED` |
| Source attestation | Recalled facts carry source trust scores | `stigmem-plugin-source-attestation` / `stigmem[source-attestation]` | `STIGMEM_SOURCE_ATTESTATION_ENABLED` |
| Multi-tenant scoping | Boot, handoff, decision, and escalation become tenant-scoped | `stigmem-plugin-multi-tenant` / `stigmem[multi-tenant]` | `STIGMEM_MULTI_TENANT_ENABLED` |
| Cognee adapter | Bridges selected facts into Cognee memory graphs | `stigmem-plugin-cognee-adapter` / `stigmem[cognee-adapter]` | Host-application opt-in |
| Gemini adapter | Exposes Stigmem tools as Gemini FunctionDeclarations | `stigmem-plugin-gemini-adapter` / `stigmem[gemini-adapter]` | Host-application opt-in |
| Letta adapter | Bridges selected facts into Letta archival memory | `stigmem-plugin-letta-adapter` / `stigmem[letta-adapter]` | Host-application opt-in |
| OpenAI tools adapter | Exposes Stigmem tools as OpenAI-compatible function calls | `stigmem-plugin-openai-tools-adapter` / `stigmem[openai-tools-adapter]` | Host-application opt-in |
| Zep adapter | Bridges selected facts into Zep session memory | `stigmem-plugin-zep-adapter` / `stigmem[zep-adapter]` | Host-application opt-in |
| Adapter bundle | Installs all five host-application adapter packages | `stigmem[adapters]` | Host-application opt-in |

Inspect local state with `stigmem plugins list`, `stigmem plugins describe
<plugin>`, and `stigmem plugins doctor`. Full catalog and per-plugin security
notes: [docs/docs/plugins](docs/docs/plugins/index.md).

## MCP + editor integrations

Stigmem ships an [MCP](https://modelcontextprotocol.io) server so LLM-aware
editors can read from and write to a Stigmem node directly from chat.

```bash
stigmem mcp doctor                    # check node + npm + npx availability
stigmem mcp detect                    # enumerate editor configs found locally
stigmem mcp config codex-cli          # print metadata + connector guide
stigmem mcp install codex-cli         # dry-run preview; credential omitted
stigmem mcp install codex-cli --write # write the editor config file
stigmem mcp smoke codex-cli           # round-trip handshake test
```

`stigmem mcp config <editor>` prints metadata and the connector guide link
only. `stigmem mcp install <editor>` defaults to a dry run and previews the
planned Stigmem server entry with the credential field omitted. Passing
`--write` applies the change with a timestamped backup.

| Editor | Validation tier | Connector guide |
| --- | --- | --- |
| Codex CLI | Validated | [docs/integrations/mcp/codex-cli](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/codex-cli) |
| Claude Code | Validated | [docs/integrations/mcp/claude-code](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/claude-code) |
| Gemini CLI | Caveated | [docs/integrations/mcp/gemini-cli](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/gemini-cli) |
| Continue.dev | Experimental | [docs/integrations/mcp/continue-dev](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/continue-dev) |
| Cursor | Experimental | [docs/integrations/mcp/cursor](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/cursor) |
| Zed | Experimental | [docs/integrations/mcp/zed](https://docs.stigmem.dev/en/latest/docs/integrations/mcp/zed) |

A running node also exposes `GET /v1/mcp/connectors` so editors and
provisioning tools can discover available connectors programmatically.

## Federation, briefly

```text
node-a -- PeerDeclaration, Ed25519-signed --> node-b
node-a <-- pull replication, scoped facts ----- node-b

Contradictions become first-class conflict records instead of silent overwrites.
```

Scope membership, replication direction, and conflict semantics are specified
in [`spec/05-federation-trust.md`](spec/05-federation-trust.md) and exercised
in CI by the conformance suite plus `make demo-attack`.

## Architecture

```text
stigmem/
├── spec/           <- canonical specification
├── node/           <- reference node: FastAPI + SQLite
├── adapters/       <- adapter packages, MCP server, ClawHub skill
├── sdks/           <- Python and TypeScript client SDKs
├── experimental/   <- plugin source trees + deferred features
└── docs/           <- Docusaurus 3 documentation site
```

Each plugin lives at `experimental/<plugin>/` as its own publishable package
and ships independently to PyPI under
[ADR-011](docs/adr/011-plugin-independent-versioning.md).

### Structural CI guards

The following invariants are mechanically enforced on PRs. Failures block merge:

| Guard | What it enforces |
| --- | --- |
| `check_admin_determination.py` | Admin-determination logic is consistent across routes |
| `check_tenant_resolution.py` | Tenant resolution wraps tenant-scoped reads and writes |
| `check_plugin_readme_sections.py` | Plugin READMEs have required publication sections |
| `check_plugin_manifest_version_consistency.py` | Plugin package version literals agree |
| `check_plugin_readme_pypi_consistency.py` | README, extras, and docs catalog agree on plugin packages |
| `check_mcp_readme_consistency.py` | MCP README, CLI catalog, docs, and `/v1/mcp/connectors` agree |
| `check_readme_shape.py` | Root README keeps this structure, plugin table, and MCP tiers aligned |

See [`scripts/`](scripts/) for the full guard set.

## Security posture

Stigmem is pre-stable; the design center is audit-first. Every fact written
through a Stigmem node is attributable to a source, replayable through the HLC
clock, and revocable through tombstones or a manual retract call. The guarantee
is integrity of the record trail, not soundness of the upstream agent's
reasoning.

Adopters should read these documents before integrating against the API:

- **[LIMITATIONS.md](LIMITATIONS.md)** - adopter-facing constraints and safe deployment patterns
- **[SECURITY.md](SECURITY.md)** - vulnerability disclosure and supported versions
- **[`spec/security/threat-model.md`](spec/security/threat-model.md)** - STRIDE risk register with per-release status
- **[Security architecture](docs/docs/security/index.md)** - capability boundaries, federation trust model, prompt-injection handling per [ADR-003](docs/adr/003-prompt-injection.md)
- **Release-cadence runbook** - `docs/internal/release-cadence.md` covers how releases are cut, verified, and rolled back

Single-org single-node deployments are the only currently supported pattern.
Cross-org federation needs the hardened-core work tracked in
[`ROADMAP.md`](ROADMAP.md).

## Adjacent systems

Stigmem deliberately does not compete with:

- **Agent runtimes** - Stigmem is the shared substrate agents reason over, not the runtime that executes them.
- **Company orchestration platforms** - Stigmem sits upstream; orchestrator events become typed facts.
- **Tool protocols** - [MCP](https://modelcontextprotocol.io) is a transport; the Stigmem MCP server ships Stigmem as an MCP tool surface.

It fills the gap none of them fill: typed, provenance-traceable, federated,
entity-scoped shared knowledge with first-class contradiction handling.

## AI-authorship disclosure

Stigmem is built by two contributors with heavy AI-coding assistance. We disclose this because a category whose product is trust shouldn't quietly hide where the work came from.

**Paths with deeper human review (line-by-line):**
- `spec/` — protocol specification text
- `docs/adr/` — Architecture Decision Records
- `LIMITATIONS.md`, `SECURITY.md`, `MAINTAINERS.md`, root `README.md`
- All threat-model entries (`spec/security/`, `docs/security/`)

**Paths with lighter human review (high-level direction + spot-checks):**
- `node/src/` — implementation
- `adapters/` — adapter implementations
- `sdks/` — SDK stubs
- `apps/` — UI scaffolding
- Test suites
- Documentation pages outside the spec and ADRs

This disclosure is also in [`CONTRIBUTING.md`](CONTRIBUTING.md) and the docs-site [AI authorship disclosure](docs/docs/community/ai-authorship.md). It is not a defect notice — it's a calibration aid for anyone evaluating whether to trust stigmem with their workload. Treat the lighter-reviewed paths as you would any AI-written code: verify behavior against the spec, run the conformance suite, and audit before adopting.

---

## The name

**Stigmem** = **Stigmergy** + **Memory**.

[Stigmergy](https://en.wikipedia.org/wiki/Stigmergy) (Greek *stigma* — mark; *ergon* — work) is the coordination mechanism observed in ant colonies and termite mounds: agents don't communicate directly with each other. Instead, they leave traces in a shared environment — a pheromone trail, a soil deposit — and those traces guide the behavior of future agents. The colony's intelligence emerges from the environment itself, not from any central controller.

Stigmem applies the same principle to multi-agent AI systems. Agents write typed, provenance-tagged facts into a shared substrate. Other agents — running later, on different platforms, inside different organizations — read those facts and act on them. No central coordinator, no point-to-point protocol overhead. The knowledge environment carries the coordination signal.

The **Memory** half reflects persistence and decay: facts have `valid_until` expiries and confidence scores, so the substrate stays fresh rather than accumulating stale state — just as pheromone trails fade when they're no longer reinforced.

---

## Spec

The canonical specification lives in [`spec/`](spec/). See [`spec/README.md`](spec/README.md) for the section-by-section status table.

The spec is being reviewed and improved into the v0.9.0a1 canonical structure: core sections first, then experimental sections move to `experimental/<feature>/spec.md` per [ADR-008](docs/adr/008-experimental-gates.md) and [ADR-020](docs/adr/020-feature-owned-product-structure.md) §9 (modular specs). Earlier evolutionary spec files (`stigmem-spec-pre-reset.md` through `stigmem-spec-pre-reset draft.md`) move to `spec/archive/evolution/` after their content has been forward-migrated. Nothing from the spec is being deleted.

---

## Community

Real-time chat: **[discord.gg/Z47Re7FjjV](https://discord.gg/Z47Re7FjjV)**.

The Stigmem Discord is where adopters, contributors, and operators discuss installation, federation, the spec, and SDK use. Help channels are organized by topic (`#install-help`, `#usage-questions`, `#federation-help`, `#troubleshooting`); spec and contributor discussion lives under the **Development** category. Asynchronous discussion continues to happen in [GitHub Discussions](https://github.com/eidetic-labs/stigmem/discussions) — both work.

If you're already running Stigmem in production and would consider participating in the future hardened-core external operator soak, mention it in `#dev-general` or DM `@offbyonce`. We're recruiting.

For security disclosures, see [SECURITY.md](SECURITY.md) — never report vulnerabilities in Discord.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the RFC process. Short version:

1. Open an issue using the [RFC template](.github/ISSUE_TEMPLATE/rfc.yml)
2. Discuss and iterate
3. Submit a PR against the canonical spec — new sections start as draft blocks inside the relevant spec file
4. Spec changes merge per the **[ADR-001 §Contributor approval rule](docs/adr/001-versioning.md)**: two contributors *or* the founder alone, through the pre-stable hardening window.

For bugs in the reference node, use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml).

Maintainers and contributors are listed in [MAINTAINERS.md](MAINTAINERS.md).

---

## Security

To report a vulnerability, use GitHub's private advisory process — **do not open a public issue**. See [SECURITY.md](SECURITY.md) for the full disclosure policy and the v0.9.0a12 security posture statement.

The full STRIDE threat model with per-release risk-register status lives at [`spec/security/threat-model.md`](spec/security/threat-model.md). See also [Security posture](#security-posture) above.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
