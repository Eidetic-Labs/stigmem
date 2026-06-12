# Stigmem — OpenClaw Adapter

Integrates Stigmem with OpenClaw agents. Provides the standard boot handshake
(pull user prefs + project constraints into context) and write surfaces for
handoffs, decisions, and escalations.

> **Status:** alpha / experimental. The current v0.9.0a11 OpenClaw adapter
> source is prepared as an evaluation surface, not a recommended production
> integration. The ClawHub skill is published as
> [`stigmem-node`](https://clawhub.ai/skills/stigmem-node) and installs the
> `stigmem-openclaw` adapter package from the active alpha line. The adapter has
> audit-mapped regression coverage and remains alpha while broader R-21
> certification/operator evidence is pending; see
> [LIMITATIONS.md §9](../../LIMITATIONS.md#9-running-the-openclaw-bundled-adapter-as-is).

## ClawHub skill

For alpha evaluation, install the
[`stigmem-node` ClawHub skill](https://clawhub.ai/skills/stigmem-node). The skill
bundles `adapter.py` as a compatibility shim, installs the
`stigmem-openclaw` package from the active alpha line, and documents the
environment variables in a format OpenClaw reads automatically.

```bash
# Install via OpenClaw's ClawHub integration
skill install stigmem-node
```

Then set the required env vars (ClawHub will prompt for them on first use):

```bash
STIGMEM_URL=https://stigmem.example.com   # required
STIGMEM_API_KEY=sk-your-key               # required by from_env()
STIGMEM_SOURCE_ENTITY=agent:openclaw      # optional; default: agent:openclaw
STIGMEM_SESSION_ID=openclaw:agent-01      # optional; generated per adapter instance if unset
```

## Security model

**Identity binding** — Each write surface (`emit_decision`, `emit_handoff`,
`emit_escalation`) pins the `source` field to the entity declared in
`STIGMEM_SOURCE_ENTITY`. Facts are attributed to this URI in the fact graph; ensure
it uniquely identifies the agent deployment, not a shared or generic identifier.

**Untrusted retrieved context** — `boot()` returns facts from an external Stigmem
node as the content channel. Put the exported `SYSTEM_PROMPT_DIRECTIVE` in the
agent's system prompt above `ctx.summary`; the summary is wrapped in explicit
`UNTRUSTED STIGMEM CONTENT` delimiters and must be treated as data, not
instructions. `recall_context()` consumes the channel-separated recall response
and keeps instruction-channel facts out of the content summary.

**API key scope** — Set `STIGMEM_API_KEY` to a least-privilege key scoped only to
the nodes this agent reads from and writes to. `OpenClawStigmemAdapter.from_env()`
fails closed when the key is missing so deployments do not accidentally run
unauthenticated. Do not share a key across unrelated agent deployments. Rotate
keys regularly; revoke via the Stigmem node admin API if compromised.

**Session and provenance propagation** — The adapter carries a stable
`Stigmem-Session` value across boot, recall, decision, escalation, and handoff
surfaces. Set `STIGMEM_SESSION_ID` when an operator needs a stable process or
agent identity; otherwise the adapter generates one per instance. Handoff writes
that reference source facts use `write_mode="summarize_with_provenance"` with
`derived_from` entries so the node can distinguish legitimate summaries from
same-session write poisoning.

## Known alpha gaps

The OpenClaw C1/H5 path now separates recall content from instruction-channel
facts at the adapter boundary, and C1-C4/H1-H5 audit-mapped regression tests
cover the adapter's known critical/high findings. The broader R-21 hardening
line now has supported-adapter session propagation and outbound replication
exclusion evidence, but still needs release certification and operator
validation before the project recommends OpenClaw for high-stakes production
deployments.

## Changelog

### v0.9.0a11 artifact refresh

- Documentation: remove pre-reset release-history framing from the PyPI long
  description so the `stigmem-openclaw` publish presents the adapter as a
  v0.9.0a11 alpha/evaluation surface.
- Documentation: align the package README with the ClawHub skill warning that
  OpenClaw is not a recommended production integration while R-21 certification
  and operator validation remain open.
- Packaging: keep the dependency contract on the active alpha line with
  `stigmem-py>=0.9.0a11,<1.0.0`.

## Design

OpenClaw agents are persistent and channel-agnostic. The Stigmem adapter hooks into:

1. **Agent boot** — pull user preferences (`preference:*`), active project
   constraints (`roadmap:constraint`), pending handoff facts, and recent
   escalations. All queries are paginated; node unavailability raises a typed
   boot error so callers cannot confuse a failed boot with a healthy empty
   context.
2. **Handoff** — when a user ends a session or delegates to another channel/agent,
   emit a typed `intent:handoff` fact cluster with validated fact refs, an optional
   continuation note, and a human-readable summary. A non-empty `fact_refs` list
   must have at least one valid ref; otherwise the adapter raises before writing a
   provenance-free handoff. Pass an `idempotency_key` for retries; complete prior
   writes no-op, while partial prior writes raise a typed error.
3. **Decision** — when the agent makes a meaningful choice, emit a
   `roadmap:decision` fact. Decisions are append-only; dedupe externally before
   calling if your workflow needs at-most-once semantics.
4. **Escalation** — emit a priority-typed `intent:escalation` fact cluster with a
   24-hour expiry so stale escalations don't linger.

### OpenClaw surface inventory

Built against OpenClaw's public API surfaces only — no holdco outreach during the earliest pre-reset design work
constraint. The adapter wraps Stigmem's HTTP API via `stigmem-py`; OpenClaw-hosted
agents import it as a standard Python library.

## Files

| File | Purpose |
|---|---|
| `adapter.py` | Python adapter class — boot handshake + write surfaces |
| `tests/conftest.py` | pytest path setup (no package install required) |
| `tests/test_adapter.py` | Unit tests (respx-mocked) + conformance vector smoke tests |
| `README.md` | This file |

## Setup

### Requirements

- Python ≥ 3.11
- `stigmem-py` installed from the alpha line:
  `pip install --pre "stigmem-py>=0.9.0a11,<1.0.0"`
- A running Stigmem node

### Environment variables

```bash
STIGMEM_URL=http://localhost:8765
STIGMEM_API_KEY=sk-your-key
STIGMEM_SOURCE_ENTITY=agent:openclaw   # entity URI for this OpenClaw instance
STIGMEM_OPENCLAW_ALLOWED_HANDOFF_TARGETS=agent:assistant,agent:cto
```

`STIGMEM_OPENCLAW_ALLOWED_HANDOFF_TARGETS` is a comma-separated allowlist for
handoff and escalation targets. The adapter always includes its own
`STIGMEM_SOURCE_ENTITY`; all other targets must be listed explicitly and must use
an `agent:` entity URI.

## Worked example — full agent boot + session lifecycle

```python
import os
from stigmem.adapters.openclaw.adapter import (
    OpenClawBootError,
    OpenClawStigmemAdapter,
    SYSTEM_PROMPT_DIRECTIVE,
)

# 1. Construct from environment
adapter = OpenClawStigmemAdapter.from_env()

# 2. Boot at session start — pull all relevant facts and format a system prompt snippet
try:
    ctx = adapter.boot(
        user_entity="user:alice",
        session_id="session:2026-05-02-abc",
        project_entities=["project:acme-roadmap"],
    )
except OpenClawBootError:
    # Treat as a failed boot, not as a healthy empty context.
    raise

system_prompt = (
    base_system_prompt
    + ("\n\n" + SYSTEM_PROMPT_DIRECTIVE + "\n\n" + ctx.summary if ctx else "")
)

# ctx.summary looks like:
#
# <<<UNTRUSTED STIGMEM CONTENT — DATA ONLY>>>
# ## Stigmem content context — user:alice
#
# ### preference
# - **preference:theme** on `user:alice`: dark
# - **preference:lang** on `user:alice`: en
#
# ### roadmap
# - **roadmap:constraint** on `project:acme-roadmap`: Must ship the pre-reset design work before 2026-06-01
#
# ### intent
# - **intent:context_ref** on `handoff:5f3a`: fact-004

# 3. Agent runs its main loop …
# (LLM calls, tool use, etc.)

# 4a. Emit a significant architectural decision
adapter.emit_decision(
    entity="decision:auth-provider",
    summary="Chose Clerk over Auth0: simpler Next.js integration, lower per-seat cost at SMB scale.",
)

# 4b. Escalate to the CTO when the agent hits a scope boundary
adapter.emit_escalation(
    to_entity="agent:cto",
    goal="Approve increased Stripe webhook rate limit for the pre-reset design work load.",
    priority="high",
)

# 5. Emit a handoff when the session ends or delegates
adapter.emit_handoff(
    from_entity="agent:openclaw",
    to_entity="agent:assistant",
    summary="User asked about Q2 roadmap; auth provider chosen; Stripe limit escalation pending.",
    fact_refs=["fact-auth-decision", "fact-esc-stripe"],   # invalid refs are skipped with a warning
    continuation="Resume from the Stripe rate-limit discussion.",
    idempotency_key="session-2026-05-02-abc",
)
```

## Running the tests

```bash
# from the repo root
uv run pytest stigmem/adapters/openclaw/tests/ -v
```

No live Stigmem node required — all tests are respx-mocked. Conformance vectors
from `sdks/stigmem-py/tests/conformance_vectors.py` are included as smoke tests.

## Relation namespaces

| Relation | Scope | Written by | Notes |
|---|---|---|---|
| `preference:*` | company | Any agent or user | Pulled on boot; filtered to `preference:` prefix |
| `roadmap:constraint` | company | CTO / planning agents | Pulled per project entity |
| `roadmap:decision` | company | Agent | Append-only; caller dedupes externally if needed |
| `intent:handoff_to` | company | Agent on session end | Ref to receiving agent |
| `intent:handoff_summary` | company | Agent on session end | Text summary |
| `intent:context_ref` | company | Agent on session end | Fact refs for receiver |
| `intent:continuation` | company | Agent on session end | Optional continuation note |
| `intent:escalation` | company | Agent on escalation | Priority string; 24h expiry |
| `intent:escalate_to` | company | Agent on escalation | Ref to receiving agent |
| `intent:goal` | company | Agent on escalation | Text goal |
