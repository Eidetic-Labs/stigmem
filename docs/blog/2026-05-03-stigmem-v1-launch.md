---
slug: stigmem-v1-launch
title: "Stigmem v1.0: A Federated Knowledge Fabric for AI Agents"
authors:
  - name: Eidetic Labs
    url: https://github.com/eidetic-labs
date: 2026-05-03
tags: [release, federation, mcp, ai-agents]
description: >
  Stigmem v1.0 is stable. A shared, provenance-tagged, federated knowledge substrate for AI agents — open-source, self-hostable, and MCP-compatible.
---

:::warning Retracted: this v1.0 announcement was withdrawn

This post announced stigmem v1.0 on 2026-05-03. **The v1.0 label was withdrawn shortly after.** The canonical version line of stigmem now begins at `v0.9.0a1` per [ADR-001](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md) and [ADR-001](https://github.com/eidetic-labs/stigmem/blob/main/docs/adr/001-versioning.md). This post is preserved in place to keep external links from breaking; it is not the current state of the project.

For the current posture, the retraction's reasoning, and what changed, see [the retraction post on dev.to](https://dev.to/offbyonce/walking-back-our-v10-announcement-resetting-to-v090a1-as-the-first-build-al0) and [LIMITATIONS.md](https://github.com/eidetic-labs/stigmem/blob/main/LIMITATIONS.md).

:::

---

Today we're releasing **stigmem v1.0** — a stable, open-source specification and reference implementation for a federated knowledge fabric for AI agents.

If you've ever wanted your AI agents to share what they know — across tools, platforms, and organizations — without a central database or a proprietary protocol, stigmem is built for that.

<!-- truncate -->

## The problem

Multi-agent systems accumulate knowledge in isolated silos. One agent knows a user prefers dark mode. Another inferred which projects are high priority. A third discovered a bug in the payment flow. None of them can see what the others know, because there's no shared place to put typed, provenance-tagged facts that travel across tool boundaries.

Existing approaches patch around this: you copy facts into prompts, maintain per-agent memory stores, or route everything through a central coordinator. These work up to a point, but they don't scale across organizations, they discard provenance, and they require trust in a single broker.

Stigmem takes a different path. Agents write facts into a shared substrate. The facts replicate across peer nodes via signed, scope-limited federation. No central coordinator. No broker. The knowledge environment itself carries the coordination signal — the same principle that makes ant colonies work, without any ant knowing the global plan.

## What stigmem is

**A fact** in stigmem is an immutable seven-tuple:

```
(entity, relation, value, source, timestamp, confidence, scope)
```

- `entity` — the URI of the thing being described (`user:alice`, `project:payments`, `stigmem://company.example/task/t-42`)
- `relation` — the predicate (`memory:prefers`, `status:blocked`, `infers:next_action`)
- `value` — typed payload: string, number, boolean, JSON object
- `source` — who asserted this fact (an agent ID, a tool name, a user session)
- `timestamp` — a Hybrid Logical Clock value that stays monotonic across distributed nodes
- `confidence` — 0.0–1.0 float; decays over time if not re-asserted
- `scope` — access boundary (`public`, `company`, `team`, `private`)

Facts are immutable. If you need to update a fact, you assert a newer one — the old one stays in history for audit. Contradictions between nodes are surfaced as first-class conflict records, not silently overwritten.

## The v1.0 milestone

The v1.0 spec (all 18 sections stable) includes:

- **Core fact shape and provenance** (§2–3) — the seven-tuple, `valid_until` expiry, and contradiction detection
- **HTTP wire format** (§5) — assert, query, retract, single-fact GET, and lint endpoints
- **Auth** (§3.5) — API keys with per-scope restrictions
- **Federation** (§6) — PeerDeclaration handshake over Ed25519, pull replication with configurable intervals, scope enforcement across nodes, and backpressure for N-node topologies
- **MCP adapter** (§12) — ships stigmem as an MCP server so any MCP-compatible agent runtime can read and write facts without knowing the HTTP wire format
- **Decay sweep** (§15) — configurable TTL and confidence-decay policies via `POST /v1/decay/sweep`
- **Synthesis** (§16) — `POST /v1/synthesis` aggregates recent facts into a structured summary; also exposed as the `synthesize_scope` MCP tool
- **Memory Garden** (§17) and **Source Attestation** (§18) — promoted from the pre-reset spec draft to stable

The reference node is a FastAPI + SQLite implementation with 74 tests, including automated failure-mode tests for split-brain, malicious peers, partial failures, and replay attacks (§11).

## Federation in practice

Two nodes federating takes under two minutes with Docker:

```bash
git clone https://github.com/eidetic-labs/stigmem && cd stigmem
docker compose up --build -d

# Register peers (both directions)
docker exec stigmem-node-a-1 \
  stigmem federation register-peer \
    --local-url http://node-a:8765 --remote-url http://node-b:8765 --scopes company,public

docker exec stigmem-node-b-1 \
  stigmem federation register-peer \
    --local-url http://node-b:8765 --remote-url http://node-a:8765 --scopes company,public

# Assert a fact on node-a
curl -s -X POST http://localhost:8765/v1/facts \
  -H 'Content-Type: application/json' \
  -d '{
    "entity": "user:alice",
    "relation": "memory:prefers",
    "value": {"type": "string", "v": "dark mode"},
    "source": "agent:settings",
    "confidence": 1.0,
    "scope": "company"
  }' | jq .

# After ~30 s, verify replication on node-b
curl -s 'http://localhost:8766/v1/facts?entity=user:alice&scope=company' | jq .facts
```

The two nodes discover each other via the `/.well-known/stigmem` metadata endpoint, exchange Ed25519-signed PeerDeclarations, and begin pull replication on the interval you configure (`STIGMEM_FEDERATION_PULL_INTERVAL_S`, default 30 s).

Scope enforcement is strict: a fact written to the `company` scope on node-a only replicates to peers that declared `company` in their handshake. `private` scope facts never leave the node that created them.

## MCP integration

Stigmem ships an MCP adapter, so any agent runtime that speaks MCP can interact with a stigmem node without calling the HTTP API directly:

```json
{
  "mcpServers": {
    "stigmem": {
      "command": "npx",
      "args": ["-y", "@stigmem/mcp-server"],
      "env": { "STIGMEM_NODE_URL": "http://localhost:8765" }
    }
  }
}
```

Once connected, agents get tools: `assert_fact`, `query_facts`, `retract_fact`, `synthesize_scope`, and `lint_scope`. The synthesis tool is particularly useful — it aggregates recent facts in a scope into a structured narrative that can be injected directly into an agent's context window.

## What stigmem is not

Stigmem does not replace:

- **Agent runtimes** (Claude Code, OpenClaw) — stigmem is the shared substrate those runtimes reason over, not a runtime itself
- **Orchestration platforms** (Paperclip) — the Paperclip adapter emits issue lifecycle events as stigmem facts; they layer, not compete
- **Tool protocols** (MCP) — MCP is the transport; the stigmem MCP adapter rides on top

It fills the gap none of them fill: typed, provenance-traceable, expiry-aware, federated shared knowledge.

## Get started

**Self-hosted:** [docs.stigmem.dev/docs/getting-started/quickstart](https://docs.stigmem.dev/docs/getting-started/quickstart)

**Repo:** [github.com/eidetic-labs/stigmem](https://github.com/eidetic-labs/stigmem) — Apache 2.0

**Spec:** [`spec/stigmem-spec-v1.0.md`](https://github.com/eidetic-labs/stigmem/blob/main/spec/stigmem-spec-v1.0.md) — all 18 sections stable

**Free-tier hosted node:** coming soon — [join the list](https://github.com/eidetic-labs/stigmem/discussions)

We'd love to hear what you're building. Open a discussion on GitHub, or drop a comment below.
