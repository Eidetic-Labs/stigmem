# Local development runbook

How to bring up stigmem locally for hacking, debugging, and federation testing. Companion to the public [README quickstart](../../README.md#quickstart--two-nodes-federating); the public quickstart is for adopters, this is for contributors.

Internal-facing maintainer doc — not in the public docs site.

---

## What you need

| Tool | Recommended version | Install |
|---|---|---|
| **uv** | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **pnpm** | 9.x (matches `packageManager` in root `package.json`) | `npm install -g pnpm@9` |
| **Docker / Compose** | recent | macOS: `brew install colima docker docker-compose docker-buildx`; Linux: distro packages or Docker Desktop |
| **gh CLI** (optional but useful) | latest | `brew install gh` |
| **Python** | 3.11+ | uv manages this — no separate install needed |
| **Node** | 20+ | nvm / corepack / direct install |

If using Colima on macOS, the smoke-test runbook below assumes you've already done `colima start --cpu 4 --memory 8 --disk 60`.

---

## First-time setup

```bash
git clone https://github.com/eidetic-labs/stigmem
cd stigmem

# Python deps
uv sync --all-extras          # installs Python deps for all workspace members
uv pip install -e node        # editable install of the reference node

# Node/TypeScript deps
pnpm install --frozen-lockfile
pnpm --filter "./sdks/stigmem-ts" build   # builds the SDK; required for tests that import from dist/
```

Verify the install:

```bash
uv run pytest node/tests/ -x --tb=short -q          # ~30 seconds, ~900 tests
pnpm --filter "./sdks/stigmem-ts" test              # vitest, fast
pnpm --filter "./adapters/mcp" test                 # vitest, fast
```

---

## Run a single node

```bash
# From the repo root, in the workspace venv:
uv run python -c 'from stigmem_node.main import run; run()'
# Listens on 0.0.0.0:8765 by default; auth required by default
```

Override settings via env or `.env`:

```bash
STIGMEM_AUTH_REQUIRED=false STIGMEM_DB_PATH=/tmp/stigmem-dev.db uv run python -c 'from stigmem_node.main import run; run()'
```

Common envs: `STIGMEM_PORT`, `STIGMEM_HOST`, `STIGMEM_FEDERATION_ENABLED`, `STIGMEM_FEDERATION_PULL_INTERVAL_S`, `STIGMEM_LOG_LEVEL`.

---

## Run two-node federation locally (Docker Compose)

The full quickstart against the canonical `docker-compose.yml`:

```bash
docker compose up -d                  # pulls GHCR image if available; falls back to local build
docker compose ps                     # both healthy
docker compose logs --follow node-a   # watch one node's logs
docker compose down -v                # tear down + remove volumes (clears all DB state)
```

For a contributor working on changes:

```bash
docker compose up --build -d          # forces local rebuild from node/Dockerfile
```

If host port 8765/8766 is already in use (another stigmem-node instance, dev tunnel, etc.):

```bash
STIGMEM_NODE_A_HOST_PORT=18765 STIGMEM_NODE_B_HOST_PORT=18766 docker compose up -d
```

The internal container port stays at 8765; only the host-side mapping changes. Federation between containers uses service-network DNS (`http://node-a:8765`) which is unaffected by host port choice.

---

## Run the federation smoke test

```bash
bash scripts/quickstart-verify.sh
```

For the production-shaped mTLS compose path:

```bash
bash scripts/mtls-compose-smoke.sh
```

That command generates demo certificates in a temp directory, starts the
two-node mTLS compose stack, verifies HTTPS health checks with client
certificates, registers peers, asserts a fact, confirms federation on the peer,
and tears everything down. Set `KEEP_UP=1` to inspect the running stack after a
failure.

What it does (~40 seconds end-to-end):

1. Pre-flight teardown (`docker compose down -v --remove-orphans`) clears any leftover state from a dirty previous run.
2. Auto-selects two free host ports starting at 18765 (configurable via env).
3. `docker compose up --build -d` brings up two nodes.
4. Waits for both healthchecks to pass.
5. Reads `/.well-known/stigmem` on each, captures node IDs.
6. Registers each node as a peer of the other (signed Ed25519 PeerDeclaration handshake).
7. Asserts a fact on node-a.
8. Waits 35s for the federation pull cycle (default `STIGMEM_FEDERATION_PULL_INTERVAL_S=30`).
9. Queries node-b for the replicated fact.
10. Tears down (`docker compose down -v --remove-orphans`).

Useful environment overrides:

| Env | Default | Effect |
|---|---|---|
| `KEEP_UP=1` | `0` | Skip teardown — leaves containers up so you can inspect state after failure |
| `PULL_WAIT_S=N` | `35` | Adjust how long to wait for the fact to replicate |
| `STIGMEM_NODE_A_HOST_PORT` / `STIGMEM_NODE_B_HOST_PORT` | auto-detected | Force specific host ports; fail fast if either is occupied |

---

## Debugging a failing federation test

If the smoke test fails with "Fact NOT found on node-b after Ns":

1. **Re-run with `KEEP_UP=1`** so containers stay up.
2. **Check both nodes' federation state** to confirm peers are registered:
   ```bash
   curl -sf http://localhost:${STIGMEM_NODE_A_HOST_PORT:-18765}/v1/federation/peers | python3 -m json.tool
   curl -sf http://localhost:${STIGMEM_NODE_B_HOST_PORT:-18766}/v1/federation/peers | python3 -m json.tool
   ```
3. **Verify pull requests are reaching the peer** — node-a's logs should show requests like `GET /v1/federation/facts?limit=100`:
   ```bash
   docker compose logs node-a | grep federation
   docker compose logs node-b | grep federation
   ```
4. **Verify node IDs match across surfaces.** The most common federation bug is a node-id mismatch between `/.well-known/stigmem` and the stored peer record. From inside node-b's container:
   ```bash
   docker exec stigmem-node-b-1 python -c "
   from stigmem_node.db import get_or_create_node_id
   print('self:', get_or_create_node_id())
   "
   curl -sf http://localhost:${STIGMEM_NODE_A_HOST_PORT:-18765}/.well-known/stigmem | python3 -c "import sys,json;print('via wellknown:',json.load(sys.stdin)['node_id'])"
   ```
   If those don't match, you're likely hitting another stigmem-node process bound to the same loopback port. Check with `lsof -nP -i :${STIGMEM_NODE_A_HOST_PORT:-18765}`.
5. **Check the federation audit log** on the receiving side:
   ```bash
   curl -sf http://localhost:${STIGMEM_NODE_B_HOST_PORT:-18766}/v1/federation/audit | python3 -m json.tool
   ```
   Common entries: `tl_proof_missing` (relaxed mode warning, harmless in dev), `san_mismatch` (mTLS cert check), `pull_failed` (network or auth issue).

If you've debugged something useful, consider adding it to this section.

---

## Run linters + type checks

```bash
# Python
uv run ruff check                                       # full repo
uv run ruff check node/src/stigmem_node/main.py         # single file
uv run mypy --show-error-codes node/                    # type-check
uv run python scripts/check_mypy_baseline.py            # baseline-aware check (CI uses this)

# TypeScript
pnpm --filter "./sdks/stigmem-ts" type-check
pnpm --filter "./adapters/mcp" type-check
pnpm --filter "./apps/dashboard" type-check
```

The CI runs these as `Python checks` and `TypeScript checks` jobs.

---

## Regenerate OpenAPI spec

If you change the FastAPI app definition or any route signature:

```bash
uv run python scripts/export_openapi.py
git diff docs/openapi/stigmem.json    # confirm only the change you made appears
```

The contract-checks CI job fails on uncommitted drift.

---

## Update version-consistency CI fixtures

If you add a new release surface (e.g., publishing to a new registry):

1. Add an entry to `release/version-surfaces.yaml` per the schema in [ADR-001 (version-string convention)](../../docs/adr/001-versioning.md).
2. Run `python scripts/validate_version_surfaces.py` locally.
3. Run `python scripts/check_version_consistency.py` locally.
4. Commit. The CI gate will run the same checks.

### Hardened-core #160 evidence snapshot

Verified 2026-05-13 as part of the upstream-validation F-01 / F-02 follow-up:

- **Implementation PRs:** Phase A version reset and canonical Apache-2.0 license replacement landed before this snapshot; #160 expands the checker to cover prose/runtime surfaces that were previously manifest-only.
- **Current release posture:** canonical version anchor is `pyproject.toml` `project.version = "0.9.0a2"`; semver packages use the equivalent `0.9.0-alpha.2`.
- **Checked version surfaces:** root/node/SDK/OpenClaw Python package metadata, root and TypeScript package metadata, FastAPI app metadata, generated OpenAPI metadata, README banner, CHANGELOG top entry, LIMITATIONS applicability, SECURITY posture header, Docusaurus versions metadata, conformance package version, and plugin registry/manifest fallback strings.
- **MCP package metadata:** `adapters/mcp/package.json` is aligned to the active alpha semver release line for publication readiness, and repo-local MCP protocol smoke passes against a live node; registry publication remains blocked until host UI smoke, adapter security certification, dry-run evidence, and maintainer clearance complete; experimental adapter/dashboard package versions remain independent `0.1.0` surfaces until they pass ADR-008 reintroduction gates.
- **License evidence:** GitHub repository metadata reports `apache-2.0` / "Apache License 2.0"; root `LICENSE` is the canonical Apache-2.0 text; published package metadata uses `Apache-2.0` for in-scope packages.
- **CI/test evidence:** `.github/workflows/version-consistency.yml` runs `scripts/validate_version_surfaces.py` and `scripts/check_version_consistency.py --verbose`; `node/tests/lifecycle/test_version_consistency_script.py` covers the regex and literal metadata extractors used for prose/runtime surfaces.
- **Version introduced:** v0.9.0a1 baseline, with #160 coverage added during the v0.9.0aN upstream-validation correction line.
- **Follow-up issues:** none opened from this snapshot; no drift was found after expanding checker coverage.

---

## Build all four Python wheels (release prep)

```bash
rm -rf dist/
uv build --package stigmem
uv build --package stigmem-py
uv build --package stigmem-node
uv build --package stigmem-openclaw
uv run twine check dist/*    # all should PASSED
```

`uv build` is workspace-aware (handles cross-package deps via local paths). `python -m build` works for individual packages but not for `stigmem-openclaw` because it tries to resolve the `stigmem-py` dep against PyPI in an isolated env.

---

## Smoke-install in a fresh venv

```bash
uv venv --python 3.11 /tmp/stigmem-smoke
VBIN=/tmp/stigmem-smoke/bin
uv pip install --python "$VBIN/python" --pre --find-links dist/ stigmem    # meta-package
uv pip list --python "$VBIN/python" | grep stigmem
"$VBIN/python" -c "from stigmem import StigmemClient; print('OK')"
```

For the meta-package's extras:

```bash
uv pip install --python "$VBIN/python" --pre --find-links dist/ "stigmem[node]"
uv pip install --python "$VBIN/python" --pre --find-links dist/ "stigmem[all]"
```

---

## Smoke-install npm package in a fresh node_modules

```bash
cd sdks/stigmem-ts
pnpm build
npm pack    # produces eidetic-labs-stigmem-ts-0.9.0-alpha.2.tgz

mkdir -p /tmp/stigmem-ts-smoke && cd /tmp/stigmem-ts-smoke
echo '{"name":"smoke","type":"module","private":true}' > package.json
npm install /Users/bjones/Desktop/stigmem/sdks/stigmem-ts/eidetic-labs-stigmem-ts-0.9.0-alpha.2.tgz
node -e "import('@eidetic-labs/stigmem-ts').then(m => console.log('exports:', Object.keys(m).join(', ')))"
```

---

## Common gotchas

### Port 8765 / 8766 already in use

Another stigmem-node instance — typically a Paperclip-managed instance or a stale `uv run python -c 'from stigmem_node.main import run; run()'` from a previous session. Either:

- Kill it: `lsof -nP -i :8765` to find PID, then `kill <pid>`.
- Or use the smoke test's auto-port-detection: it picks the next free pair.
- Or override explicitly: `STIGMEM_NODE_A_HOST_PORT=18888 docker compose up -d`.

### "peer already registered" on a fresh `docker compose up`

Means the previous run's volumes weren't cleaned up. The Compose teardown step is `docker compose down -v --remove-orphans`. If you ran with `KEEP_UP=1`, the volumes persisted; clean explicitly:

```bash
docker compose down -v --remove-orphans
```

### Tests pass locally but fail in CI

Most common cause: shared-state leak between tests. Run the full suite locally to surface it: `uv run pytest node/tests/ -x`. If `-x` doesn't reproduce, try with `--forked` or `-p no:cacheprovider`.

There's a known flake in `test_tombstone_filter.py` — see GitHub issue #47.

### `pnpm install` with the wrong major version

Symptoms: misleading "different major version" errors during `next build` or `tsc`. Fix: use pnpm 9.x; check with `pnpm --version`. The lockfile format is pinned to v9. `npm install -g pnpm@9` if you're on a newer version locally.

---

## Useful one-liners

```bash
# Wipe all stigmem dev state (containers, volumes, local DBs, dist artifacts)
docker compose down -v --remove-orphans
rm -rf /tmp/stigmem-* dist/ node/dist/ sdks/*/dist/ apps/*/.next/

# Rebuild docker images from scratch (no cache)
docker compose build --no-cache

# Tail combined logs from both nodes
docker compose logs --follow

# Drop into one node's Python shell
docker exec -it stigmem-node-a-1 python

# Inspect a peer's signed PeerDeclaration
docker exec stigmem-node-a-1 python -c "
from stigmem_node.db import db
import json
with db() as conn:
    for p in conn.execute('SELECT * FROM peers'):
        d = dict(p)
        print(json.dumps(d, indent=2, default=str))
"
```

---

*This runbook is updated when contributors find debugging patterns useful enough to share. If you've fought a federation issue and the steps above didn't help, please update this doc with what worked.*
