# Stigmem Test Structure — Current State and Best Practices

> Final piece of the structural-sweep work. Confirms pytest as the test framework, recommends test layout, plans the `node/tests/` reorganization.
> Companion to `stigmem-file-structure-and-size-best-practices.md` and `stigmem-pydantic-decomposition-plan.md`.

---

## Short answer

**Yes, pytest — already in use, and well-configured. Keep it.**

**Tests-at-package-root with internal structure mirroring source.** Not "next to what they're testing" (Go/Rust convention, not Python-idiomatic) and not "everything at the root" (loses the polyglot monorepo's natural boundaries). The right pattern is the one you're already mostly using; the improvement is to organize `node/tests/` internally so it mirrors `node/src/stigmem_node/`.

---

## What's already in place (and right)

The `pyproject.toml` setup is already strong:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["node/tests", "sdks/stigmem-py/tests", "node/src/stigmem_conformance/tests"]
pythonpath = ["node/tests", "sdks/stigmem-py/tests"]
addopts = "--import-mode=importlib"
markers = [
 "unit: ...",
 "integration: ...",
 "conformance: ...",
 "postgres: ...",
 "libsql: ...",
 "docker: ...",
 "eval: ...",
 "slow: ...",
 "network: ...",
]
```

What's right about this:

- **`asyncio_mode = "auto"`** — eliminates the need for `@pytest.mark.asyncio` on every async test. Modern best practice.
- **`--import-mode=importlib`** — the newer pytest import mode; avoids `sys.path` manipulation. Recommended by pytest maintainers for new projects.
- **Marker taxonomy** is well-thought-out. Nine markers covering test scope (`unit`/`integration`/`conformance`), test cost (`slow`), and infrastructure dependencies (`postgres`/`libsql`/`docker`/`network`/`eval`). Operators and CI can run tightly-scoped subsets.
- **Auto-marker assignment** in root `conftest.py` via `pytest_collection_modifyitems`. Tests don't have to remember to add markers; the test path tells the conftest what they are. This is the right pattern.
- **Coverage configured** for `node/src` and `sdks/stigmem-py/src`, omitting tests and migrations.

This setup is genuinely better than what most projects ship with. Keep it.

---

## Where tests live today (already mostly correct)

The package-level layout follows the right pattern:

| Location | Test count | Pattern |
|---|---|---|
| `node/tests/` | 47 | Tests for the reference node, flat |
| `sdks/stigmem-py/tests/` | 1 | Tests for the Python SDK |
| `node/src/stigmem_conformance/tests/` | 8 | Conformance vector tests |
| `adapters/openclaw/tests/` | 1 | OpenClaw adapter tests |
| `adapters/obsidian/tests/` | 4 | Obsidian adapter tests |
| `adapters/letta/tests/` | 1 | Each adapter has its own tests/ dir |
| `adapters/zep/tests/` | 1 | … |
| `adapters/cognee/tests/` | 1 | … |
| `adapters/gemini/tests/` | 1 | … |
| `adapters/openai-tools/tests/` | 1 | … |
| `adapters/mcp/tests/` | 0 | empty |
| `apps/dashboard/tests/` | 0 | empty |
| `sdks/stigmem-ts/tests/` | 0 | empty |

Each package owns its tests at the package root. **This is the right pattern** for a polyglot monorepo. Don't change it.

The actual problems are:

1. **`node/tests/` is flat** — 47 files at one level is the same problem as the 40 flat `*.py` files in the source module. Hard to navigate, hard to find existing tests, hard to know where new tests should go.
2. **Three empty `tests/` directories** — `adapters/mcp/`, `apps/dashboard/`, `sdks/stigmem-ts/`. Either fill them or document why they're empty.
3. **No formal convention for adapter tests** — each adapter has its own pattern. Probably fine while they're experimental, but worth establishing a convention before the OpenClaw adapter ships in v1.0.

---

## The two test-layout schools (and which one applies)

**School A: Tests in a separate `tests/` directory at the package root.** Standard Python convention since pre-pytest. Used by Django, Flask, requests, FastAPI itself, most major libraries. Keeps source clean, separates production code from test code, makes packaging straightforward (exclude `tests/` from sdist if needed).

**School B: Tests colocated next to source files.** Common in Go (`foo_test.go` next to `foo.go`), Rust (`#[cfg(test)] mod tests` in the same file), some Java/Kotlin, some JS projects. Advantages: tests follow code through refactors; no "where does this test belong" question.

**For Python specifically:** School A is the dominant convention. PEP 8 doesn't mandate, but the entire ecosystem of tooling, packaging, and documentation assumes School A. Going against it produces friction you don't need.

**For stigmem specifically:** you're a Python-primary polyglot monorepo with multiple packages. School A at the package level is the right answer, which is what's already in place. The improvement is internal organization within each package's `tests/` directory.

---

## Recommended discipline

### Test files mirror source files

For every source file `node/src/stigmem_node/<path>/<module>.py`, the corresponding test file lives at `node/tests/<path>/test_<module>.py`. Concretely:

| Source | Test |
|---|---|
| `node/src/stigmem_node/auth.py` | `node/tests/auth/test_*.py` for auth, agent-key, and trust-rule concerns |
| `node/src/stigmem_node/auth/peer_auth.py` (after sub-package work) | `node/tests/auth/test_peer_auth.py` |
| `node/src/stigmem_node/routes/facts.py` | `node/tests/routes/test_facts.py` |
| `node/src/stigmem_node/routes/federation.py` | `node/tests/routes/test_federation.py` |
| `node/src/stigmem_node/models/facts.py` | `node/tests/models/test_facts.py` |
| `node/src/stigmem_node/cli/capability.py` | `node/tests/cli/test_capability.py` |

The mirror discipline gives you:
- "Where's the test for X?" has one answer.
- "Where do I put a new test?" has one answer.
- Refactoring source automatically guides test refactoring.
- Code coverage tools naturally pair source with tests.

### Test class organization within a file

For files with many tests (and pytest supports either function-style or class-style), prefer **class-grouping by behavior**:

```python
# node/tests/routes/test_facts.py

class TestFactAssertion:
 def test_basic_assert(self, client, auth_headers): ...
 def test_assert_with_attestation(self, ...): ...
 def test_assert_rejects_invalid_scope(self, ...): ...

class TestFactQuery:
 def test_query_by_entity(self, ...): ...
 def test_query_with_pagination(self, ...): ...

class TestFactProvenance:
 def test_provenance_chain(self, ...): ...
```

This gives you per-behavior isolation without splitting into more files than necessary, and it lets `pytest -k TestFactAssertion` run a focused subset.

### Test discovery boundaries

The current `testpaths` setting points at three places: `node/tests`, `sdks/stigmem-py/tests`, `node/src/stigmem_conformance/tests`. Add `adapters/*/tests` once adapter test coverage is meaningful (recommend doing this before OpenClaw v0.9 ships). Concretely:

```toml
testpaths = [
 "node/tests",
 "sdks/stigmem-py/tests",
 "node/src/stigmem_conformance/tests",
 "adapters/mcp/tests",
 "adapters/openclaw/tests",
]
```

Experimental features per ADR-020 §13 (repo structure) will live at `experimental/<feature>/tests/`. Add them to `testpaths` only when they pass ADR-008 gates and rejoin the v1 critical-path.

---

## Reorganizing `node/tests/`

The 47 flat test files cluster naturally by source-file domain. Proposed reorganization (mirrors the eventual `node/src/stigmem_node/` sub-package structure):

```
node/tests/
├── conftest.py # (existing — central fixtures)
├── routes/
│ ├── test_facts.py # was test_facts.py
│ ├── test_federation.py # was test_federation.py
│ ├── test_recall.py # was test_recall.py
│ ├── test_gardens.py # was test_gardens.py
│ ├── test_quarantine.py # was test_quarantine.py
│ ├── test_intents.py # was test_intents.py
│ ├── test_subscriptions.py # was test_subscriptions.py (move w/ feature later)
│ ├── test_admin_audit.py # was test_admin_audit.py
│ └── ...
├── auth/
│ ├── test_agent_keys.py # was test_agent_keys.py
│ ├── test_oidc.py # was test_oidc.py (move to experimental/oidc later)
│ ├── test_phase8_identity.py # split into multiple files (per file-size best-practices)
│ └── ...
├── federation/
│ ├── test_4node_federation.py # was test_4node_federation.py
│ ├── test_mtls.py # was test_mtls.py
│ ├── test_phase12_replay_fuzz.py # was test_phase12_replay_fuzz.py
│ ├── test_phase12_key_rotation.py # was test_phase12_key_rotation.py
│ └── ...
├── recall/
│ ├── test_recall.py # core recall logic
│ ├── test_embeddings.py # was test_embeddings.py
│ ├── test_synthesis_decay.py # was test_synthesis_decay.py
│ ├── test_fuzzy_resolver.py # was test_fuzzy_resolver.py (move to experimental later)
│ └── ...
├── observability/
│ ├── test_audit_enriched.py # was test_audit_enriched.py
│ ├── test_observability.py # was test_observability.py
│ ├── test_quota.py # was test_quota.py
│ ├── test_rate_limit.py # was test_rate_limit.py
│ └── ...
├── lifecycle/
│ ├── test_async_jobs.py # was test_async_jobs.py
│ ├── test_migrate.py # was test_migrate.py
│ ├── test_migration_compat.py # was test_migration_compat.py
│ ├── test_snapshot.py # was test_snapshot.py
│ └── ...
├── models/ # New, after Pydantic decomposition
│ ├── test_facts.py
│ ├── test_gardens.py
│ └── ...
├── conformance/ # Already mostly here; consolidate
│ ├── test_conformance_v1.py # was test_conformance_v1.py
│ ├── test_conformance_v2.py # was test_conformance_v2.py (or move to experimental)
│ └── ...
├── secure_defaults/
│ ├── test_secure_defaults.py # was test_secure_defaults.py
│ ├── test_encryption.py # was test_encryption.py
│ └── ...
├── tombstones/ # Stays here in v0.9.0a1 (per ADR-011 C3); moves to experimental/23-rtbf-tombstones/tests/ in v0.9.x
│ ├── test_tombstones.py
│ ├── test_tombstone_filter.py
│ └── test_provenance_tombstone.py
└── time_travel/ # Same — moves to `experimental/time-travel/tests/` when implemented as plugin per ADR-011 (C1)
 ├── test_phase13_as_of.py
 ├── test_phase13_time_travel_cid.py
 └── test_time_travel.py
```

This isn't a refactor of test logic — it's just `git mv`. The auto-marker assignments in root `conftest.py` need a small update to handle the new paths:

```python
# conftest.py (updated)
def pytest_collection_modifyitems(items):
 for item in items:
 rel = Path(str(item.fspath)).as_posix()

 if rel.startswith("eval/"):
 item.add_marker(pytest.mark.eval)
 item.add_marker(pytest.mark.slow)

 if rel.startswith("node/src/stigmem_conformance/tests/") or "/conformance/" in rel:
 item.add_marker(pytest.mark.conformance)
 item.add_marker(pytest.mark.integration)
 elif rel.startswith("node/tests/"):
 item.add_marker(pytest.mark.integration)

 if rel.startswith("sdks/") and rel.endswith("/tests/"):
 item.add_marker(pytest.mark.unit)

 if rel.startswith("adapters/") and "/tests/" in rel:
 item.add_marker(pytest.mark.integration)

 if rel.startswith("experimental/"):
 item.add_marker(pytest.mark.experimental)
```

Add `experimental` to the markers list in `pyproject.toml` while you're there.

**Effort:** half day. Mostly mechanical `git mv` plus the conftest update and a quick test run to confirm nothing breaks.

---

## Empty `tests/` directories

Three packages have empty test directories:
- `adapters/mcp/tests/`
- `apps/dashboard/tests/`
- `sdks/stigmem-ts/tests/`

Three options for each:

1. **Fill them.** Write the tests. Right answer for `adapters/mcp/` (it's v1.0 critical-path per ADR-002) and `sdks/stigmem-ts/` (until SDK moves to experimental).
2. **Document why empty.** Add a `tests/README.md` explaining the gap. Acceptable for `apps/dashboard/` if dashboard is moving to experimental anyway.
3. **Remove the directory.** If genuinely no tests will land here, the empty `tests/` directory is misleading.

For `adapters/mcp/`: this is v1.0 critical-path and currently has zero tests. Add tests as part of the strengthening plan's hardened-core work alongside the OpenClaw audit-driven changes is reasonable.

For the others: they're all moving to experimental per ADR-020 §13 (repo structure), so the empty `tests/` directories disappear with the relocation.

---

## Adapter test convention

Each adapter currently has its own `tests/` directory with varying content. As OpenClaw v0.9 ships and other adapters return through ADR-008 gates, adopt this convention:

```
experimental/<adapter-name>/
├── STATUS.md
├── README.md
├── pyproject.toml
├── src/stigmem_<adapter>/
│ └── adapter.py
└── tests/
 ├── conftest.py
 ├── test_adapter_basic.py # core integration: assert / query / recall through the adapter
 ├── test_adapter_<surface>.py # surface-specific tests (handoff, escalation, decision, etc.)
 └── test_adapter_security.py # adversarial vectors for the adapter's threat surface
```

For OpenClaw v0.9 specifically (since it's v1.0 critical-path), this lives at `adapters/openclaw/` with the same internal structure.

The `test_adapter_security.py` file is the place to land the audit findings as regression tests. Per the OpenClaw audit, every C-series and H-series finding becomes a test in that file:

```python
# adapters/openclaw/tests/test_adapter_security.py

class TestC4HandoffWormVector:
 """Audit finding C4: emit_handoff to_entity is unvalidated."""

 def test_emit_handoff_rejects_unallowlisted_target(self, adapter):
 with pytest.raises(StigmemHandoffError, match="not in the configured allowlist"):
 adapter.emit_handoff(
 from_entity="agent:test",
 to_entity="agent:admin", # Not in allowlist
 summary="...",
 fact_refs=[],
 )

class TestH1OrphanHandoffs:
 """Audit finding H1: handoffs with all-invalid refs."""

 def test_emit_handoff_refuses_when_all_refs_invalid(self, adapter):
 with pytest.raises(StigmemHandoffError, match="none of .* fact_refs validated"):
 adapter.emit_handoff(
 from_entity="agent:test",
 to_entity="agent:scheduler", # Allowed
 summary="...",
 fact_refs=["fact:nonexistent-1", "fact:nonexistent-2"],
 )
```

This pattern makes the audit findings durable: the tests document what was found and lock in the fix.

---

## Marker discipline going forward

The marker taxonomy is good. Two refinements:

### Add an `experimental` marker

For tests of features deferred to `experimental/`. The auto-marker rule above adds it automatically by path. Default CI runs exclude `experimental` markers; tests are run only when explicitly opted in.

### Add a `security` marker

For adversarial / threat-model regression tests. This makes it possible to run `pytest -m security` as a focused security-validation pass, separate from general integration tests. Useful for the security-revisions punch list and for incident response.

```toml
markers = [
 "unit: ...",
 "integration: ...",
 "conformance: ...",
 "security: adversarial vectors and threat-model regression tests",
 "experimental: tests for features in experimental/ (excluded from default CI)",
 "postgres: ...",
 "libsql: ...",
 "docker: ...",
 "eval: ...",
 "slow: ...",
 "network: ...",
]
```

---

## CI test strategy

The marker taxonomy enables tightly-scoped CI jobs. Recommended split:

| Job | Marker filter | Trigger | Goal |
|---|---|---|---|
| `pytest-unit` | `-m unit` | Every PR | Fast pre-flight; <30s |
| `pytest-integration` | `-m "integration and not slow and not network"` | Every PR | Catch regressions in core paths; <5min |
| `pytest-conformance` | `-m conformance` | Every PR | Wire-format and adversarial vectors must pass |
| `pytest-security` | `-m security` | Every PR | Audit-finding regression tests |
| `pytest-postgres` | `-m postgres` | PR + nightly | Backend-specific tests |
| `pytest-libsql` | `-m libsql` | PR + nightly | Backend-specific tests |
| `pytest-eval` | `-m eval` | Nightly | Adversarial recall evals; can take >30min |
| `pytest-network` | `-m network` | Nightly | Tests that need outbound network |
| `pytest-experimental` | `-m experimental` | Manual / per-feature | Run when extracting an experimental feature |

This is what the marker taxonomy was designed for; the split matches the existing markers cleanly.

---

## What this does NOT change

A few things that look like they might be affected but aren't:

- **`pytest-asyncio` configuration is correct** — `asyncio_mode = "auto"` should stay.
- **`--import-mode=importlib`** — keep. Modern best practice.
- **Auto-marker assignment in root conftest** — keep, just expand the path patterns to handle the new `node/tests/<subdomain>/` layout.
- **`pythonpath` setting** — fine as-is. Some projects drop this in favor of `pyproject.toml`-based package discovery, but the current setup works.
- **Coverage configuration** — keep. The omit list is correct; sub-directory reorganization within `tests/` doesn't affect coverage paths.
- **Conformance vectors location** — `data/conformance/` is the right place. Tests for those vectors live in `node/src/stigmem_conformance/tests/` (already a package-internal tests directory; that's correct because conformance is part of the node's public-facing functionality).

---

## Implementation order

This is **v0.9.x work**, not Phase A. Sequence after the source-side reorganizations to keep the test/source mirror in sync:

> 2026-05-17 update: issue #465 performs the broad `node/tests/` mirror pass
> after the CLI, route, Pydantic, identity, federation, and soak-driver
> decompositions landed. Root-level node tests are moved into concern
> directories while keeping `node/tests/conftest.py`, recursive pytest
> discovery, and existing fixture behavior intact.

| When | What |
|---|---|
| early hardened-core pass | Add `security` and `experimental` markers; update root conftest auto-marker rules. |
| v0.9.x — alongside `cli/` decomposition | Move CLI tests into `node/tests/cli/`. Completed as part of the #465 mirror pass. |
| v0.9.x — alongside `routes/facts/` decomposition | Move route tests into `node/tests/routes/`. Completed as part of the #465 mirror pass. |
| v0.9.x — alongside Pydantic models decomposition | Add `node/tests/models/` mirroring `node/src/stigmem_node/models/`. Completed as part of the #465 mirror pass. |
| v0.9.x — alongside `node/src/stigmem_node/` sub-package organization | Reorganize `node/tests/` into matching sub-directories. Completed for existing node tests by #465; future module-flattening PRs should move any new tests with their source concern. |
| Phase A — alongside ADR-011 (C1) plugin implementations | Tests move with their features to `experimental/<feature>/tests/` as part of each plugin's implementation. |
| v0.9.x — adapter hardening | Add `test_adapter_security.py` per audit findings; populate `adapters/mcp/tests/`. |
| Pre-v1.0.0-rc.0 | Confirm test/source mirror is consistent across the codebase. |

Total effort across v0.9.x: roughly **2 days of `git mv` + conftest updates**, plus the substantive new test work for `adapters/mcp/` and the audit-finding regressions.

---

## Closing thought

You're already on the right framework with the right configuration; the question wasn't really "should we use pytest" — it was "where do tests live." The answer is the convention you're already using (package-root `tests/` directories), with the discipline that internal organization within `tests/` should mirror source layout. That's the entire test-structure recommendation in one sentence.

The structural-decision sweep is complete after this. From here, the work is execution: ADRs accepted, the strengthening plan begins, the cuts land in PR 1, the security work in Weeks 3–5, and the operator soak happens as a future hardened-core gate.

---

*This concludes the structural sweep. Future structure decisions should reference the established conventions here and in the related best-practices documents.*
