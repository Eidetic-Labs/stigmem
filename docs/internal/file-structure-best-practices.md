# Stigmem File Structure & Size — Best Practices and Decomposition Plan

> Survey of file-size and structure issues in the current repo, calibrated to industry best practices.
> Intended as an early hardened-core deliverable in the strengthening plan, sequenced after ADR-020 §13 (repo structure) (repo structure) lands.

> 2026-05-17 adoption note: this document preserves the 2026-05-06 baseline
> analysis that motivated the gate. Several examples in the baseline have since
> been decomposed, including the former monolithic CLI and facts/federation route
> files. The enforceable current state is `scripts/check_file_sizes.py`, which
> fails only hard-limit violations and reports soft-limit files as warnings for
> planned decomposition.

---

## Why this matters

Code review velocity is the most-overlooked engineering metric. A 1500-line file takes 10x longer to review than three 500-line files covering the same surface — not because the total lines are different, but because reviewer attention degrades with file length. For a project that operates under two-person review on every PR (or founder solo-approval, per ADR-001), large files are a per-review tax that compounds whether the founder reviews alone or with another contributor.

Structure also matters for new contributors: 40 flat `*.py` files at the top of a single module make it harder to form a mental model than 6–8 sub-packages with clear responsibilities. The discipline of moving files into the right sub-package usually surfaces unclear ownership before it becomes a bug.

This is not a "make it pretty" exercise. It's targeted at: review velocity, reviewer comprehension, contributor onboarding, and resistance to scope creep within individual files.

---

## Established best practices for file size

A synthesis of widely-adopted conventions:

| Source | Soft limit | Hard limit | Note |
|---|---|---|---|
| Robert Martin, *Clean Code* | 200 lines | 500 lines | "Files should typically be small" |
| Google Python Style | — | — | No explicit rule; flags 2000-line Java classes |
| Linux kernel (Linus) | 1000 lines | — | "If over 1000 lines, you're doing something wrong" |
| React community | 300 lines | 500 lines | Components |
| Go community | 500 lines | 1000 lines | `go vet` doesn't enforce |
| Rust community | 500 lines | 1000 lines | `clippy` doesn't enforce |

**The rule we adopt for stigmem (proposal):**

| Threshold | Behavior |
|---|---|
| **≤500 lines** | Default. No discipline cost. |
| **501–1000 lines** | Acceptable with justification. Add a comment at the top explaining why this file is larger (e.g., "this is a single FastAPI router covering 8 related endpoints; splitting would scatter the resource definition"). PR review specifically considers whether decomposition is appropriate. |
| **1001–1500 lines** | Discouraged. PR review must include a decomposition plan as a comment, even if the plan is "split in the next PR." |
| **>1500 lines** | Hard rule: do not merge without decomposition. |

These thresholds apply to source files. Auto-generated files (TypeScript types from OpenAPI, lock files) are exempt and explicitly identified.

For markdown specs, the same thresholds apply *after* ADR-020 §9 (modular specs) modular-specs decomposition lands. Pre-decomposition, the monolithic spec files are exceptions.

For tests, the soft limit is doubled (1000 lines) because parameterized test classes can legitimately exceed source-file size for the equivalent surface.

---

## Current state assessment

### Top 10 source files by line count (excluding generated)

| File | Lines | Type | Status |
|---|---|---|---|
| `node/tests/test_phase8_identity.py` | 1553 | Test | **Hard rule violation** |
| `node/src/stigmem_node/cli.py` | 1527 | Source | **Hard rule violation** |
| `node/tests/test_federation.py` | 1196 | Test | Within test soft limit |
| `eval/federation/soak_driver.py` | 1137 | Eval | Discouraged |
| `node/src/stigmem_node/routes/federation.py` | 1122 | Source | Discouraged |
| `node/src/stigmem_node/routes/facts.py` | 1031 | Source | Discouraged |
| `node/tests/tombstones/test_tombstones.py` | 970 | Test | Within test soft limit |
| `node/tests/instruction/test_phase10_instruction.py` | 948 | Test | Within test soft limit |
| `node/src/stigmem_node/routes/recall.py` | 879 | Source | Acceptable with justification |
| `node/src/stigmem_node/routes/instruction.py` | 804 | Source | Acceptable with justification |

### Spec files (separate category)

| File | Lines | Disposition |
|---|---|---|
| `spec/stigmem-spec-v2.0.md` | 3517 | Archive per ADR-020 §9 (modular specs); no decomposition needed |
| `spec/stigmem-spec-v1.1-draft.md` | 3508 | Archive (and there's a duplicate copy in `spec/archive/`) |
| `spec/stigmem-spec-v0.8-draft.md` | 2597 | Archive |
| Older drafts | 800–1700 | Archive |

The monolithic specs become irrelevant once ADR-020 §9 (modular specs) modular specs land. Each `Spec-NN-Topic-Name.md` is targeted at <500 lines.

### Auto-generated files (legitimately large)

| File | Lines | Justification |
|---|---|---|
| `sdks/stigmem-ts/src/generated.ts` | 5049 | Generated by `openapi-typescript`; not handwritten |
| `pnpm-lock.yaml` | (binary) | npm lockfile |
| `uv.lock` | (binary) | uv lockfile |

These are exempt from line-count rules. We add a `# AUTO-GENERATED` comment standard in the file header for clarity.

### Module-level concern: flat sprawl in `node/src/stigmem_node/`

40 Python files at the top of `node/src/stigmem_node/`. Existing sub-packages (`identity/`, `embedding/`, `storage/`, `routes/`, `static/`) suggest an intent to organize by concern, but most files remain at the top level.

This is not a hard rule violation but it makes the module hard to navigate. When you have 40 sibling files, no contributor has a clear mental map of which-belongs-where, and new code lands wherever feels closest rather than where it actually belongs.

---

## Recommended decompositions

### Source files requiring decomposition

#### `cli.py` (1527 lines) — split into `cli/` subpackage

The file is a flat list of `_cmd_*` handlers for argparse subcommands. It naturally decomposes by command family:

```
node/src/stigmem_node/cli/
├── __init__.py # main() entrypoint and parser construction
├── capability.py # _cmd_capability_issue / verify / revoke
├── decay.py # _cmd_decay_sweep
├── federation.py # _cmd_federation_*
├── snapshot.py # _cmd_snapshot_*
├── instruction.py # _cmd_instruction_*
├── audit.py # _cmd_audit_discovery
├── identity.py # _cmd_identity_*
├── migrate.py # _cmd_migrate_normalize_entities, _cmd_backfill_cids
└── parser.py # _build_parser
```

Each sub-file lands at 100–250 lines. The top-level `__init__.py` becomes the orchestrator.

**Effort:** 1 day. Mechanical refactor; existing tests should pass identically.
**Payoff:** when a contributor adds a new CLI command, they know exactly which file to touch.

#### `routes/facts.py` (1031 lines) — split into `routes/facts/` subpackage

The file has 5 routes, but each is large:
- `POST /v1/facts` (lines 294–662, ~370 lines) — the assert path
- `GET /v1/facts` (lines 663–828) — the query path
- `GET /v1/facts/{id}` — single-fact read
- `POST /v1/facts/{id}/verify-cid` — CID verification
- `GET /v1/facts/{id}/provenance` — provenance history

The 370-line `POST` function is the smell. Most of it is validation, scope/garden checks, tombstone filtering, attestation handling, and audit logging — separable concerns.

```
node/src/stigmem_node/routes/facts/
├── __init__.py # router construction + endpoint declarations
├── assert_handler.py # POST /v1/facts logic
├── query_handler.py # GET /v1/facts logic
├── single_fact.py # GET /v1/facts/{id} + verify-cid + provenance
├── validation.py # shared validation helpers (entity URI, scope, attestation)
└── (tombstone filtering: provided by `stigmem-plugin-tombstones` via the `recall_filter` hook per ADR-011 C1; not in core)
```

**Effort:** 2 days. Less mechanical than CLI because logic is interleaved.
**Payoff:** the assert path becomes reviewable; tombstone integration becomes a clean dependency.

#### `routes/federation.py` (1122 lines) — split into `routes/federation/` subpackage

Federation routes cluster naturally around: peer admission, replication endpoints, manifest exchange, capability tokens, quarantine promotion. Without seeing the file in detail, I recommend the same pattern: a `routes/federation/` subpackage with separate files per endpoint family.

**Effort:** 2 days.

#### `routes/recall.py` (879 lines) — split into `routes/recall/` subpackage

Recall has three pipeline stages (lexical, vector, graph) plus the orchestrator. Natural split:

```
node/src/stigmem_node/routes/recall/
├── __init__.py # router + POST /v1/recall orchestrator
├── stage_lexical.py # FTS path
├── stage_vector.py # ANN path
├── stage_graph.py # graph traversal path
└── ranking.py # combined-score logic
```

**Effort:** 1.5 days.

#### `routes/instruction.py` (804 lines) — defer

Per ADR-011, this file moves to `experimental/21-lazy-instruction-discovery/` during v0.9.x. No decomposition is required in core; the experimental package can decompose internally as it sees fit.

### Test files requiring decomposition

#### `node/tests/test_phase8_identity.py` (1553 lines) — split by test concern

Tests at 1500+ lines usually combine multiple distinct test surfaces. Identity tests likely cover: key issuance, key rotation, signature verification, capability tokens, peer authentication. Split:

```
node/tests/identity/
├── __init__.py
├── test_key_issuance.py
├── test_key_rotation.py
├── test_signature_verification.py
├── test_capability_tokens.py
└── test_peer_authentication.py
```

**Effort:** 1 day.

#### `node/tests/test_federation.py` (1196 lines) — same pattern

Split by federation concern: handshake, replication, capability admission, manifest verification, error scenarios.

**Effort:** 1 day.

#### `node/tests/tombstones/test_tombstones.py` (970 lines) — defer

Per ADR-011, tombstone code (and tests) move to `experimental/23-rtbf-tombstones/` during v0.9.x. The `experimental/` directory imposes its own structure; this test file can decompose there.

#### `eval/federation/soak_driver.py` (1137 lines) — split by phase

Soak drivers usually have setup, run, monitor, teardown phases. Split into `eval/federation/soak/` with files per phase.

**Effort:** half day.

### Module flattening: organize `node/src/stigmem_node/`

After the ADR-011 (C1) plugin implementations complete, ~10 files of feature-specific code are no longer in core (each cross-cutting feature lives in its `experimental/<feature>/` plugin package). The remaining ~30 files should be grouped into sub-packages by concern:

```
node/src/stigmem_node/
├── __init__.py
├── main.py # FastAPI app construction
├── cli/ # (per cli.py decomposition above)
├── settings.py
├── db.py
├── models.py
├── auth/ # auth.py, peer_auth.py, peer_token.py
├── identity/ # (existing)
├── embedding/ # (existing)
├── storage/ # (existing)
├── federation/ # federation_ingest.py, federation_pull.py, source_trust.py, trust_rules.py
├── recall/ # recall_pipeline.py, vector_search.py, graph.py, graph_index.py, entity_resolver.py
├── observability/ # audit_event.py, metrics.py, tracing.py
├── lifecycle/ # decay.py, snapshot.py, migrate.py, jobs.py
├── networking/ # tls.py, net_util.py, hlc.py
├── utility/ # entity_normalizer.py, cid.py
└── routes/ # (existing)
 ├── facts/
 ├── federation/
 ├── recall/
 └── ...
```

After organization, each sub-package contains 3–8 focused files. The top of `node/src/stigmem_node/` shrinks to about 6 files (entrypoint + 4 cross-cutting essentials).

**Effort:** 1 week. This is a substantial refactor that should NOT happen in Phase A of the strengthening plan. Sequence it for v0.9.x, after the experimental cuts (ADR-020 §13 (repo structure) PR 1) and the cross-cutting extractions (ADR-011) have largely landed.

---

## Files to leave alone

Worth being explicit:

- **`sdks/stigmem-ts/src/generated.ts` (5049 lines)** — auto-generated. Add a CI check that the file is regenerated correctly; otherwise leave it.
- **`adapters/openclaw/tests/test_adapter.py` (562 lines)** — within test soft limit; structure is fine.
- **`sdks/stigmem-py/src/stigmem/client.py` (578 lines)** — slightly over source soft limit but client API is naturally a single class. Acceptable with justification.
- **The migration SQL files** — all <200 lines; structure is fine. They're sequenced numerically by design.

### Pydantic models: a domain-organization exception

`node/src/stigmem_node/models.py` (652 lines, 45 classes) was originally listed here as "acceptable in one file" — that recommendation was wrong. **Pydantic model files should be organized by domain, not by data shape.** A flat `models.py` over ~10 classes is a smell; over 20 classes is a hard rule violation regardless of total line count.

The decomposition plan is in `stigmem-pydantic-decomposition-plan.md`. Briefly:

- `models.py` decomposes into `models/<domain>.py` files (facts, federation, gardens, quarantine, identity, intents, audit, provenance, conflict).
- Inline Pydantic models in `routes/*.py` that are part of the wire format also move to the appropriate domain module; only underscore-prefixed internal models stay inline.
- A backwards-compat re-export shim in `models/__init__.py` covers v0.9.x; removed in v1.0.0.

The corrected best-practice rule:

> **Pydantic model files:** organize by domain (`models/facts.py`, `models/gardens.py`, etc.), not by data shape (`models.py`, `requests.py`, `responses.py`). Group classes that change together. A flat single-file Pydantic module over 10 classes warrants decomposition; over 20 classes is a hard rule violation.

---

## Best-practice document (proposed for the repo)

Drop in at `docs/internal/file-size-and-structure.md` (or `CONTRIBUTING.md` extension).

```markdown
# File Structure and Size — Stigmem Conventions

## Source-file size limits

| Threshold | Rule |
|---|---|
| ≤500 lines | Default. No discipline cost. |
| 501–1000 lines | Acceptable with justification at the top of the file. |
| 1001–1500 lines | Discouraged. PR review must include a decomposition plan. |
| >1500 lines | Hard rule: do not merge without decomposition. |

## Test-file size limits (doubled)

| Threshold | Rule |
|---|---|
| ≤1000 lines | Default. |
| 1001–2000 lines | Acceptable with justification. |
| >2000 lines | Hard rule: split into multiple test files. |

## Auto-generated files

Files generated by tooling (OpenAPI clients, ORM models from migrations, etc.) are exempt from line limits. They MUST carry an `AUTO-GENERATED` marker in the file header so the rule is verifiable:

```
# AUTO-GENERATED by openapi-typescript on 2026-05-06.
# Do not edit; re-run scripts/generate_sdk.sh to regenerate.
```

Lockfiles (`pnpm-lock.yaml`, `uv.lock`, etc.) are exempt without markers.

## Markdown limits

Spec files, ADRs, and operator-facing documentation follow the same source thresholds. Specifically:

- Each modular spec at `spec/specs/Spec-NN-*.md` should target <500 lines.
- ADRs target <800 lines, with the longest being 1000–1200 lines for foundational decisions.
- Operator docs target <500 lines per page; longer content gets split with a sidebar entry per section.

## When to split a file

A file is a candidate for decomposition when any of the following are true:

1. **It exceeds the soft limit (500 source / 1000 test).**
2. **It contains multiple distinct responsibilities.** A single file should have one reason to change.
3. **A reader cannot form a mental model of the whole file in one sitting** (~10 minutes).
4. **PR diffs against the file are routinely too large to review carefully.**

A file is NOT a candidate for decomposition just because it's long, if:

- It contains a single logical unit (one Pydantic model class, one API client class, one parser).
- The cost of splitting is high (cross-references, circular imports).
- The length is justified in the file header.

## When to extract a sub-package

A directory of flat source files (e.g., `node/src/stigmem_node/`) is a candidate for sub-package organization when any of the following are true:

1. **More than ~15 source files at the same level.**
2. **Files cluster naturally by domain or concern** (e.g., all federation-related files; all identity-related files).
3. **New contributors regularly ask "where does file X belong?"**

The cost of sub-package organization is one-time (the moves) plus a small ongoing cost (an extra import path). The benefit is durable: contributors find code faster, reviewers know which directory to focus on, and the structure communicates the project's architecture.

## CI enforcement

The `scripts/check_file_sizes.py` CI step (added in v0.9.x) walks the repo and:

1. Reports any source file >500 lines and warns the PR author.
2. Fails the build if any source file >1500 lines does not contain a `LARGE-FILE-JUSTIFIED` marker followed by 1+ lines of justification.
3. Same for test files at the doubled thresholds.

The justification marker forces the conversation. A justified large file is acceptable; an unjustified one is a blocker.

## Decomposition checklist

When splitting a file:

- [ ] All public interfaces preserved.
- [ ] Imports updated everywhere.
- [ ] Tests pass identically before and after.
- [ ] No circular imports introduced.
- [ ] Each new file has a clear single responsibility, named accordingly.
- [ ] The original file is either deleted or contains only re-exports for backward compatibility.
- [ ] PR description includes the decomposition rationale (link this best-practice doc).

## When to revisit these conventions

These thresholds reflect the project's current scale (one product, two contributors, ~55k LOC Python). Revisit at:

- v1.0.0 GA: confirm thresholds still serve the project.
- 100k LOC: structures that work at 50k may not at 100k.
- 5+ active contributors: review velocity becomes more important.
```

This doc commits the project to discipline that's measurable, enforceable in CI, and durable.

---

## Implementation order

This work is **not Phase A strengthening-plan work.** It comes after the v0.9.0a1 reset has landed. Suggested sequencing:

### early hardened-core pass

- Adopt the best-practices doc (drop into the repo).
- Add `scripts/check_file_sizes.py` as a CI step.
- Apply `AUTO-GENERATED` markers to existing generated files.
- Banner the monolithic specs as archive (lands as part of ADR-020 §9 (modular specs) spec decomposition anyway).

### v0.9.x (alongside cross-cutting extractions per ADR-011)

- Decompose `cli.py` into `cli/` sub-package (1 day).
- Decompose `routes/facts.py` into `routes/facts/` sub-package (2 days).
- Decompose `routes/federation.py` into `routes/federation/` sub-package (2 days).
- Decompose `routes/recall.py` into `routes/recall/` sub-package (1.5 days).
- Decompose `tests/test_phase8_identity.py` into `tests/identity/` (1 day).
- Decompose `tests/test_federation.py` (1 day).
- `routes/instruction.py` and `tests/tombstones/test_tombstones.py` are absorbed into their respective plugin packages as part of the ADR-011 (C1) plugin implementations; no separate effort needed.
- `eval/federation/soak_driver.py` split into `eval/federation/soak/` (half day).

### Pre-v1.0.0-rc.0

- Module flattening: organize the remaining `node/src/stigmem_node/` files into sub-packages by concern (1 week).
- Confirm CI line-count rules pass on every file in v1.0 critical-path scope.

---

## What this is NOT

This is not a goal-the-numbers exercise. **A 600-line file with a clear single responsibility and a one-paragraph justification is fine.** The discipline is about asking "should this be smaller?" honestly on each PR, not about hitting a hard ceiling.

The thresholds exist to make the question routine, not to mandate a specific answer. PR reviewers are the calibration of last resort.

---

*This analysis is calibrated to the v0.9.0a1 reset and ADR-020 §13 (repo structure)/010/011. As the cross-cutting extractions complete, the file-size landscape changes; revisit the recommendations here at v1.0.0-rc.0.*
