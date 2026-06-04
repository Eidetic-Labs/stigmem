---
title: Eval Harness
sidebar_label: Eval Harness
description: Adversarial and recall benchmarks for verifying node correctness and detecting regressions.
audience: Operator
---

# Eval Harness

**Audience:** Node operators and independent implementers validating correctness, security posture, and recall quality.

The Stigmem eval harness is a two-part test suite — **adversarial scenarios** (security) and **recall benchmarks** (quality) — that runs against a live node. It ships in the `eval/` directory and executes in CI on every push via the `eval-fast` workflow.

---

## What it tests

| Suite | Scenarios | Focus |
|-------|-----------|-------|
| Adversarial | 79 | Security: typo-squatting, contradiction floods, tombstone bypass, capability-token forgery, sanitizer bypass |
| Recall | 400 probes | Quality: nDCG@10 and Recall@5 against a 20-entity corpus with four probe classes |

---

## Running the eval harness

### Prerequisites

- A running Stigmem node (local or remote)
- Python 3.11+
- [uv](https://docs.astral.sh/uv/) for dependency management

### Quick start

```bash
# Install dependencies
uv sync --all-packages

# Run adversarial suite (79 scenarios)
STIGMEM_EVAL_URL=http://localhost:8765 \
STIGMEM_EVAL_API_KEY=sk-... \
  uv run pytest eval/test_adversarial.py -v --tb=short

# Run recall benchmark (400 probes)
STIGMEM_EVAL_URL=http://localhost:8765 \
STIGMEM_EVAL_API_KEY=sk-... \
  uv run pytest eval/test_recall.py -v --tb=short
```

Results are written to `eval/results/`.

---

## Adversarial corpus — 79 scenarios

The adversarial suite tests the node's resistance to five attack classes:

### Typo-squatting (20 scenarios)

Verifies that the recall ranker does not confuse visually similar entity names:

- **Single-char mutations** — `user:alice` vs `user:a1ice`
- **Homoglyph substitutions** — Unicode lookalikes (Cyrillic а for Latin a)
- **Delimiter spoofs** — `user:alice` vs `user_alice` vs `user.alice`

Pass criterion: the spoofed entity must **not** appear in the top-5 recall results for the canonical entity's query.

### Contradiction floods (9 scenarios)

Asserts K contradicting facts for 3 target entities (K ∈ {10, 50, 200}) and verifies that:

- The contradiction counter increments correctly.
- The canonical fact's effective confidence degrades according to the source-trust model.
- Recall does not surface low-confidence flood facts above the canonical fact.

### Tombstone bypass (10 scenarios)

Verifies that tombstoned entities are fully suppressed:

- **Same-source retraction** (5 scenarios) — the entity's own source tombstones it.
- **Different-source retraction** (5 scenarios) — an admin tombstones an entity asserted by another source.

Pass criterion: tombstoned entities must return zero results from both query and recall.

### Capability-token forgery (15 scenarios)

Tests various token manipulation attacks:

- Expired tokens, tampered payloads, wrong-key signatures, truncated tokens, replayed tokens.

Pass criterion: the node must reject the request with `401` or `403`.

### Sanitizer bypass (25 scenarios)

Probes the recall-time content sanitizer with:

- SQL injection payloads
- Null-byte injection
- Unicode normalization attacks
- Oversized payloads
- Prompt-injection sentinels

Pass criterion: the sanitizer strips or rejects the payload without returning unsanitized content.

---

## Recall benchmark — 400 probes

The recall suite measures retrieval quality against a seeded 20-entity corpus.

### Probe classes

| Class | Count | Description |
|-------|-------|-------------|
| Entity lookup | 100 | Direct entity + relation queries with 5 query variants each |
| Relation lookup | 100 | Relation-centric queries across 10 relation types |
| Paraphrase | 100 | Open-ended natural-language query variants |
| Adversarial OOD | 100 | TTL-expiring facts, missing entities, semantic confounders, out-of-distribution queries |

### Metrics

| Metric | Description |
|--------|-------------|
| **nDCG@10** | Normalized discounted cumulative gain at rank 10 — measures ranking quality |
| **Recall@5** | Proportion of relevant facts in the top 5 results — measures coverage |

### Baseline and regression gating

The recall suite compares against `eval/corpus/recall/baseline.json`:

```json
{
  "nDCG@10": 0.87,
  "Recall@5": 0.92,
  "corpus_sha": "abc123...",
  "server_version": "0.8.0",
  "recorded_at": "2026-05-01T00:00:00Z"
}
```

- A **3% drop** in nDCG@10 or Recall@5 triggers a CI warning.
- A **second consecutive failure** blocks the CI pipeline.
- Consecutive failure state is tracked in `eval/results/consecutive_failures.txt`.

To update the baseline after intentional ranking changes:

```bash
STIGMEM_EVAL_URL=http://localhost:8765 \
STIGMEM_EVAL_API_KEY=sk-... \
  uv run python -m eval.harness.recall --save-baseline
```

---

## CI integration

The `eval-fast` GitHub Actions workflow runs both suites on every push to `main`, `phase/**`, and `feat/**` branches:

```yaml
# .github/workflows/eval-fast.yml
name: Eval fast subset
on:
  pull_request:
  push:
    branches: ["main", "phase/**", "feat/**"]
```

Total CI budget: **≤ 5 minutes** for both suites. Artifacts are uploaded to GitHub Actions and retained for 30 days.

### Verification steps

The workflow also verifies:

1. **Adversarial scenario count** — exactly 79 scenarios across all 5 classes.
2. **Recall probe count** — exactly 400 probes in `eval/corpus/recall/probes.json`.
3. **Baseline schema** — `baseline.json` contains all required fields.

---

## Running against independent implementations

The eval harness is designed to be run against any spec-compliant node, not just the reference implementation. Point `STIGMEM_EVAL_URL` at your node:

```bash
STIGMEM_EVAL_URL=https://your-node.example.com \
STIGMEM_EVAL_API_KEY=sk-... \
  uv run pytest eval/ -v
```

The adversarial suite is the minimum bar for security compliance. The recall benchmark provides a quality baseline — independent implementations may have different ranking characteristics, but should not fall below the regression threshold.

---

## Corpus structure

```
eval/
├── corpus/
│   ├── adversarial/
│   │   ├── typo_squatted/       # 20 scenarios
│   │   ├── contradiction_floods/ # 9 scenarios
│   │   ├── tombstone_bypass/    # 10 scenarios
│   │   ├── capability_token/    # 15 scenarios
│   │   └── sanitizer_bypass/    # 25 scenarios
│   └── recall/
│       ├── probes.json          # 400 recall probes
│       └── baseline.json        # nDCG@10, Recall@5 baseline
├── harness/
│   ├── adversarial.py           # Adversarial runner
│   ├── recall.py                # Recall benchmark runner
│   └── utils.py                 # Shared HTTP client, metric helpers
├── test_adversarial.py          # pytest entry point
├── test_recall.py               # pytest entry point
└── results/                     # Output artifacts (gitignored)
```

---

## See also

- [Observability](./) — Prometheus metrics and OpenTelemetry tracing
- [Security section](../../security/) — threat model and pen-test handbook
- [Conformance guide](../../operators/conformance.md) — spec conformance testing
