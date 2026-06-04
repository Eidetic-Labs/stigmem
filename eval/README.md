# Eval Harness

Behavioral evaluation suite for the stigmem reference node. Covers two pillars:

1. **Adversarial corpus** — 79 labeled attack scenarios (typo-squatting, contradiction floods, tombstone bypass, capability-token forgery, sanitizer bypass)
2. **Recall benchmark** — 400 labeled probes measuring nDCG@10 and Recall@5

## Quick start

```bash
# Full eval suite (adversarial + recall, ≤ 5 min)
make eval-fast

# Individual targets
make eval-adversarial   # 79 adversarial scenarios only
make eval-recall        # 400 recall probes only

# Freeze a new baseline after improving recall quality
make eval-fast-baseline
```

Results land in `eval/results/` as JSON + markdown:
- `adversarial-<git-sha>.log`
- `recall-<git-sha>.log`
- `ci-<git-sha>.json` + `ci-<git-sha>.md` (from the recall benchmark)

## Running against a live node

By default the harness starts an in-process test node using `fastapi.testclient.TestClient`.
To run against a real running node:

```bash
export STIGMEM_EVAL_URL=http://localhost:8765
export STIGMEM_EVAL_API_KEY=your-api-key   # omit if auth_required=false
make eval-fast
```

## Directory layout

```
eval/
  conftest.py               # pytest session fixture: in-process node + corpus loading
  test_adversarial.py       # parametrised pytest entry-point for all 79 scenarios
  test_recall.py            # pytest entry-point for 400 recall probes
  corpus/
    adversarial/
      typo_squatted/        # 20 entity pairs (10 single-char, 5 homoglyph, 5 delimiter)
      contradiction_floods/ # 9 scenarios (3 targets × K=10/50/200)
      tombstone_bypass/     # 10 scenarios (5 same-source, 5 different-source)
      capability_token/     # 15 forgery shapes
      sanitizer_bypass/     # 25 payloads (SQL, null bytes, Unicode, oversized, prompt-injection)
    recall/
      probes.json           # 400 labeled (query, gold-entity-set) probes, hash-pinned
      baseline.json         # frozen nDCG@10 with canonical corpus hash
  results/                  # JSON + markdown run artifacts (gitignored per-run files)
  harness/
    adversarial.py          # run adversarial corpus, return pass/fail per scenario
    recall.py               # run recall benchmark, return nDCG@10 + Recall@5 vs baseline
    utils.py                # shared: HTTP client, corpus loader, metric helpers
```

## CI gates

The `eval-fast` job runs on every PR via `.github/workflows/eval-fast.yml`.

**Adversarial gates** — CI fails immediately if any scenario fails its pass criterion:

| Class | Count | Criterion |
|---|---|---|
| Typo-squatted entities | 20 | Spoofed URI never in recall top-5 |
| Contradiction floods | 9 | Canonical in top-3; flood salience ≤ 0.75 |
| Tombstone bypass | 10 | fact_A absent (confidence=0 filter); fact_B present |
| Capability-token forgery | 15 | 403/401; zero fact data in response |
| Sanitizer bypass | 25 | 400 or stored sanitised |

**Recall regression gate** — nDCG@10 drop ≥ 3% relative triggers a warning on the first failure, and blocks CI on the second consecutive failure. The counter resets on any passing run (`eval/results/consecutive_failures.txt`).

## Probe classes (400 total)

| Class | Count | Description |
|---|---|---|
| entity_lookup | 100 | Direct entity+relation lookups with 5 query variants |
| relation_lookup | 100 | Relation-centric queries across 10 relation types |
| paraphrase | 100 | Open-ended natural language question variants |
| adversarial_ood | 100 | TTL-expiring (10), missing entities (30), semantic-confusing (30), OOD (30) |

## Baseline management

`eval/corpus/recall/baseline.json` schema:

```json
{
  "nDCG@10": 0.0,
  "Recall@5": 0.0,
  "corpus_sha": "<sha256[:16] of canonical sorted JSON probes>",
  "server_version": "0.9.0a1",
  "recorded_at": "<ISO8601 UTC>"
}
```

Update baseline after a quality improvement:

```bash
make eval-fast-baseline
git add eval/corpus/recall/baseline.json
git commit -m "chore(eval): update recall baseline"
```
