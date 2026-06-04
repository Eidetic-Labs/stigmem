# Evaluation Harness Evidence

## Implementation Evidence

| Path | Evidence |
| --- | --- |
| `eval/README.md` | Operator-facing harness overview, corpus counts, CI gates, and baseline guidance. |
| `eval/test_adversarial.py` | Pytest entry point for the 79-scenario adversarial corpus. |
| `eval/test_recall.py` | Pytest entry point for 400 recall probes and nDCG@10 regression behavior. |
| `eval/harness/adversarial.py` | Adversarial runner implementation. |
| `eval/harness/recall.py` | Recall benchmark implementation and baseline writer. |
| `eval/harness/utils.py` | Shared HTTP client, corpus loader, metrics, and canonical corpus hashing. |
| `eval/corpus/adversarial/**/scenarios.json` | 79 adversarial scenarios across typo-squatting, contradiction floods, tombstone bypass, capability-token forgery, and sanitizer bypass. |
| `eval/corpus/recall/probes.json` | 400 labeled recall probes. |
| `eval/corpus/recall/baseline.json` | Alpha recall baseline schema and canonical corpus hash. |
| `eval/results/` | Tracked seed result evidence plus ignored per-run result artifacts; release readiness rejects unapproved tracked result files. |
| `.github/workflows/eval-fast.yml` | Path-filtered CI workflow for fast adversarial and recall validation, including eval harness feature-record changes. |
| `Makefile` | `eval-fast`, `eval-adversarial`, `eval-recall`, `eval-fast-baseline`, `eval-soak-smoke`, and `eval-soak` targets. |

## Test Evidence

| Command | Evidence |
| --- | --- |
| `make eval-adversarial` | Runs the adversarial pytest entry point and writes `eval/results/adversarial-<sha>.log`. |
| `make eval-recall` | Runs the recall pytest entry point and writes `eval/results/recall-<sha>.log` plus JSON/Markdown summaries. |
| `make eval-fast` | Runs adversarial and recall suites together; expected local budget is documented as five minutes or less. |
| `uv run python scripts/validate_adversarial_corpus.py` | Validates ADR-015 adversarial corpus structure. |
| `uv run python scripts/validate_adversarial_results.py` | Validates the ADR-015 certification results index. |
| `.github/workflows/eval-fast.yml` | CI validation for eval, eval-harness feature records, Make target, node, SDK, spec, and conformance path changes. |

## Documentation Evidence

| Path | Evidence |
| --- | --- |
| `experimental/eval-harness/concept.md` | Legacy concept documentation retained for historical context. |
| `experimental/eval-harness/STATUS.md` | Compatibility pointer to this canonical feature record. |
| `docs/internal/feature-tracker.md` | Migration inventory row for active internal eval tooling. |
| `docs/internal/plugin-publication-disposition.md` | Records that the eval harness is internal tooling, not a plugin publication target. |

## Validation Commands

Use repository eval and docs checks for feature-record and projection
validation:

```bash
make eval-fast
uv run python scripts/validate_adversarial_corpus.py
uv run python scripts/validate_adversarial_results.py
python3 scripts/check_feature_records.py
python3 scripts/check_feature_projections.py
python3 scripts/check_feature_security_projection.py
python3 scripts/check_feature_changelog_projection.py
python3 scripts/check_feature_compatibility_projection.py
python3 scripts/check_feature_protocol_projection.py
CHECK_SKIP_DOCS_INSTALL=1 bash scripts/check.sh docs
python3 scripts/check_release_readiness.py --no-milestone-check
```

## Limitations

- The current recall baseline is an alpha placeholder until a maintainer freezes
  a quality-improvement baseline.
- Live-node runs are supported by environment variables but are not yet a
  required release gate.
- Standalone package publication evidence is intentionally absent for the a11
  internal foundation pass.
