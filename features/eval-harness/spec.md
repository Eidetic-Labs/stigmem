# Evaluation Harness Spec

The evaluation harness defines internal alpha validation for Stigmem
correctness and quality. It combines adversarial security scenarios with
recall-quality benchmarks, running by default against an in-process test node
and optionally against a live node.

## Suites

| Suite | Focus | Current corpus |
| --- | --- |
| Adversarial scenarios | Typo-squatting, contradiction floods, tombstone bypass, capability-token forgery, and sanitizer bypass. | 79 scenarios in `eval/corpus/adversarial/**/scenarios.json`. |
| Recall benchmarks | nDCG@10 and Recall@5 against seeded corpus probes. | 400 probes in `eval/corpus/recall/probes.json` with `baseline.json`. |

## Configuration

| Setting | Purpose |
| --- | --- |
| `STIGMEM_EVAL_URL` | Target live node for evaluation. |
| `STIGMEM_EVAL_API_KEY` | Optional API key for authenticated nodes. |

When `STIGMEM_EVAL_URL` is unset, pytest fixtures run against an in-process
FastAPI TestClient.

## Artifacts

| Artifact | Purpose |
| --- | --- |
| `eval/test_adversarial.py` | Pytest entry point for adversarial scenarios. |
| `eval/test_recall.py` | Pytest entry point for recall probes and baseline regression checks. |
| `eval/harness/adversarial.py` | Adversarial scenario runner and result shaping. |
| `eval/harness/recall.py` | Recall benchmark runner, nDCG@10, Recall@5, baseline handling. |
| `eval/harness/utils.py` | Shared HTTP client, corpus loading, metrics, and corpus hashing. |
| `eval/results/` | Tracked seed/result evidence plus ignored per-run artifacts. |
| `.github/workflows/eval-fast.yml` | Path-filtered CI workflow for the fast eval subset. |

The recall baseline `corpus_sha` is the harness canonical sorted-JSON hash from
`eval.harness.utils.corpus_sha`, not the raw file digest of `probes.json`.

## Out of Scope

- Publishing a standalone `stigmem-eval-harness` package in the first a11 pass.
- Treating alpha eval results as stable external certification.
- Making Docker/Colima-dependent soak checks a required tag gate without a
  separate maintainer decision.

## Spec Assignment

There is no Spec-X assignment for the evaluation harness. It is internal
tooling rather than a protocol-bearing feature.
