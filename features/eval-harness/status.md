# Evaluation Harness Status

The evaluation harness is active experimental internal tooling for the
`v0.9.0a11` release lane. The repository now contains a runnable `eval/`
implementation with adversarial and recall corpora, pytest entry points, Make
targets, CI wiring, and tracked baseline/result artifacts.

## Lifecycle

| Field | Value |
| --- | --- |
| Status | `active` |
| Stability | `experimental` |
| Default surface | `internal` |
| Owner | `unowned` |
| Package | `none` |
| Implementation | `eval` |
| Publication state | `internal` - runnable foundation tooling is validated in-repo; standalone `stigmem-eval-harness` packaging remains deferred. |

## Release History

| Release line | State | Evidence |
| --- | --- | --- |
| `v0.9.0a1` | Evaluation harness concept documentation existed outside the supported artifact set. | `experimental/eval-harness/concept.md`; `experimental/eval-harness/STATUS.md` |
| `v0.9.0a11` planned | Reconcile the feature record with the runnable internal harness foundation: 79 adversarial scenarios, 400 recall probes, `make eval-fast`, and the path-filtered eval-fast CI workflow. | `eval/README.md`; `eval/test_adversarial.py`; `eval/test_recall.py`; `.github/workflows/eval-fast.yml`; this feature record |

## Gates

| Gate | Status | Notes |
| --- | --- | --- |
| Concept inventory | Complete | `experimental/eval-harness/concept.md` describes intended suites and metrics. |
| Feature record | Complete | ADR-020 feature record added under `features/eval-harness`. |
| Runnable harness | Complete | `eval/test_adversarial.py`, `eval/test_recall.py`, and `eval/harness/*.py` are present. |
| Corpus fixtures | Complete | `eval/corpus/adversarial/**/scenarios.json` contains 79 scenarios; `eval/corpus/recall/probes.json` contains 400 probes. |
| CI integration | Complete | `.github/workflows/eval-fast.yml` runs the fast harness on eval, eval-harness feature record, Make target, node, SDK, spec, and conformance changes. |
| Live-node validation | Partial | The default path uses an in-process FastAPI TestClient; `STIGMEM_EVAL_URL` and `STIGMEM_EVAL_API_KEY` support operator-run live-node validation. |
| Ownership | Open | Owner remains unassigned. |

## Current Gaps

- Standalone `stigmem-eval-harness` packaging is intentionally out of scope for
  the first a11 foundation pass.
- Recall baseline values are alpha placeholders until a maintainer freezes a
  quality-improvement baseline with `make eval-fast-baseline`.
- The harness is release evidence for internal alpha gating, not a stable
  external certification surface.
