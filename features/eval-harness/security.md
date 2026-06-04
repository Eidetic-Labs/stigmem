# Evaluation Harness Security

The evaluation harness validates adversarial behavior against a Stigmem node or
in-process test node. Its current `v0.9.0a11` posture is internal alpha release
evidence, not a stable external certification surface.

## Security Posture

| Area | Current control | Evidence |
| --- | --- | --- |
| Internal surface | The harness remains in-repo internal tooling with no standalone package publication. | `features/eval-harness/status.md`; `docs/internal/plugin-publication-disposition.md` |
| Adversarial scope | The corpus covers typo-squatting, contradiction floods, tombstone bypass, capability-token forgery, and sanitizer bypass. | `eval/corpus/adversarial/**/scenarios.json`; `eval/test_adversarial.py` |
| Credential handling | Live-node runs use `STIGMEM_EVAL_URL` and optional `STIGMEM_EVAL_API_KEY`; default runs use an in-process TestClient. | `eval/README.md`; `eval/harness/utils.py`; `eval/conftest.py` |
| Artifact handling | Per-run results under `eval/results/` are ignored except for intentionally tracked seed evidence, and release readiness rejects unapproved tracked result files. | `.gitignore`; `eval/results/.gitkeep`; `eval/results/ci-0b1a76a.*`; `scripts/check_release_readiness.py` |
| CI scope | The fast harness is path-filtered to eval, eval-harness feature records, Make target, node, SDK, spec, and conformance changes. | `.github/workflows/eval-fast.yml` |

## Security References

No dedicated R-* audit item is assigned to this feature. The concept maps to
security regression testing through the adversarial corpus and fast eval CI.

## Advisories and Findings

None currently recorded for the feature.

## Residual Risk

- Live-node runs must protect API keys and avoid committing generated result
  artifacts.
- Recall thresholds and baseline values are alpha gates, not a stable external
  quality claim.
- Federation soak checks depend on Docker/Colima and remain optional/manual or
  nightly unless a later release gate makes them mandatory.

## Operator Guidance

- Prefer `make eval-fast` for local a11 foundation validation.
- Use `make eval-soak-smoke` only when Docker/Colima-dependent federation soak
  validation is explicitly in scope.
- Do not publish the harness as a package until package boundaries, secrets,
  generated artifacts, and Trusted Publisher setup are deliberately reviewed.
