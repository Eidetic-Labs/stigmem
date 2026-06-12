#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PNPM_SHIM_DIR=""
TIMING_LINES=()

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

ensure_pnpm() {
  if command -v pnpm >/dev/null 2>&1; then
    return
  fi
  need_cmd corepack
  if [[ -z "${PNPM_SHIM_DIR}" ]]; then
    PNPM_SHIM_DIR="$(mktemp -d)"
    cat >"${PNPM_SHIM_DIR}/pnpm" <<'EOF'
#!/usr/bin/env bash
exec corepack pnpm "$@"
EOF
    chmod +x "${PNPM_SHIM_DIR}/pnpm"
    export PATH="${PNPM_SHIM_DIR}:${PATH}"
  fi
}

pnpm_cmd() {
  ensure_pnpm
  pnpm "$@"
}

pytest_args() {
  local args=("-q" "--tb=short")
  if [[ -n "${PYTEST_TIMEOUT_SECONDS:-}" ]]; then
    args+=("--timeout=${PYTEST_TIMEOUT_SECONDS}")
  fi
  printf '%s\n' "${args[@]}"
}

timed_run() {
  local name="$1"
  shift
  local start_ms end_ms duration_ms
  start_ms="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  "$@"
  end_ms="$(python3 -c 'import time; print(time.time_ns() // 1_000_000)')"
  duration_ms="$((end_ms - start_ms))"
  TIMING_LINES+=("${name}:${duration_ms}")
}

write_timing_report() {
  local output_path="${CHECK_TIMING_OUTPUT:-}"
  [[ -n "${output_path}" ]] || return 0
  python3 - "$output_path" "${TIMING_LINES[@]}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
rows = []
for raw in sys.argv[2:]:
    name, duration_ms = raw.split(":", 1)
    rows.append(
        {
            "name": name,
            "duration_ms": int(duration_ms),
            "duration_s": round(int(duration_ms) / 1000, 3),
        }
    )
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
PY
}

run_python() {
  need_cmd uv
  cd "$ROOT_DIR"
  if [[ "${CHECK_SKIP_PYTHON_SYNC:-0}" != "1" ]]; then
    timed_run python-sync uv sync --all-packages
  fi

  local common_pytest_args=()
  while IFS= read -r arg; do
    common_pytest_args+=("$arg")
  done < <(pytest_args)
  timed_run python-ruff-baseline uv run python scripts/check_ruff_baseline.py
  timed_run python-mypy-baseline uv run python scripts/check_mypy_baseline.py
  timed_run python-sdk-ruff uv run ruff check sdks/stigmem-py/src sdks/stigmem-py/tests
  timed_run python-sdk-mypy uv run mypy \
    --show-error-codes \
    --hide-error-context \
    --no-color-output \
    --no-pretty \
    sdks/stigmem-py/src
  local junit_dir="${PYTEST_JUNIT_DIR:-}"
  local core_args=("${common_pytest_args[@]}")
  local adapter_args=("${common_pytest_args[@]}")
  if [[ -n "${junit_dir}" ]]; then
    mkdir -p "${junit_dir}"
    core_args+=("--junitxml=${junit_dir}/python-core.xml")
    adapter_args+=("--junitxml=${junit_dir}/python-adapters.xml")
  fi
  # Wrap core-pytest in `coverage run` so the produced .coverage file feeds
  # the coverage-baseline ratchet step in CI (scripts/check_coverage_baseline.py).
  # Adapter tests stay outside coverage measurement (the ratchet only tracks node/src).
  timed_run python-core-pytest uv run coverage run -m pytest \
    "${core_args[@]}" node/tests/ sdks/stigmem-py/tests/
  timed_run python-adapter-pytest uv run pytest "${adapter_args[@]}" adapters/

  timed_run python-pip-audit uv run pip-audit --progress-spinner off
  timed_run python-bandit uv run bandit -r node/src/ sdks/stigmem-py/src/ -c pyproject.toml -q
  timed_run python-constant-time uv run python scripts/check_constant_time.py node/src/ sdks/stigmem-py/src/
  timed_run python-admin-determination uv run python scripts/check_admin_determination_consistency.py
  timed_run python-tenant-resolution uv run python scripts/check_tenant_resolution_consistency.py
  timed_run python-fact-query-tenant-scope uv run python scripts/check_fact_query_tenant_scope.py
  timed_run python-manifest-key-unification uv run python scripts/check_manifest_key_unification.py
  timed_run python-federation-v2-origin uv run python scripts/check_federation_v2_origin.py
  timed_run python-federation-relay-egress uv run python scripts/check_federation_relay_egress.py
  timed_run python-plugin-readme-sections uv run python scripts/check_plugin_readme_sections.py
  timed_run python-plugin-manifest-version uv run python scripts/check_plugin_manifest_version_consistency.py
  timed_run python-plugin-readme-pypi-consistency uv run python scripts/check_plugin_readme_pypi_consistency.py
  timed_run python-mcp-readme-consistency uv run python scripts/check_mcp_readme_consistency.py
  timed_run python-readme-shape uv run python scripts/check_readme_shape.py
  timed_run python-facts-immutability-inventory uv run python scripts/check_facts_immutability_inventory.py
  timed_run python-adr-references uv run python scripts/check_adr_references.py
  write_timing_report
}

run_node() {
  need_cmd node
  cd "$ROOT_DIR"
  if [[ "${CHECK_SKIP_NODE_INSTALL:-0}" != "1" ]]; then
    pnpm_cmd install --frozen-lockfile
  fi

  timed_run build pnpm_cmd build
  timed_run type-check pnpm_cmd type-check
  timed_run stigmem-ts-test pnpm_cmd --filter stigmem-ts test
  timed_run stigmem-mcp-test pnpm_cmd --filter stigmem-mcp test
  timed_run dashboard-test pnpm_cmd --filter dashboard test
  timed_run pnpm-audit pnpm_cmd audit --audit-level=moderate

  (
    cd "$ROOT_DIR/sdks/stigmem-ts"
    timed_run ts-smoke pnpm_cmd exec esbuild src/index.ts \
      --bundle \
      --platform=node \
      --format=cjs \
      --outfile=dist/smoke.cjs \
      --log-level=warning
    node -e "const s = require('./dist/smoke.cjs'); console.log('esbuild smoke OK — exports:', Object.keys(s).join(', '))"
  )
  write_timing_report
}

run_go() {
  need_cmd go
  # Go SDK was deferred to experimental/ per PR 3 (ADR-002 critical-path
  # cut + ADR-020 repository contracts). Per master-checklist §4.4 "skip experimental/ in
  # default jobs"; this gate now runs only against the experimental tree
  # when an operator opts in.
  if [[ ! -d "$ROOT_DIR/experimental/sdk-go" ]]; then
    echo "Go SDK gate: experimental/sdk-go/ not present; skipping (deferred per ADR-002)"
    return 0
  fi
  cd "$ROOT_DIR/experimental/sdk-go"
  go test ./...
}

run_docs() {
  need_cmd npm
  cd "$ROOT_DIR"
  timed_run feature-records python3 scripts/check_feature_records.py
  timed_run feature-projections python3 scripts/check_feature_projections.py
  timed_run feature-security-projection python3 scripts/check_feature_security_projection.py
  timed_run feature-changelog-projection python3 scripts/check_feature_changelog_projection.py
  timed_run feature-compatibility-projection python3 scripts/check_feature_compatibility_projection.py
  timed_run feature-protocol-projection python3 scripts/check_feature_protocol_projection.py
  timed_run documentation-ownership python3 scripts/check_documentation_ownership.py
  timed_run plugin-publication-disposition python3 scripts/check_plugin_publication_disposition.py
  timed_run docs-drift python3 scripts/check_docs_drift.py
  cd "$ROOT_DIR/docs"
  if [[ "${CHECK_SKIP_DOCS_INSTALL:-0}" != "1" ]]; then
    npm ci --ignore-scripts
  fi
  npm run build
}

run_obsidian() {
  need_cmd npm
  # Obsidian plugin was deferred to experimental/ per PR 3 (ADR-002 critical-
  # path cut + ADR-020 repository contracts). Per master-checklist §4.4 "skip experimental/
  # in default jobs"; this gate now runs only against the experimental
  # tree when an operator opts in.
  if [[ ! -d "$ROOT_DIR/experimental/obsidian-adapter/plugin" ]]; then
    echo "Obsidian plugin gate: experimental/obsidian-adapter/plugin not present; skipping (deferred per ADR-002)"
    return 0
  fi
  cd "$ROOT_DIR/experimental/obsidian-adapter/plugin"
  if [[ "${CHECK_SKIP_OBSIDIAN_INSTALL:-0}" != "1" ]]; then
    npm ci
  fi
  npm test
  npm run build
}

usage() {
  cat <<'EOF'
Usage: scripts/check.sh [all|python|node|contract|go|docs|obsidian]

Runs the fast repository gates locally. "all" is the PR-equivalent bundle.
EOF
}

run_contract() {
  need_cmd uv
  need_cmd node
  cd "$ROOT_DIR"

  if [[ "${CHECK_SKIP_PYTHON_SYNC:-0}" != "1" ]]; then
    uv sync --all-packages
  fi

  uv run python scripts/export_openapi.py --check
  uv run python scripts/generate_protocol_md.py --check

  if [[ "${CHECK_SKIP_NODE_INSTALL:-0}" != "1" ]]; then
    pnpm_cmd install --frozen-lockfile
  fi

  local generated_tmp
  generated_tmp="$(mktemp)"
  (
    cd "$ROOT_DIR/sdks/stigmem-ts"
    pnpm_cmd exec openapi-typescript ../../docs/openapi/stigmem.json -o "$generated_tmp" --root-types
  )
  uv run python scripts/mark_openapi_typescript_generated.py "$generated_tmp"
  diff -u "$ROOT_DIR/sdks/stigmem-ts/src/generated.ts" "$generated_tmp"
  rm -f "$generated_tmp"
}

case "${1:-all}" in
  all)
    run_python
    run_node
    run_contract
    run_go
    run_docs
    run_obsidian
    ;;
  python)
    run_python
    ;;
  node)
    run_node
    ;;
  contract)
    run_contract
    ;;
  go)
    run_go
    ;;
  docs)
    run_docs
    ;;
  obsidian)
    run_obsidian
    ;;
  *)
    usage
    exit 1
    ;;
esac
