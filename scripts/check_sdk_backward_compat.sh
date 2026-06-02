#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPAT_TAG="${SDK_BACKWARD_COMPAT_TAG:-v0.9.0a9}"
PORT="${SDK_BACKWARD_COMPAT_PORT:-8877}"
URL="http://127.0.0.1:${PORT}"
REPORT_PATH="${SDK_BACKWARD_COMPAT_REPORT:-${ROOT_DIR}/artifacts/sdk-backward-compat.json}"
WORKTREE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stigmem-sdk-backward-compat.XXXXXX")"
PYTHON_VENV_DIR="$(mktemp -d "${TMPDIR:-/tmp}/stigmem-sdk-backward-compat-venv.XXXXXX")"
DB_PATH="$(mktemp "${TMPDIR:-/tmp}/stigmem-sdk-backward-compat.XXXXXX.db")"
LOG_PATH="$(mktemp "${TMPDIR:-/tmp}/stigmem-sdk-backward-compat.XXXXXX.log")"
NODE_PID=""
PNPM_SHIM_DIR=""

cleanup() {
  if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
    kill "${NODE_PID}" || true
    wait "${NODE_PID}" || true
  fi
  git worktree remove --force "${WORKTREE_DIR}" >/dev/null 2>&1 || true
  rm -rf "${WORKTREE_DIR}" "${PYTHON_VENV_DIR}" "${DB_PATH}" "${LOG_PATH}"
  if [[ -n "${PNPM_SHIM_DIR}" ]]; then
    rm -rf "${PNPM_SHIM_DIR}"
  fi
}
trap cleanup EXIT

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

need_cmd git
need_cmd curl
need_cmd uv
need_cmd python3
need_cmd node

cd "${ROOT_DIR}"
git rev-parse "${COMPAT_TAG}^{commit}" >/dev/null
mkdir -p "$(dirname "${REPORT_PATH}")"

git worktree add --detach "${WORKTREE_DIR}" "${COMPAT_TAG}" >/dev/null
uv sync --all-packages >/dev/null

env \
  STIGMEM_AUTH_REQUIRED=false \
  STIGMEM_HOST=127.0.0.1 \
  STIGMEM_PORT="${PORT}" \
  STIGMEM_DB_PATH="${DB_PATH}" \
  STIGMEM_PLUGIN_AUTO_DISCOVERY_ENABLED=false \
  uv run python -m stigmem_node.main >"${LOG_PATH}" 2>&1 &
NODE_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "${URL}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! curl -fsS "${URL}/healthz" >/dev/null 2>&1; then
  echo "Backward compatibility check failed to start the current node." >&2
  cat "${LOG_PATH}" >&2
  exit 1
fi

python3 -m venv "${PYTHON_VENV_DIR}"
"${PYTHON_VENV_DIR}/bin/pip" install --quiet "${WORKTREE_DIR}/sdks/stigmem-py"
"${PYTHON_VENV_DIR}/bin/python" - "${URL}" <<'PY'
import sys

from stigmem import StigmemClient, string_value

url = sys.argv[1]
client = StigmemClient(url=url)
fact = client.assert_fact(
    entity="compat:legacy-shared",
    relation="compat:python-rc",
    value=string_value("ok"),
    source="agent:compat-python-rc",
)
assert fact.relation == "compat:python-rc"
page = client.query(entity="compat:legacy-shared", scope="company", limit=20)
assert any(f.relation == "compat:python-rc" for f in page.facts)
client.close()
PY

(
  cd "${WORKTREE_DIR}"
  pnpm_cmd install --frozen-lockfile >/dev/null
)
(
  cd "${WORKTREE_DIR}/sdks/stigmem-ts"
  pnpm_cmd build >/dev/null
)
node - <<'JS' "${WORKTREE_DIR}" "${URL}"
const path = require("node:path");

const worktree = process.argv[2];
const url = process.argv[3];
const { StigmemClient, sv } = require(path.join(worktree, "sdks", "stigmem-ts", "dist", "index.js"));

async function main() {
  const client = new StigmemClient({ url });
  const fact = await client.assertFact(
    "compat:legacy-shared",
    "compat:ts-rc",
    sv("ok"),
    "agent:compat-ts-rc",
  );
  if (fact.relation !== "compat:ts-rc") {
    throw new Error(`unexpected relation ${fact.relation}`);
  }
  const page = await client.query({ entity: "compat:legacy-shared", scope: "company", limit: 20 });
  if (!page.facts.some((item) => item.relation === "compat:ts-rc")) {
    throw new Error("missing ts rc compatibility fact");
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
JS

uv run python - "${URL}" "${REPORT_PATH}" "${COMPAT_TAG}" <<'PY'
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from stigmem import StigmemClient

url = sys.argv[1]
report_path = Path(sys.argv[2])

client = StigmemClient(url=url)
page = client.query(entity="compat:legacy-shared", scope="company", limit=20)
relations = {fact.relation for fact in page.facts}
expected = {"compat:python-rc", "compat:ts-rc"}
missing = sorted(expected - relations)
if missing:
    raise SystemExit(f"Missing backward compatibility facts: {missing}")
client.close()

report_path.write_text(
    json.dumps(
        {
            "release_tag": sys.argv[3],
            "server_url": url,
            "recorded_at": datetime.now(UTC).isoformat(),
            "results": [
                {"sdk": "python", "version_source": sys.argv[3], "status": "passed"},
                {"sdk": "typescript", "version_source": sys.argv[3], "status": "passed"},
                {
                    "sdk": "go",
                    "version_source": None,
                    "status": "not_applicable",
                    "reason": "No Go SDK exists in the v1.0-rc source baseline.",
                },
            ],
        },
        indent=2,
    )
    + "\n"
)
PY

echo "Backward SDK compatibility checks passed against ${URL} using ${COMPAT_TAG}"
