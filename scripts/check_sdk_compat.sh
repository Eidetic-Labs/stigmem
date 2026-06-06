#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${SDK_COMPAT_PORT:-8876}"
URL="http://127.0.0.1:${PORT}"
DB_PATH="$(mktemp "${TMPDIR:-/tmp}/stigmem-sdk-compat.XXXXXX.db")"
LOG_PATH="$(mktemp "${TMPDIR:-/tmp}/stigmem-sdk-compat.XXXXXX.log")"
NODE_PID=""

cleanup() {
  if [[ -n "${NODE_PID}" ]] && kill -0 "${NODE_PID}" 2>/dev/null; then
    kill "${NODE_PID}" || true
    wait "${NODE_PID}" || true
  fi
  rm -f "${DB_PATH}" "${LOG_PATH}"
}
trap cleanup EXIT

pnpm_cmd() {
  if command -v pnpm >/dev/null 2>&1; then
    pnpm "$@"
  else
    corepack pnpm "$@"
  fi
}

cd "${ROOT_DIR}"

uv sync --all-packages >/dev/null
pnpm_cmd install --frozen-lockfile >/dev/null
pnpm_cmd --filter stigmem-ts build >/dev/null

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
  echo "SDK compatibility smoke failed to start the node." >&2
  cat "${LOG_PATH}" >&2
  exit 1
fi

uv run python - <<'PY' "${URL}"
import sys
from stigmem import StigmemClient, string_value

url = sys.argv[1]
client = StigmemClient(url=url)
fact = client.assert_fact(
    entity="compat:shared",
    relation="compat:python",
    value=string_value("ok"),
    source="agent:compat-python",
)
assert fact.relation == "compat:python"
page = client.query(entity="compat:shared", scope="company", limit=20)
assert any(f.relation == "compat:python" for f in page.facts)
client.close()
PY

node - <<'JS' "${URL}"
const { StigmemClient, sv } = require("./sdks/stigmem-ts/dist/index.js");

async function main() {
  const client = new StigmemClient({ url: process.argv[2] });
  const fact = await client.assertFact("compat:shared", "compat:ts", sv("ok"), "agent:compat-ts");
  if (fact.relation !== "compat:ts") throw new Error("ts assert failed");
  const page = await client.query({ entity: "compat:shared", scope: "company", limit: 20 });
  if (!page.facts.some((f) => f.relation === "compat:ts")) {
    throw new Error("ts query failed");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
JS

GO_SMOKE_FILE_BASE="$(mktemp "${TMPDIR:-/tmp}/stigmem-go-compat.XXXXXX")"
GO_SMOKE_FILE="${GO_SMOKE_FILE_BASE}.go"
mv "${GO_SMOKE_FILE_BASE}" "${GO_SMOKE_FILE}"
cat >"${GO_SMOKE_FILE}" <<'EOF'
package main

import (
	"context"
	"fmt"
	"os"

	stigmem "github.com/eidetic-labs/stigmem-go"
)

func main() {
	if len(os.Args) != 2 {
		panic("expected node url")
	}
	client := stigmem.New(os.Args[1])
	fact, err := client.AssertFact(
		context.Background(),
		"compat:shared",
		"compat:go",
		stigmem.StringValue("ok"),
		"agent:compat-go",
	)
	if err != nil {
		panic(err)
	}
	if fact.Relation != "compat:go" {
		panic(fmt.Sprintf("unexpected relation %s", fact.Relation))
	}
	page, err := client.QueryFacts(
		context.Background(),
		stigmem.QueryEntity("compat:shared"),
		stigmem.QueryScope(stigmem.ScopeCompany),
		stigmem.QueryLimit(20),
	)
	if err != nil {
		panic(err)
	}
	for _, item := range page.Facts {
		if item.Relation == "compat:go" {
			return
		}
	}
	panic("go query failed")
}
EOF
# Go SDK was deferred to experimental/sdk-go/ per PR 3 (ADR-002 critical-
# path cut + ADR-020 repository contracts). The compat smoke test now runs only when an
# operator opts in by leaving the experimental Go SDK present.
if [ -d "${ROOT_DIR}/experimental/sdk-go" ]; then
	(cd "${ROOT_DIR}/experimental/sdk-go" && go run "${GO_SMOKE_FILE}" "${URL}")
elif [ -d "${ROOT_DIR}/sdks/stigmem-go" ]; then
	(cd "${ROOT_DIR}/sdks/stigmem-go" && go run "${GO_SMOKE_FILE}" "${URL}")
else
	echo "Go SDK compat: experimental/sdk-go/ not present; skipping (deferred per ADR-002)"
fi
rm -f "${GO_SMOKE_FILE}"

uv run python - <<'PY' "${URL}"
import sys
from stigmem import StigmemClient

client = StigmemClient(url=sys.argv[1])
page = client.query(entity="compat:shared", scope="company", limit=20)
relations = {fact.relation for fact in page.facts}
expected = {"compat:python", "compat:ts", "compat:go"}
missing = expected - relations
if missing:
    raise SystemExit(f"Missing compatibility facts: {sorted(missing)}")
client.close()
PY

echo "SDK compatibility smoke passed against ${URL}"
