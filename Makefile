.PHONY: sdk-ts sdk-ts-generate sdk-ts-build sdk-ts-test sdk-ts-pack help \
        check check-python check-node check-contract check-go check-docs check-obsidian check-sdk-compat check-sdk-backward-compat check-migration-compat \
        check-evidence-maintenance \
        demo demo-attack \
        eval-soak eval-soak-smoke \
        eval-fast eval-adversarial eval-recall eval-fast-baseline \
        gen-cli-docs

OPENAPI_SPEC  := docs/openapi/stigmem.json
SDK_TS_DIR    := sdks/stigmem-ts
EVAL_FED_DIR  := eval/federation
EVAL_RESULTS  := eval/results

help:
	@echo "Stigmem build targets"
	@echo ""
	@echo "  check             PR-equivalent fast gate bundle"
	@echo "  check-python      Python lint/type/test/security checks"
	@echo "  check-node        TypeScript build/type/test/audit checks"
	@echo "  check-contract    OpenAPI + generated SDK contract drift checks"
	@echo "  check-go          Go SDK tests"
	@echo "  check-docs        Docusaurus docs build"
	@echo "  check-obsidian    Obsidian plugin build"
	@echo "  check-sdk-compat  Live-node smoke across Python, TypeScript, and Go SDKs"
	@echo "  check-sdk-backward-compat  Previous-release SDK smoke against the current node"
	@echo "  check-migration-compat     Upgrade a v1.0-rc schema baseline and verify it"
	@echo "  check-evidence-maintenance Cross-phase evidence owner/trigger wiring"
	@echo ""
	@echo "  demo              Two-node Docker quickstart: peer, assert, replicate, audit"
	@echo "  demo-attack       Malicious-peer rejection demo (scope + source forgery)"
	@echo ""
	@echo "  sdk-ts            Full TypeScript SDK pipeline: generate → build → test → pack"
	@echo "  sdk-ts-generate   Regenerate src/generated.ts from $(OPENAPI_SPEC)"
	@echo "  sdk-ts-build      Compile TypeScript (tsc)"
	@echo "  sdk-ts-test       Run Vitest unit tests"
	@echo "  sdk-ts-pack       Run npm pack (produces stigmem-ts-*.tgz)"
	@echo ""
	@echo "  eval-soak-smoke   5-min federation soak: all 5 CC scenarios (local dev)"
	@echo "  eval-soak         1-hour federation soak: replication lag + CC-1..CC-5 (CI)"

check:
	bash scripts/check.sh

check-python:
	bash scripts/check.sh python

check-node:
	bash scripts/check.sh node

check-contract:
	bash scripts/check.sh contract

check-go:
	bash scripts/check.sh go

check-docs:
	bash scripts/check.sh docs

check-obsidian:
	bash scripts/check.sh obsidian

check-sdk-compat:
	bash scripts/check_sdk_compat.sh

check-sdk-backward-compat:
	bash scripts/check_sdk_backward_compat.sh

check-migration-compat:
	uv run pytest node/tests/lifecycle/test_migration_compat.py -q --tb=short

check-evidence-maintenance:
	python3 scripts/check_evidence_maintenance.py
	python3 scripts/validate_security_evidence.py
	python3 scripts/check_security_documentation.py
	python3 scripts/check_release_evidence.py

demo:
	bash scripts/quickstart-verify.sh

demo-attack:
	bash scripts/demo-attack.sh

# Full pipeline — matches the acceptance criterion in the Phase 13 spec.
sdk-ts: sdk-ts-generate sdk-ts-build sdk-ts-test sdk-ts-pack

sdk-ts-generate:
	@echo "→ Regenerating TypeScript types from $(OPENAPI_SPEC)"
	cd $(SDK_TS_DIR) && pnpm install --frozen-lockfile
	cd $(SDK_TS_DIR) && pnpm generate

sdk-ts-build:
	@echo "→ Building stigmem-ts"
	cd $(SDK_TS_DIR) && pnpm build

sdk-ts-test:
	@echo "→ Running TypeScript SDK tests"
	cd $(SDK_TS_DIR) && pnpm test

sdk-ts-pack:
	@echo "→ Creating npm tarball"
	cd $(SDK_TS_DIR) && npm pack
	@echo "✓ Tarball created in $(SDK_TS_DIR)/"

# ---------------------------------------------------------------------------
# Federation soak harness (ACM-277)
# ---------------------------------------------------------------------------

eval-soak-smoke:
	@echo "→ Federation soak smoke (5 min, all 5 CC scenarios)"
	@mkdir -p $(EVAL_RESULTS)
	uv run python $(EVAL_FED_DIR)/soak_driver.py --smoke
	@echo "✓ Smoke soak complete — see $(EVAL_RESULTS)/"

eval-soak:
	@echo "→ Federation soak ($(if $(DURATION),$(DURATION),3600) s)"
	@mkdir -p $(EVAL_RESULTS)
	uv run python $(EVAL_FED_DIR)/soak_driver.py $(if $(DURATION),--duration $(DURATION),)
	@echo "✓ Soak complete — see $(EVAL_RESULTS)/"

# ---------------------------------------------------------------------------
# Eval fast harness (ACM-276) — adversarial + recall
# ---------------------------------------------------------------------------

GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo local)

eval-fast: eval-adversarial eval-recall

eval-adversarial:
	@echo "→ Adversarial eval (79 scenarios)"
	@mkdir -p $(EVAL_RESULTS)
	uv run pytest eval/test_adversarial.py -v --tb=short \
		--rootdir=. -p no:cacheprovider -p no:cov -o "addopts=" \
		2>&1 | tee $(EVAL_RESULTS)/adversarial-$(GIT_SHA).log

eval-recall:
	@echo "→ Recall eval (400 probes)"
	@mkdir -p $(EVAL_RESULTS)
	uv run pytest eval/test_recall.py -v --tb=short \
		--rootdir=. -p no:cacheprovider -p no:cov -o "addopts=" \
		2>&1 | tee $(EVAL_RESULTS)/recall-$(GIT_SHA).log

eval-fast-baseline:
	@echo "→ Freezing recall baseline"
	uv run python -m eval.harness.recall --save-baseline

# ---------------------------------------------------------------------------
# CLI reference docs
# ---------------------------------------------------------------------------

gen-cli-docs:
	@echo "→ Regenerating CLI reference docs"
	uv run python docs/scripts/gen-cli-docs.py
	@echo "✓ CLI docs written to docs/docs/reference/cli/"
