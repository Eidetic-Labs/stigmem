# Future Hardened-Core Release Roadmap

**Status:** future gate
**Release owner:** maintainer
**Milestone:** not opened
**Tag / release:** not tagged
**Last updated:** 2026-05-22

## Release Intent

The future hardened-core line opens only after alpha exit evidence supports it.
Several hardened-core slices have landed on `main` during the alpha series, but
this document is a future gate, not a current beta release plan. No beta
milestone is open; the current published alpha build is `v0.9.0a4`.

## Scope Summary

| Area | In scope | Out of scope | Canonical references |
| --- | --- | --- | --- |
| Threat-model closure | Close v1.0.0-critical-path Open risks | Opening beta before alpha exit evidence | threat model, ADR-003, ADR-015 |
| Hardened storage | Immutability, CIDs, hash chain, checkpoint evidence | Rewriting accepted ADRs | ADR-016, ADR-011 |
| Federation hardening | mTLS, HLC, audit retention, quotas, key rotation | Production federation claims before evidence | ADR-004, federation issues |
| Operator validation | 30-day external operator soak | RC or GA release promises | #439 |

## Detailed Scope

### Landed on `main`

- OpenClaw safety hardening now has fail-closed startup behavior, visible
  partial-write failures, channel-separated recall handling, and bounded
  handoff-target allowlisting. Audit-mapped C1-C4/H1-H5 regression coverage
  lives in `adapters/openclaw/tests/test_adapter_security.py`, and the ClawHub
  skill adapter is now a compatibility re-export of the packaged adapter.
- The ADR-003 capability redesign has landed for the core protocol surfaces:
  `FactValue.interpret_as`, `instruction:write` enforcement, instruction-typed
  federation quarantine, channel-separated `recall()` output, MCP/OpenClaw
  channel framing, instruction promotion/quarantine audit events, and
  same-session read/write provenance controls. R-21's remaining structural
  gap has also landed: supported Python/TypeScript/MCP/OpenClaw surfaces
  propagate sessions and provenance, and outbound federation pull excludes
  provenance-derived facts.
- Protocol-level adversarial vectors are in
  `data/conformance/adversarial/protocol/` and are part of the blocking
  conformance gate.
- The ADR-015 consumer-layer `corpus-v1` prompt-injection corpus now contains
  80 validated patterns across 10 categories, with validation wired into the
  eval-fast CI path.
- The first ADR-015 certification harness slice exists at
  `scripts/run_adversarial_conformance.py`. It provides a deterministic offline
  provider, auditable rubric, result JSON schema, tier calculation, and result
  output path. The runner now includes OpenAI, Anthropic, and local Ollama
  provider adapters. The public reviewed-results index now exists at
  `data/conformance/adversarial/results/index.json` with CI validation and
  scheduled re-run posture; provider-backed live result rows remain pending.

### Work

1. **Finish capability-redesign documentation and threat-model closure** per
   [ADR-003](../../adr/003-prompt-injection.md) — R-05 is now in review after
   ADR-003/ADR-015 infrastructure landed, R-15 has the TB-3 adapter-promotion
   threat row, and R-21 is in review after same-session controls, supported
   adapter/session propagation, and outbound replication exclusion landed.
2. **Complete ADR-015 certification framework** per
   [ADR-015](../../adr/015-adversarial-conformance-and-model-certification.md) —
   the 80-pattern corpus, runner/result schema, and OpenAI/Anthropic/Ollama
   provider adapters exist; result-index validation and re-run posture are in
   place; remaining work is credentialed/provider-backed live certification and
   publication of reviewed result rows
   ([#398](https://github.com/eidetic-labs/stigmem/issues/398)).
3. **Storage immutability stack** per [ADR-016](../../adr/016-storage-immutability-enforcement.md) — L1 architectural append-only journal + projection tables has landed with projection schema, local-assert journal writes, embedding-status projection, zero remaining direct `facts` mutations in the tracked inventory, and read paths joined to validity/garden/quarantine/CID projections; L2 SQLite triggers now reject `UPDATE`/`DELETE` attempts on `facts` and preserve `fact_mutation_attempted` audit rows; L3 CIDs (per [ADR-011](../../adr/011-cross-cutting-extraction.md)) are computed on fact writes, recorded in `fact_cid_aliases`, and verified on direct fact reads, fact queries, and recall hydration with `409 cid_mismatch` on tampering; L4 local hash-chain entries are recorded for local fact inserts and can be verified for sequence/link tampering; L5 checkpoint storage now queues/submits chain-head checkpoints through the transparency-log abstraction and exposes checkpoint metadata in full recall proofs; client/peer verification now includes Python SDK CID/chain-proof helpers, inbound federation CID rejection/persistence, and full-verification pull requests; operator hardening docs now cover the R-23 mitigation stack, WORM evidence storage, and TEE deployment options.
4. **Per-feature security colocation** per [ADR-020](../../adr/020-feature-owned-product-structure.md) §11 (security taxonomy).
5. **Federation hardening** — mTLS-default; HLC bounded skew; persistent audit log (90-day retention); per-principal token-bucket quotas; key max-age + rotation runbook. mTLS compose smoke automation ([#425](https://github.com/eidetic-labs/stigmem/issues/425)), audit retention/observability ([#435](https://github.com/eidetic-labs/stigmem/issues/435)), and API-key lifecycle/rotation controls ([#436](https://github.com/eidetic-labs/stigmem/issues/436)) are complete.
6. **Argon2id migration** per [ADR-007](../../adr/archive/007-argon2id.md) — dual-mode verification; opportunistic re-hash; benchmarks.
7. **Operator-facing documentation** — runbooks, observability signals per [ADR-004](../../adr/004-federation-observability.md), prompt-injection hardening guide.
8. **Best-practice and quality gates** — internal best-practice docs, dependency-currency reporting, generated-file markers, file-size CI, stale internal-link linting, pytest `security`/`experimental` markers, root auto-marker assignment, major-version hold register, and branch/publish verification are queued in [#437](https://github.com/eidetic-labs/stigmem/issues/437). Follow-on dependency upgrade execution remains tracked separately from the gate adoption work.
9. **Contributor and demo readiness** — `make demo` / `make demo-attack`, contributor architecture path, issue templates, engineering log, and good-first issue tagging are being completed in [#438](https://github.com/eidetic-labs/stigmem/issues/438).
10. **30-day external operator soak** — at least one external operator runs against the hardened core with public bug reporting; operator validation and hardened-core exit evidence are tracked in [#439](https://github.com/eidetic-labs/stigmem/issues/439). The evidence framework lives in the operator validation soak guide; the actual 30-day run remains open until an external operator completes it.

## Artifact Surfaces

| Surface | Expected artifact | Status | Evidence |
| --- | --- | --- | --- |
| PyPI | Future hardened-core package artifacts | Future gate | Not opened |
| npm | Future hardened-core SDK artifacts | Future gate | Not opened |
| GHCR | Future hardened-core image artifacts | Future gate | Not opened |
| Docs | Hardened-core operator and security docs | Future gate | Not opened |
| GitHub release | Future release only after gate opens | Not tagged | Not opened |

## Security and Risk Posture

This line is blocked until the threat-model risk register has no Open status
entries for v1.0.0-critical-path risks, OpenClaw audit findings all show Closed
status, and the external operator soak completes with all P0 findings addressed.

## Evidence Gates

| Gate | Required evidence | Status |
| --- | --- | --- |
| Threat-model closure | No Open v1.0.0-critical-path risks | Future gate |
| OpenClaw audit closure | All audit findings Closed | Future gate |
| External operator soak | 30-day external run, all P0 findings addressed | Future gate |
| RC readiness | First release-candidate line justified by evidence | Future gate |

## Release Notes Candidates

- Hardened-core release notes are not drafted until the line opens.

## Deferred / Follow-Up Work

| Item | Disposition | Target |
| --- | --- | --- |
| Release-candidate line | Blocked on hardened-core exit | Future RC/GA roadmap |

## Historical Disposition

Not applicable. This horizon is not active.
