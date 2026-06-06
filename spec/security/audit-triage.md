# Audit triage registry

**Status:** Current. Maintained per the open security-state policy.
**Scope:** Alerts raised by static-analysis tools (CodeQL, bandit, pip-audit, pnpm audit, …) that have been classified as false positives or knowingly suppressed. The registry persists the **rationale** for each classification in tracked source so it survives outside the GitHub UI (alert comments are not in-repo and can be lost on fork or re-import).

This file complements:

- [`SECURITY.md`](../../SECURITY.md) § Security Posture — operator-facing summary and per-PR triage groups.
- [`threat-model.md`](threat-model.md) — risk register (R-XX entries). Only **real** risks land there; this file records **non-risks**.
- [ADR-020](../../docs/adr/020-feature-owned-product-structure.md) §11 (security taxonomy) — establishes the colocation principle that justifies an in-repo registry over GitHub-UI-only dismissal comments.

## How to use this file

Every triage decision against an open security alert that ends in **dismiss as false positive**, **dismiss as acknowledged risk**, or **suppress with rationale** SHOULD add an entry here, including:

1. The alert number(s) and rule id.
2. The location at the time of triage.
3. The root cause (why the tool flagged it).
4. The disposition category (see below) and the reason.
5. The remediation taken (structural fix, regex tightening, accepted dismissal with ADR-tracked retirement plan, …) and the PR or ADR that landed it.

### Disposition categories

- **False positive (precision-gap).** The tool's analysis is wrong about the exploit conditions; no actual vulnerability exists. Remediation is usually a structural design-pivot so the analyzer can prove safety, not a suppression.
- **Acknowledged risk (ADR-tracked remediation).** The tool's analysis is technically correct but the code is a deliberate, documented choice (typically a bounded migration window) whose retirement is committed in an ADR. The risk is real but accepted; dismissal points at the ADR and a definite retirement milestone.
- **Suppression (with documented rationale).** Anything that doesn't fit the above two and can't be structurally fixed. Rare; should be the last resort.

Entries are append-only. If a previously-dismissed alert is later determined to be a real bug, add a new entry under the same date acknowledging the revision and link to the fix; do **not** edit the historical entry.

---

## CodeQL — false positives (precision-gap)

### 2026-05-11 — conditional SQL-fragment assembly (7 SQL + 1 transitive ReDoS)

**Alerts:** [#18](https://github.com/eidetic-labs/stigmem/security/code-scanning/18), [#19](https://github.com/eidetic-labs/stigmem/security/code-scanning/19), [#21](https://github.com/eidetic-labs/stigmem/security/code-scanning/21), [#22](https://github.com/eidetic-labs/stigmem/security/code-scanning/22), [#23](https://github.com/eidetic-labs/stigmem/security/code-scanning/23), [#24](https://github.com/eidetic-labs/stigmem/security/code-scanning/24), [#25](https://github.com/eidetic-labs/stigmem/security/code-scanning/25), [#26](https://github.com/eidetic-labs/stigmem/security/code-scanning/26).

**Rules:** 7× `py/sql-injection`, 1× `py/polynomial-redos`.

**Locations at triage time:**

- `node/src/stigmem_node/routes/lint.py` lines 94, 124, 185, 220, 254 (5 builders).
- `node/src/stigmem_node/routes/facts.py` line 246.
- `node/src/stigmem_node/routes/synthesize.py` line 105.
- `node/src/stigmem_node/storage/postgres_backend.py` line 146 (transitive taint from the SQL builders into `_STRFTIME_EPOCH_RE.sub()`).

**Root cause:** CodeQL's taint analyzer cannot reason about Python's conditional-string-fragment assembly pattern:

```python
conditions = ["f.tenant_id = ?"]
params = [tenant_id]
if entity:
    conditions.append("f.entity = ?")  # ← literal SQL fragment
    params.append(entity)              # ← user value (parameter-bound)
sql = f"SELECT * FROM facts WHERE {' AND '.join(conditions)}"
conn.execute(sql, params)
```

The user value (`entity`) reaches an f-string control flow because the branch that appends it is conditional on the value. CodeQL marks `sql` as user-tainted at the `execute` sink, even though only a string-literal SQL fragment was interpolated and the user value was bound as a parameter. For the ReDoS alert (#21), the same tainted `sql` flows one hop further into `_pg_translate`'s `_STRFTIME_EPOCH_RE.sub(...)`, where the analyzer flags the regex as a polynomial-ReDoS sink — even though in practice the regex only sees the SQL skeleton text (a string literal at every call site).

**Why these are not vulnerabilities:** every user-supplied value reaches the database as a bound parameter via `?` placeholders. The SQL **text** that CodeQL sees concatenated never contains user input — only literal strings the developer wrote. The regex in `_pg_translate` only processes those same literal SQL strings, plus migration files that ship in the repository (developer-authored, trusted at the supply-chain boundary). There is no flow from a network input to a SQL parser or a regex engine that an attacker could exploit.

**Why suppression was not the right fix:** `# nosec` comments satisfy bandit but **CodeQL does not honor them**. Confirmed in two prior triages:

- PR #106 — `py/clear-text-logging-sensitive-data`: inline suppression attempts failed; resolved by design pivot to a user-provides-key flow.
- PR #112 follow-up — these same SQL injection alerts: this triage.

Both produced the same conclusion: the durable remediation is structural, not declarative.

**Remediation:** [PR #117](https://github.com/eidetic-labs/stigmem/pull/117) refactors all three SQL builders to a constant-SQL pattern. The WHERE clause becomes a module-level string constant and optional filters are gated by bound parameters using `(? IS NULL OR col = ?)` (or a `? = 1` sentinel for boolean toggles). After the refactor:

- No f-string concatenation reachable from user input.
- No taint flow from `routes/` to `_pg_translate`'s regex.
- 7 `# nosec B608` comments removed (no longer needed).
- Belt-and-suspenders: bounded quantifiers on `_STRFTIME_EPOCH_RE` (`\s{0,16}`, `[^)]{1,256}?`) in case the transitive-taint break alone is not enough to close #21.

**Status:** Closed on PR #117 + PR #121 merge (CodeQL re-scan).

**Follow-up — 2026-05-11, issue #121:** CodeQL re-scanned `main` after PR #117 merged and re-opened alerts #22 (`facts.py:263`) and #26 (`synthesize.py:110`). Both moved one line — from the f-string concatenation site that PR #117 removed, to the `conn.execute(sql, params)` call site. Diagnosis: even though the SQL string is now a module-level constant, the builder function (`_build_as_of_query`, `_build_synthesize_sql`) still **returned** the SQL string from a function whose arguments are user-controlled. CodeQL's interprocedural taint engine follows the user input into the function and out via the tuple return, tagging the returned SQL as tainted even though its value is invariant.

Resolution (PR #121): split each builder so the module-level SQL constant is referenced **directly at the call site** and the builder returns **only** the params list (`_build_as_of_params`, `_build_synthesize_params`). This breaks the user-input → tuple-return → SQL data-flow path. No change to the SQL text itself.

Lesson: even after the constant-SQL refactor, the SQL string must never appear in the return type of a function that accepts user input. The taint-precision gap is wider than the f-string-only case originally diagnosed.

**No threat-model entries added:** the exploitation conditions do not exist; recording the alerts in `threat-model.md` would mislead future readers into treating them as real residual risks. The Rev 2.2 entry in `threat-model.md` § 10 documents the triage decision without claiming a new residual risk.

---

## CodeQL — acknowledged risks (ADR-tracked remediation)

### 2026-05-13 — SHA-256 in the Argon2id migration verifier ([alert #34](https://github.com/eidetic-labs/stigmem/security/code-scanning/34))

**Rule:** `py/weak-sensitive-data-hashing`.
**Severity:** High.
**Location at triage:** `node/src/stigmem_node/auth.py:67` — function `_legacy_sha256(raw: str) -> str` and its sibling `_verify_key_hash(...)` which calls it. Introduced in [PR #172](https://github.com/eidetic-labs/stigmem/pull/172) (Argon2id API key hashing migration per [ADR-007](../../docs/adr/archive/007-argon2id.md)).

**Why this is NOT a false positive.** Unlike the 2026-05-11 SQL-injection cluster above, the analyzer is **technically correct**: SHA-256 is computationally cheap and inappropriate as a password-hashing primitive in isolation. The function genuinely hashes credential material with SHA-256.

**Why we keep it anyway.** [ADR-007](../../docs/adr/archive/007-argon2id.md) commits to a dual-mode verification window:

- All **new** API keys are hashed with Argon2id (via `_hash_key`, which returns the `$argon2id$…` PHC string).
- **Legacy** v0.9.0a1 rows — issued before PR #172 landed — remain SHA-256-hashed in the database. They verify against `_legacy_sha256` on first use, then are opportunistically re-hashed to Argon2id and the database row is updated.
- A new audit event type `api_key_rehashed` fires on every opportunistic re-hash. Operators track migration progress with:
  ```sql
  SELECT COUNT(*) FROM fact_audit_log WHERE event_type = 'api_key_rehashed';
  ```
- At **v1.0.0 GA**, a bulk re-hash migration retires the remaining SHA-256 hashes by issuing forced rotations; `_legacy_sha256` and the legacy verification branch in `_verify_key_hash` are then deleted as part of the same release.

Deleting `_legacy_sha256` today would invalidate every v0.9.0a1-issued API key the moment v0.9.0a2 ships — a far worse failure than the residual risk of having the function in the codebase for the v0.9.x migration window. The risk is real but bounded and accepted per the ADR's explicit decision.

**Threat-model linkage.** The dual-mode design is already captured in `threat-model.md`:

- §4 Assumption 2 — describes Argon2id storage with legacy SHA-256 rows accepted during the v0.9.x window and rehashed opportunistically (`api_key_rehashed` audit event).
- T1-S1 (TB-1 STRIDE) — names the legacy-row residual as part of the spoofing-mitigation control.
- T7-S1 (TB-7 STRIDE) — same residual on admin-key storage.

No new `R-XX` entry is required: the residual is already accounted for in the existing controls. The Rev 2.3 entry in `threat-model.md` § 10 logs the alert acknowledgment without re-litigating the design.

**Disposition.** Alert dismissed in GitHub UI with reason `won't fix`. Dismissal comment points at this section.

**Retirement milestone.** v1.0.0 GA — bulk re-hash migration deletes `_legacy_sha256` from `auth.py`; CodeQL re-scan after that release auto-closes any residual reference to the function.

**Tracking.** [ADR-007](../../docs/adr/archive/007-argon2id.md) defines the dual-mode migration window; the v1.0.0 GA release checklist must verify that the legacy SHA-256 path has been retired before the stable release is cut.

---

## bandit, pip-audit, pnpm audit

No long-form entries yet. Bandit suppressions are inline (`# nosec BXXX`) and explained at the call site; per-alert dependency suppressions are documented in `SECURITY.md` Groups A and B. If a bandit or dependency-audit suppression ever requires more than one line of rationale, prefer adding an entry to this file over expanding the inline comment.
