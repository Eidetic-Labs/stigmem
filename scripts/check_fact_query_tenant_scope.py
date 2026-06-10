#!/usr/bin/env python3
"""CI guard: every ``FROM facts`` query in the route/recall layer must carry a
tenant_id predicate (or be explicitly allowlisted with a reason).

This locks in the fix for the cross-tenant read-leak class (audit H4 and its
siblings — synthesize, intents, decay, cards, …): a new fact-returning surface
that forgets to scope by tenant fails CI instead of silently leaking. The
single definition of "visible facts" lives in stigmem_node.fact_visibility;
this guard is the construction that stops routes from bypassing it.

Heuristic: for each ``FROM facts`` occurrence we scan a window of the following
SQL text for ``tenant_id``. Queries that are legitimately cross-tenant (system
maintenance, federation egress that scopes elsewhere, schema with no tenant
column yet) are listed in ALLOWLIST with an anchor substring + reason.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "node" / "src" / "stigmem_node"
# routes/ + recall/ cover the API read surface; federation/ is the cross-node
# ingest/pull path, where the tenant gap was on the WRITE side (INSERT INTO facts
# without tenant_id) — see find_insert_violations. Including it here also covers
# any `FROM facts` SELECT in the top-level federation package via the read-guard.
SCAN_DIRS = [ROOT / "routes", ROOT / "recall", ROOT / "federation"]

# Tenant-bearing tables this guard defends. All carry a `tenant_id` column (facts
# from the start; entity_aliases/instruction_manifests/boot_stubs/instruction_audit
# since migrations 039/040) — a route/recall query against any of them must scope
# by tenant or it can leak across tenants.
TENANT_TABLES = r"(?:facts|entity_aliases|instruction_manifests|boot_stubs|instruction_audit)"
# Case-sensitive: SQL keywords are uppercase in this codebase, so this skips
# prose like "from facts.py" in docstrings.
FROM_FACTS = re.compile(rf"FROM\s+{TENANT_TABLES}\b")
WINDOW = 800  # max chars after the FROM to search (further bounded to the statement)

# The window is cut at the first of these (end of the execute() call / statement),
# so a later, unrelated query's predicate can't bleed in and mask an unscoped one.
WINDOW_TERMINATORS = (".fetchone", ".fetchall", ".fetchmany", ".fetchval", ";")

# A query is tenant-scoped only when tenant_id appears in PREDICATE position
# (tenant_id = ? / tenant_id IN (...)) — a bare mention in a comment or an
# adjacent column does NOT count (avoids failing open).
TENANT_PREDICATE = re.compile(r"tenant_id\s*(?:=|<|>|!=|\bIN\b)", re.IGNORECASE)

# …or the query is routed through the shared read-scope helper
# (stigmem_node.fact_visibility), which injects the tenant predicate.
HELPER_MARKERS = ("scope_sql", "visible_facts_where", "read_scope")

# A primary-key lookup `... FROM facts ... WHERE id = ?` (or `id IN (...)`) targets
# unguessable UUIDs already produced by a tenant-scoped query upstream — not an
# enumeration/oracle surface. Treated as scoped by construction.
BY_ID_LOOKUP = re.compile(
    rf"FROM\s+{TENANT_TABLES}\b[^;]{{0,160}}?WHERE\s+(?:f\.)?id\s*(?:=\s*\?|IN\s*\()", re.DOTALL
)

# Allowlist: {relative_path: [(anchor, reason), ...]}. An occurrence is exempt
# when the anchor substring appears in its window. Keep reasons specific.
ALLOWLIST: dict[str, list[tuple[str, str]]] = {
    "routes/cid_admin.py": [
        ("COUNT(*) FROM facts", "admin-only CID backfill stats; global by design"),
        ("cid IS NOT NULL", "admin-only CID backfill stats; global by design"),
    ],
    "routes/quarantine.py": [
        ("where_clause", "garden-membership-scoped via the dynamic where_clause"),
    ],
    "routes/federation/replication.py": [
        ("WHERE {where}", "federation egress; tenant-scoped via the built {where} (tenant_id = ?)"),
    ],
    "routes/recall/common.py": [
        ("fact_validity_overrides", "recall candidate fetch; ids from the scoped entry query"),
    ],
    "recall/vector_search.py": [
        ("fact_embedding_status", "recall vector candidates; tenant enforced by the scoped query"),
    ],
}


def _exempt(rel: str, window: str) -> bool:
    return any(anchor in window for anchor, _reason in ALLOWLIST.get(rel, []))


def _bounded_window(text: str, start: int) -> str:
    """Window from `start`, cut at the first statement terminator (so a later
    query's predicate cannot bleed in), capped at WINDOW chars."""
    raw = text[start : start + WINDOW]
    end = len(raw)
    for term in WINDOW_TERMINATORS:
        idx = raw.find(term)
        if idx != -1:
            end = min(end, idx)
    return raw[:end]


def window_is_scoped(rel: str, window: str, ctx: str) -> bool:
    """True if a `FROM facts` window is tenant-scoped (or legitimately exempt).

    ``window`` is the strict statement-bounded slice used for the automatic
    checks (no bleed from later statements). ``ctx`` includes some leading text
    (the SELECT clause) and is used only for the curated, human-vetted allowlist
    anchors, some of which reference text before ``FROM`` (e.g. ``COUNT(*)``).
    """
    if TENANT_PREDICATE.search(window):
        return True
    if any(marker in window for marker in HELPER_MARKERS):
        return True
    if BY_ID_LOOKUP.match(window):
        return True
    return _exempt(rel, ctx)


def find_violations(scan_dirs: list[Path], root: Path) -> list[str]:
    """Return `relpath:line: …` for every unscoped `FROM facts` query under scan_dirs."""
    violations: list[str] = []
    for base in scan_dirs:
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            rel = str(path.relative_to(root))
            for m in FROM_FACTS.finditer(text):
                window = _bounded_window(text, m.start())
                ctx = text[max(0, m.start() - 120) : m.start() + WINDOW]
                if window_is_scoped(rel, window, ctx):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                snippet = text[m.start() : m.start() + 70].replace("\n", " ").strip()
                violations.append(f"{rel}:{line}: FROM facts without tenant_id — …{snippet}…")
    return violations


# --- Write dimension --------------------------------------------------------
# The read-guard above defends `FROM facts` SELECTs. The federation ingest gap
# (audit) was on the WRITE side: an `INSERT INTO facts (...)` that omits the
# tenant_id column writes a row that defaults/nulls its tenant, so it later reads
# as cross-tenant. Every fact-producing INSERT must name tenant_id in its column
# list (or be allowlisted with a reason if legitimately tenant-agnostic — there
# are none today; conflict/meta inserts all carry tenant_id after Tasks 3/6).
INSERT_FACTS = re.compile(r"INSERT\s+INTO\s+facts\s*\(([^)]*)\)", re.IGNORECASE | re.DOTALL)
INSERT_TENANT_COL = re.compile(r"\btenant_id\b", re.IGNORECASE)

# Allowlist: {relative_path: [(anchor, reason), ...]}. The anchor must appear in
# the captured column list for the insert to be exempt. Keep reasons specific.
INSERT_ALLOWLIST: dict[str, list[tuple[str, str]]] = {}


def _insert_exempt(rel: str, columns: str) -> bool:
    return any(anchor in columns for anchor, _reason in INSERT_ALLOWLIST.get(rel, []))


def find_insert_violations(scan_dirs: list[Path], root: Path) -> list[str]:
    """Return `relpath:line: …` for every `INSERT INTO facts (...)` whose column
    list omits tenant_id (and is not allowlisted)."""
    violations: list[str] = []
    for base in scan_dirs:
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            rel = str(path.relative_to(root))
            for m in INSERT_FACTS.finditer(text):
                columns = m.group(1)
                if INSERT_TENANT_COL.search(columns):
                    continue
                if _insert_exempt(rel, columns):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                cols = " ".join(columns.split())[:70]
                violations.append(
                    f"{rel}:{line}: INSERT INTO facts without tenant_id column — ({cols}…)"
                )
    return violations


# --- Garden dimension -------------------------------------------------------
# A fact-by-id read route returning content must also enforce the garden ACL,
# not just the tenant. provenance/cid leaked restricted-garden facts (F-A1/F-A2)
# and /v1/facts?as_of= leaked them too (F-AS-OF-FACTS) — all satisfied the
# tenant guard. So: any routes/facts file that SELECTs fact CONTENT must
# reference a garden gate. (By-id is NOT exempt here — F-A1 was a by-id read.)
GARDEN_SCAN_DIR = ROOT / "routes" / "facts"
GARDEN_MARKERS = (
    "require_fact_garden_read",
    "require_garden_read",
    "caller_read_scope",
    "garden_allows",
    "fact_visible",
    "_query_visible_gardens",
    "projected_garden",
    "_caller_sees_all_card_gardens",
)
# A `FROM facts` is "content" unless it is a COUNT/existence probe (no row data).
_NON_CONTENT = re.compile(r"(?:COUNT\s*\(|SELECT\s+1\b|EXISTS\s*\()", re.IGNORECASE)


def _file_returns_fact_content(text: str) -> bool:
    for m in FROM_FACTS.finditer(text):
        preceding = text[max(0, m.start() - 120) : m.start()]
        if not _NON_CONTENT.search(preceding):
            return True
    return False


def find_garden_violations(garden_dir: Path, root: Path) -> list[str]:
    """Return files under routes/facts/ that return fact content with no garden gate."""
    violations: list[str] = []
    if not garden_dir.exists():
        return violations
    for path in sorted(garden_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if not text.count("facts"):
            continue
        if _file_returns_fact_content(text) and not any(g in text for g in GARDEN_MARKERS):
            rel = str(path.relative_to(root))
            violations.append(f"{rel}: returns fact content with no garden-ACL gate")
    return violations


def main() -> int:
    violations = find_violations(SCAN_DIRS, ROOT)
    insert_violations = find_insert_violations(SCAN_DIRS, ROOT)
    garden_violations = find_garden_violations(GARDEN_SCAN_DIR, ROOT)
    failed = False
    if violations:
        failed = True
        sys.stderr.write(
            "Fact-query tenant-scope guard FAILED — these tenant-table queries lack a "
            "tenant_id predicate (route through stigmem_node.fact_visibility, or add to "
            "ALLOWLIST with a reason if intentionally cross-tenant):\n\n"
        )
        for v in violations:
            sys.stderr.write(f"  {v}\n")
    if insert_violations:
        failed = True
        sys.stderr.write(
            "\nFact-write tenant-scope guard FAILED — these `INSERT INTO facts` statements omit "
            "the tenant_id column (a fact written without a tenant later reads as cross-tenant; "
            "add tenant_id to the column list, or add to INSERT_ALLOWLIST with a reason):\n\n"
        )
        for v in insert_violations:
            sys.stderr.write(f"  {v}\n")
    if garden_violations:
        failed = True
        sys.stderr.write(
            "\nFact-query garden-ACL guard FAILED — these routes/facts files return fact "
            "content without a garden gate (add require_fact_garden_read / a projected-garden "
            "filter, like single/provenance/cid):\n\n"
        )
        for v in garden_violations:
            sys.stderr.write(f"  {v}\n")
    if failed:
        return 1
    print("Fact-query tenant-scope (read+write) + garden-ACL guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
