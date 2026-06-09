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
SCAN_DIRS = [ROOT / "routes", ROOT / "recall"]

# Case-sensitive: SQL keywords are uppercase in this codebase, so this skips
# prose like "from facts.py" in docstrings.
FROM_FACTS = re.compile(r"FROM\s+facts\b")
WINDOW = 800  # max chars after "FROM facts" to search (further bounded to the statement)

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
    r"FROM\s+facts\b[^;]{0,160}?WHERE\s+(?:f\.)?id\s*(?:=\s*\?|IN\s*\()", re.DOTALL
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


def main() -> int:
    violations = find_violations(SCAN_DIRS, ROOT)
    if violations:
        sys.stderr.write(
            "Fact-query tenant-scope guard FAILED — these `FROM facts` queries lack a "
            "tenant_id predicate (route through stigmem_node.fact_visibility, or add to "
            "ALLOWLIST with a reason if intentionally cross-tenant):\n\n"
        )
        for v in violations:
            sys.stderr.write(f"  {v}\n")
        return 1
    print("Fact-query tenant-scope guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
