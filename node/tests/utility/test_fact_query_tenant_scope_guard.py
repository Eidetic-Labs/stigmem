"""The fact-query tenant-scope CI guard stays clean AND has teeth."""

import importlib.util
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[3] / "scripts" / "check_fact_query_tenant_scope.py"
_spec = importlib.util.spec_from_file_location("_fact_scope_guard", _GUARD)
guard = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(guard)


def test_real_tree_is_clean() -> None:
    """The route/recall layer carries no unscoped `FROM facts` query (regression)."""
    violations = guard.find_violations(guard.SCAN_DIRS, guard.ROOT)
    assert violations == [], "\n".join(violations)


def test_real_tree_has_no_garden_violations() -> None:
    """Every routes/facts file returning fact content has a garden-ACL gate."""
    violations = guard.find_garden_violations(guard.GARDEN_SCAN_DIR, guard.ROOT)
    assert violations == [], "\n".join(violations)


def test_guard_scans_new_tenant_tables(tmp_path: Path) -> None:
    """An unscoped query on a newly tenant-bearing table is flagged."""
    d = tmp_path / "routes"
    d.mkdir()
    (d / "leaky.py").write_text(
        'conn.execute("SELECT * FROM instruction_manifests WHERE agent_id = ?", (a,))\n'
    )
    violations = guard.find_violations([d], tmp_path)
    assert len(violations) == 1
    assert "instruction_manifests" in violations[0]


def test_garden_guard_flags_content_query_without_gate(tmp_path: Path) -> None:
    """A routes/facts file returning fact content with no garden marker is flagged."""
    d = tmp_path / "routes" / "facts"
    d.mkdir(parents=True)
    (d / "leaky.py").write_text(
        'row = conn.execute("SELECT * FROM facts WHERE id = ? AND tenant_id = ?", a).fetchone()\n'
    )
    violations = guard.find_garden_violations(d, tmp_path)
    assert len(violations) == 1
    assert "leaky.py" in violations[0]


def test_garden_guard_accepts_gated_content_query(tmp_path: Path) -> None:
    d = tmp_path / "routes" / "facts"
    d.mkdir(parents=True)
    (d / "ok.py").write_text(
        'row = conn.execute("SELECT * FROM facts WHERE id = ?", a).fetchone()\n'
        "require_fact_garden_read(conn, fact_id, tenant_id, identity)\n"
    )
    assert guard.find_garden_violations(d, tmp_path) == []


def test_garden_guard_ignores_count_only(tmp_path: Path) -> None:
    """A COUNT/existence probe returns no content → no garden gate required."""
    d = tmp_path / "routes" / "facts"
    d.mkdir(parents=True)
    (d / "count.py").write_text(
        'n = conn.execute("SELECT COUNT(*) FROM facts WHERE tenant_id = ?", (t,)).fetchone()\n'
    )
    assert guard.find_garden_violations(d, tmp_path) == []


def test_guard_flags_a_new_unscoped_query(tmp_path: Path) -> None:
    """A newly-introduced unscoped fact query must be caught."""
    d = tmp_path / "routes"
    d.mkdir()
    (d / "leaky.py").write_text(
        'rows = conn.execute("SELECT * FROM facts WHERE entity = ?", (e,)).fetchall()\n'
    )
    violations = guard.find_violations([d], tmp_path)
    assert len(violations) == 1
    assert "leaky.py" in violations[0]


def test_guard_accepts_a_scoped_query(tmp_path: Path) -> None:
    d = tmp_path / "routes"
    d.mkdir()
    (d / "ok.py").write_text(
        'conn.execute("SELECT * FROM facts WHERE entity = ? AND tenant_id = ?", a)\n'
    )
    assert guard.find_violations([d], tmp_path) == []


def test_guard_accepts_by_id_lookup(tmp_path: Path) -> None:
    d = tmp_path / "routes"
    d.mkdir()
    (d / "byid.py").write_text('conn.execute("SELECT * FROM facts WHERE id = ?", (i,))\n')
    assert guard.find_violations([d], tmp_path) == []


def test_guard_accepts_helper_routed_query(tmp_path: Path) -> None:
    d = tmp_path / "routes"
    d.mkdir()
    (d / "helper.py").write_text(
        'sql = f"SELECT f.* FROM facts f {JOIN} WHERE x = ? {scope_sql}"\n'
    )
    assert guard.find_violations([d], tmp_path) == []


def test_guard_flags_when_tenant_id_only_a_bare_token(tmp_path: Path) -> None:
    """A `tenant_id` mention that is NOT a predicate (comment / column) must not
    count as scoped — the guard must not fail open."""
    d = tmp_path / "routes"
    d.mkdir()
    (d / "sneaky.py").write_text(
        'conn.execute("SELECT * FROM facts WHERE entity = ? -- tenant_id elsewhere", (e,))\n'
    )
    violations = guard.find_violations([d], tmp_path)
    assert len(violations) == 1


def test_guard_does_not_bleed_from_a_later_statement(tmp_path: Path) -> None:
    """An unscoped query must be flagged even when a *later* statement nearby
    carries a tenant_id predicate (window must be statement-bounded)."""
    d = tmp_path / "routes"
    d.mkdir()
    (d / "bleed.py").write_text(
        'a = conn.execute("SELECT * FROM facts WHERE entity = ?", (e,)).fetchall()\n'
        'b = conn.execute("SELECT * FROM facts WHERE x = ? AND tenant_id = ?", (x, t))\n'
    )
    violations = guard.find_violations([d], tmp_path)
    assert any("bleed.py:1:" in v for v in violations)  # first query still flagged
