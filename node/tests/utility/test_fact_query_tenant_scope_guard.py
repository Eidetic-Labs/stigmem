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
