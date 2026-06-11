"""Migration 049 — tombstone relay origin columns (Phase 2c W6.2).

Confirms that migration 049_tombstone_v2_origin.sql adds the 7 relay-origin
columns to the tombstones table, all nullable, and that re-applying migrations
is idempotent (no error on second apply).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from stigmem_node.db import apply_migrations

_EXPECTED_COLUMNS = {
    "received_from",
    "origin_node_id",
    "origin_tenant",
    "origin_entity_uri",
    "origin_allowed_scopes",
    "origin_allowed_tenants",
    "origin_sig",
}


def _tombstone_column_info(db_path: Path) -> dict[str, dict]:
    """Return {col_name: {notnull, dflt_value}} for every tombstones column."""
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("PRAGMA table_info(tombstones)").fetchall()
    # PRAGMA table_info columns: (cid, name, type, notnull, dflt_value, pk)
    return {row[1]: {"notnull": row[3], "dflt_value": row[4]} for row in rows}


def test_migration_049_adds_origin_columns(tmp_path: Path) -> None:
    """After apply_migrations, tombstones must have all 7 relay-origin columns."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    col_info = _tombstone_column_info(db_path)
    col_names = set(col_info)

    assert col_names >= _EXPECTED_COLUMNS, (
        f"Missing tombstone origin columns: {_EXPECTED_COLUMNS - col_names}"
    )


def test_migration_049_new_columns_are_nullable(tmp_path: Path) -> None:
    """All 7 relay-origin columns must be nullable (no NOT NULL constraint)."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    col_info = _tombstone_column_info(db_path)

    for col in _EXPECTED_COLUMNS:
        assert col in col_info, f"Column {col!r} not found in tombstones"
        assert col_info[col]["notnull"] == 0, (
            f"Column {col!r} must be nullable; got notnull={col_info[col]['notnull']}"
        )


def test_migration_049_idempotent(tmp_path: Path) -> None:
    """Applying migrations twice must not raise (idempotency guard)."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    apply_migrations(db_path=str(db_path))  # must not raise

    col_info = _tombstone_column_info(db_path)
    assert set(col_info) >= _EXPECTED_COLUMNS
