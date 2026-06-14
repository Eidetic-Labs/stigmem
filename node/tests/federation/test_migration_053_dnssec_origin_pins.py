"""Migration 053 — dnssec_origin_pins (Phase 3 build-phase 3b, Rev 6 §9).

The pinned DNSSEC binding per identity (I1): an accepted first-trust binding is
pinned to (entity_uri, node_id). Confirms migration 053 creates the table with
the correct columns + composite PRIMARY KEY, applies to a fresh DB, and that a
DB carrying pre-existing rows still migrates. Mirrors the migration 050 test.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from stigmem_node.db import apply_migrations

_EXPECTED_COLUMNS = {
    "entity_uri",
    "node_id",
    "key_fpr",
    "epoch",
    "prev_fpr",
    "prev_until",
    "host",
    "last_validated_at",
}


def _table_info(db_path: Path, table: str) -> list[tuple]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"PRAGMA table_info({table})").fetchall()


def test_migration_053_creates_table_with_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "dnssec_origin_pins")
    assert rows, "dnssec_origin_pins table not created"
    col_names = {row[1] for row in rows}
    assert col_names == _EXPECTED_COLUMNS, (
        f"column mismatch: extra={col_names - _EXPECTED_COLUMNS}, "
        f"missing={_EXPECTED_COLUMNS - col_names}"
    )


def test_migration_053_composite_primary_key(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "dnssec_origin_pins")
    # PRAGMA table_info row: (cid, name, type, notnull, dflt_value, pk)
    pk_cols = {row[1] for row in rows if row[5] > 0}
    assert pk_cols == {"entity_uri", "node_id"}, f"unexpected PK columns: {pk_cols}"


def test_migration_053_existing_data_still_migrates(tmp_path: Path) -> None:
    """A DB carrying pre-existing rows in an earlier table still migrates cleanly."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO origin_pins (entity_uri, node_id, key_fingerprint) "
            "VALUES ('https://memory.acme.example/', 'node-1', 'sha256:abc')"
        )
        conn.commit()

    # Re-applying migrations over a populated DB must not raise.
    apply_migrations(db_path=str(db_path))

    with sqlite3.connect(db_path) as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM origin_pins").fetchone()[0]
    assert cnt == 1
    assert _table_info(db_path, "dnssec_origin_pins"), "table missing after re-migrate"
