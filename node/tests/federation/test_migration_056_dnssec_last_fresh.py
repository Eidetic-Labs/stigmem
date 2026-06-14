"""Migration 056 — dnssec_epoch_pins.last_fresh_at (Phase 3 build-phase 3b.6).

Adds the per-host "previously-fresh" marker (Rev 6 I4) used by the RRSIG-age
clamp: an aged RRSIG on a previously-fresh host is rejected, while on a
never-fresh host it falls through to operator-confirm. Confirms the additive
column lands, defaults NULL, the existing columns/PK are untouched, applies
fresh, and an existing-data DB still migrates. Mirrors the migration 054 test.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from stigmem_node.db import apply_migrations

_EXPECTED_COLUMNS = {
    "host",
    "max_epoch_seen",
    "signed_delegation_seen",
    "last_validated_at",
    "last_fresh_at",
}


def _table_info(db_path: Path, table: str) -> list[tuple]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"PRAGMA table_info({table})").fetchall()


def test_migration_056_adds_last_fresh_at_column(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "dnssec_epoch_pins")
    col_names = {row[1] for row in rows}
    assert col_names == _EXPECTED_COLUMNS, (
        f"column mismatch: extra={col_names - _EXPECTED_COLUMNS}, "
        f"missing={_EXPECTED_COLUMNS - col_names}"
    )


def test_migration_056_last_fresh_at_defaults_null(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO dnssec_epoch_pins (host, max_epoch_seen, last_validated_at) "
            "VALUES ('memory.acme.example', 3, '2026-06-12T00:00:00Z')"
        )
        conn.commit()
        val = conn.execute(
            "SELECT last_fresh_at FROM dnssec_epoch_pins WHERE host=?",
            ("memory.acme.example",),
        ).fetchone()[0]
    assert val is None


def test_migration_056_preserves_host_primary_key(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    rows = _table_info(db_path, "dnssec_epoch_pins")
    pk_cols = {row[1] for row in rows if row[5] > 0}
    assert pk_cols == {"host"}, f"unexpected PK columns: {pk_cols}"


def test_migration_056_existing_data_still_migrates(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO dnssec_epoch_pins (host, max_epoch_seen, last_validated_at) "
            "VALUES ('memory.acme.example', 5, '2026-06-12T00:00:00Z')"
        )
        conn.commit()

    apply_migrations(db_path=str(db_path))  # must not raise over populated DB

    with sqlite3.connect(db_path) as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM dnssec_epoch_pins").fetchone()[0]
    assert cnt == 1
