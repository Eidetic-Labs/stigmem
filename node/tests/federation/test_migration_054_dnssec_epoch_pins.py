"""Migration 054 — dnssec_epoch_pins (Phase 3 build-phase 3b, Rev 6 §9).

Per-host monotonic epoch + sticky-signedness state (I2/I4): max_epoch_seen is
monotonic (rollback => reject), and once a signed delegation has been seen for a
host a later "absent" is treated as an attack. Keyed by host (NOT identity).
Confirms migration 054 creates the table with the correct columns, the host
PRIMARY KEY, and the signed_delegation_seen DEFAULT 0; applies fresh; and an
existing-data DB still migrates. Mirrors the migration 050/053 tests.
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
    # Added by migration 056 (RRSIG-age clamp, 3b.6); apply_migrations runs the
    # full chain, so the live dnssec_epoch_pins schema carries it.
    "last_fresh_at",
}


def _table_info(db_path: Path, table: str) -> list[tuple]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"PRAGMA table_info({table})").fetchall()


def test_migration_054_creates_table_with_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "dnssec_epoch_pins")
    assert rows, "dnssec_epoch_pins table not created"
    col_names = {row[1] for row in rows}
    assert col_names == _EXPECTED_COLUMNS, (
        f"column mismatch: extra={col_names - _EXPECTED_COLUMNS}, "
        f"missing={_EXPECTED_COLUMNS - col_names}"
    )


def test_migration_054_host_primary_key(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "dnssec_epoch_pins")
    # PRAGMA table_info row: (cid, name, type, notnull, dflt_value, pk)
    pk_cols = {row[1] for row in rows if row[5] > 0}
    assert pk_cols == {"host"}, f"unexpected PK columns: {pk_cols}"


def test_migration_054_signed_delegation_seen_defaults_zero(tmp_path: Path) -> None:
    """signed_delegation_seen defaults to 0 (not-yet-seen) so absence is not
    sticky until a signed delegation is observed."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO dnssec_epoch_pins (host, max_epoch_seen, last_validated_at) "
            "VALUES ('memory.acme.example', 3, '2026-06-12T00:00:00Z')"
        )
        conn.commit()
        val = conn.execute(
            "SELECT signed_delegation_seen FROM dnssec_epoch_pins WHERE host=?",
            ("memory.acme.example",),
        ).fetchone()[0]
    assert val == 0


def test_migration_054_existing_data_still_migrates(tmp_path: Path) -> None:
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
