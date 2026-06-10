from __future__ import annotations

import sqlite3
from pathlib import Path

from stigmem_node.storage import make_backend


def _cols(db_path: str, table: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_migration_041_adds_policy_columns(tmp_path: Path) -> None:
    from stigmem_node.db import _MIGRATIONS_DIR

    db_path = tmp_path / "m041.db"
    make_backend(db_path=str(db_path)).apply_migrations(_MIGRATIONS_DIR)
    assert {"pull_tenant", "ingest_tenant", "allowed_tenants", "trust_tier"} <= _cols(
        str(db_path), "peers"
    )
    assert "federatable" in _cols(str(db_path), "gardens")
