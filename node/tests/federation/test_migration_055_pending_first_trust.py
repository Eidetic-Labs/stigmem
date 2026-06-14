"""Migration 055 — pending_first_trust (Phase 3 build-phase 3b, Rev 6 §9).

The operator-confirm quarantine (I1/I9): the sole non-DNSSEC first-trust
fallback parks an unconfirmed candidate binding here, keyed by (entity_uri,
node_id), recording the candidate fingerprint, the source (unsigned vs
authenticated-insecure-delegation), the relay_peer it arrived from, and seen_at.
A per-relay_peer insert cap (index on relay_peer) + seen_at-based TTL eviction
(index on seen_at) keep the queue bounded so an untrusted relay cannot flood it.
This migration is SCHEMA ONLY — the rate-cap / TTL enforcement logic lands in a
later 3b task. Confirms the table, composite PK, both indexes; applies fresh;
existing-data DB still migrates. Mirrors the migration 053/054 tests.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from stigmem_node.db import apply_migrations

_EXPECTED_COLUMNS = {
    "entity_uri",
    "node_id",
    "candidate_key_fpr",
    "source",
    "relay_peer",
    "seen_at",
}


def _table_info(db_path: Path, table: str) -> list[tuple]:
    with sqlite3.connect(db_path) as conn:
        return conn.execute(f"PRAGMA table_info({table})").fetchall()


def _index_columns(db_path: Path, table: str) -> dict[str, list[str]]:
    """Return {index_name: [indexed column names]} for *table*."""
    out: dict[str, list[str]] = {}
    with sqlite3.connect(db_path) as conn:
        index_rows = conn.execute(f"PRAGMA index_list({table})").fetchall()
        # PRAGMA index_list row: (seq, name, unique, origin, partial)
        for row in index_rows:
            idx_name = row[1]
            cols = [r[2] for r in conn.execute(f"PRAGMA index_info({idx_name})").fetchall()]
            out[idx_name] = cols
    return out


def test_migration_055_creates_table_with_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "pending_first_trust")
    assert rows, "pending_first_trust table not created"
    col_names = {row[1] for row in rows}
    assert col_names == _EXPECTED_COLUMNS, (
        f"column mismatch: extra={col_names - _EXPECTED_COLUMNS}, "
        f"missing={_EXPECTED_COLUMNS - col_names}"
    )


def test_migration_055_composite_primary_key(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    rows = _table_info(db_path, "pending_first_trust")
    pk_cols = {row[1] for row in rows if row[5] > 0}
    assert pk_cols == {"entity_uri", "node_id"}, f"unexpected PK columns: {pk_cols}"


def test_migration_055_has_relay_peer_and_seen_at_indexes(tmp_path: Path) -> None:
    """A relay_peer index (per-peer cap) and a seen_at index (TTL eviction)."""
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))

    indexed_cols = {tuple(cols) for cols in _index_columns(db_path, "pending_first_trust").values()}
    assert ("relay_peer",) in indexed_cols, f"no relay_peer index; got {indexed_cols}"
    assert ("seen_at",) in indexed_cols, f"no seen_at index; got {indexed_cols}"


def test_migration_055_existing_data_still_migrates(tmp_path: Path) -> None:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO pending_first_trust "
            "(entity_uri, node_id, candidate_key_fpr, source, relay_peer, seen_at) "
            "VALUES ('https://memory.acme.example/', 'node-1', 'sha256:abc', "
            "'unsigned', 'peer-7', '2026-06-12T00:00:00Z')"
        )
        conn.commit()

    apply_migrations(db_path=str(db_path))  # must not raise over populated DB

    with sqlite3.connect(db_path) as conn:
        cnt = conn.execute("SELECT COUNT(*) FROM pending_first_trust").fetchone()[0]
    assert cnt == 1
