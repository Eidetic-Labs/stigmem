from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest
from conftest import _make_enc_settings, _patch_settings, _restore_settings
from fastapi.testclient import TestClient

import stigmem_node.settings as settings_module
from stigmem_node.db import _MIGRATIONS_DIR, apply_migrations
from stigmem_node.main import create_app
from stigmem_node.storage import make_backend

_LEGACY_RELEASE_MAX_MIGRATION = 12
_LEGACY_FACT_ID = "stigmem:fact:legacy-compat"


def _copy_legacy_release_migrations(dest: Path) -> None:
    for migration in sorted(_MIGRATIONS_DIR.glob("*.sql")):
        version = int(migration.stem.split("_", 1)[0])
        if version <= _LEGACY_RELEASE_MAX_MIGRATION:
            shutil.copy2(migration, dest / migration.name)


def _seed_v1_rc_fact(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO facts (
            id,
            entity,
            relation,
            value_type,
            value_v,
            source,
            timestamp,
            valid_until,
            confidence,
            scope,
            hlc,
            received_from,
            attested_key_id,
            origin_node_id,
            origin_allowed_scopes,
            re_federation_blocked,
            garden_id,
            attested,
            tenant_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _LEGACY_FACT_ID,
            "compat:migration",
            "memory:role",
            "string",
            "Architect",
            "agent:legacy-client",
            "2026-01-01T00:00:00Z",
            None,
            1.0,
            "company",
            "1735689600000.000",
            None,
            None,
            None,
            None,
            0,
            None,
            None,
            "default",
        ),
    )
    conn.commit()
    conn.close()


def _facts_columns(db_path: Path) -> set[str]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute("PRAGMA table_info(facts)").fetchall()
    conn.close()
    return {row[1] for row in rows}


def test_upgrade_from_v1_rc_schema_applies_all_current_migrations(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    legacy_migrations_dir = tmp_path / "v1-rc-migrations"
    legacy_migrations_dir.mkdir()
    _copy_legacy_release_migrations(legacy_migrations_dir)

    backend = make_backend(db_path=str(db_path))
    backend.apply_migrations(legacy_migrations_dir)
    _seed_v1_rc_fact(db_path)

    apply_migrations(db_path=str(db_path))

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    applied = {row["version"] for row in conn.execute("SELECT version FROM schema_migrations")}
    fact = conn.execute(
        "SELECT id, entity, relation, value_v, tenant_id FROM facts WHERE id = ?",
        (_LEGACY_FACT_ID,),
    ).fetchone()
    conn.close()

    expected_versions = {migration.stem for migration in _MIGRATIONS_DIR.glob("*.sql")}
    assert applied == expected_versions
    assert fact is not None
    assert fact["entity"] == "compat:migration"
    assert fact["relation"] == "memory:role"
    assert fact["value_v"] == "Architect"
    assert fact["tenant_id"] == "default"

    facts_columns = _facts_columns(db_path)
    assert {"tenant_id", "garden_id", "cid", "re_federation_blocked"} <= facts_columns


def test_current_app_can_query_facts_after_v1_rc_upgrade(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-app.db"
    legacy_migrations_dir = tmp_path / "v1-rc-migrations-app"
    legacy_migrations_dir.mkdir()
    _copy_legacy_release_migrations(legacy_migrations_dir)

    backend = make_backend(db_path=str(db_path))
    backend.apply_migrations(legacy_migrations_dir)
    _seed_v1_rc_fact(db_path)
    apply_migrations(db_path=str(db_path))

    original = settings_module.settings
    test_settings = _make_enc_settings(
        str(db_path),
        "sqlite",
        "off",
        auth_required=False,
        node_url="http://testnode",
    )
    extra = _patch_settings(test_settings)
    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            response = client.get(
                "/v1/facts",
                params={"entity": "compat:migration", "scope": "company", "limit": 10},
            )
        assert response.status_code == 200
        payload = response.json()
        assert any(fact["id"] == _LEGACY_FACT_ID for fact in payload["facts"])
    finally:
        _restore_settings(original, extra)


def _write_partial_migration(mig_dir: Path) -> None:
    """A 2-statement migration whose 2nd statement fails (duplicate CREATE)."""
    mig_dir.mkdir(exist_ok=True)
    (mig_dir / "001_partial.sql").write_text(
        "CREATE TABLE mig_atomic_probe (id INTEGER PRIMARY KEY);\n"
        "CREATE TABLE mig_atomic_probe (id INTEGER PRIMARY KEY);\n"
    )


def _assert_migration_rolled_back(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert "mig_atomic_probe" not in tables, "partial migration was not rolled back"
        applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
        assert "001_partial" not in applied, "failed migration must not be recorded as applied"
    finally:
        conn.close()


def test_failed_migration_rolls_back_atomically_sqlite(tmp_path: Path) -> None:
    """A migration that fails partway must leave NO partial schema and must not be
    recorded as applied (audit F-MIG-TXN).

    SQLite ``executescript`` committed each statement as it ran, so a rebuild
    migration that failed after an early statement (e.g. CREATE/DROP) left a
    half-applied, committed schema. Each migration file must apply atomically.
    """
    db_path = tmp_path / "atomic.db"
    mig_dir = tmp_path / "migrations"
    _write_partial_migration(mig_dir)

    backend = make_backend(db_path=str(db_path))  # always SQLiteBackend
    with pytest.raises(Exception):  # noqa: B017 — backend-specific OperationalError
        backend.apply_migrations(mig_dir)

    _assert_migration_rolled_back(db_path)


def test_failed_migration_rolls_back_atomically_libsql(tmp_path: Path) -> None:
    """libsql parity for F-MIG-TXN — a failed migration rolls back via the
    runner's per-file transaction (skips locally when libsql isn't installed)."""
    pytest.importorskip("libsql_experimental", reason="libsql-experimental not installed")
    from stigmem_node.storage.libsql_backend import LibsqlBackend

    db_path = tmp_path / "atomic-libsql.db"
    mig_dir = tmp_path / "migrations-libsql"
    _write_partial_migration(mig_dir)

    backend = LibsqlBackend(db_path=str(db_path))
    with pytest.raises(Exception):  # noqa: B017
        backend.apply_migrations(mig_dir)

    _assert_migration_rolled_back(db_path)
