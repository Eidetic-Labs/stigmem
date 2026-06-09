"""Postgres-specific backend tests — Phase 11 (ACM-242).

Covers edge cases that are unique to the Postgres adapter:

  * Transaction isolation (rollback on exception, commit on success)
  * Idempotent migration runner (re-running apply_migrations is a no-op)
  * Schema migration DDL: schema_migrations table created; versions recorded
  * INSERT OR REPLACE → upsert behaviour (ON CONFLICT … DO UPDATE)
  * INSERT OR IGNORE → no-op on duplicate key (ON CONFLICT DO NOTHING)
  * SQL parameter rewriting (``?`` → ``%s``)
  * Percent-literal escaping in LIKE patterns
  * Vector index DDL when embed_enabled=True (skipped if pgvector absent)
  * backend_name property returns "postgres"
  * Snapshot hooks raise NotImplementedError
  * Connection pool: multiple concurrent connections

All tests skip automatically when ``STIGMEM_TEST_PG_DSN`` is unset so the
default ``pytest`` run (SQLite) is unaffected.

Run against a live Postgres instance::

    STIGMEM_TEST_PG_DSN=postgresql://user:pw@localhost/stigmem_test \\
        pytest tests/test_postgres_backend.py -v
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

import pytest

import stigmem_node

_MIGRATIONS_DIR = Path(stigmem_node.__file__).resolve().parent.parent / "migrations"
FLOAT_COMPARISON_TOLERANCE = 1e-6
logger = logging.getLogger(__name__)


class TestSchemaNameValidation:
    def test_schema_name_rejects_sql_identifier_injection(self) -> None:
        from stigmem_node.storage.postgres_backend import PostgresBackend

        with pytest.raises(ValueError, match="schema name must match"):
            PostgresBackend(
                dsn="postgresql://example.invalid/db",
                schema='public"; DROP TABLE x; --',
            )

    def test_schema_name_accepts_safe_identifier(self) -> None:
        from stigmem_node.storage.postgres_backend import PostgresBackend

        backend = PostgresBackend(dsn="postgresql://example.invalid/db", schema="valid_name_123")

        assert backend.backend_name == "postgres"


# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------


def _pg_dsn() -> str:
    return os.environ.get("STIGMEM_TEST_PG_DSN", "")


def _require_pg() -> str:
    dsn = _pg_dsn()
    if not dsn:
        pytest.skip("STIGMEM_TEST_PG_DSN not set — skipping Postgres backend tests")
    pytest.importorskip("psycopg2", reason="psycopg2 not installed")
    return dsn


def _drop_test_schema(dsn: str, schema: str) -> None:
    try:
        import psycopg2
        from psycopg2 import sql
    except ImportError as exc:
        logger.warning(
            "psycopg2 unavailable during postgres test schema cleanup %s: %s",
            schema,
            exc,
        )
        return

    conn = None
    try:
        conn = psycopg2.connect(dsn)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
    except psycopg2.Error as exc:
        logger.warning("failed to drop postgres test schema %s: %s", schema, exc)
    finally:
        if conn is not None:
            conn.close()


# ---------------------------------------------------------------------------
# Fixture: fresh schema per test
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_backend():
    """Create a PostgresBackend with a unique per-test schema; drop after test."""
    from stigmem_node.storage.postgres_backend import PostgresBackend

    dsn = _require_pg()
    schema = f"pgtest_{uuid.uuid4().hex[:12]}"

    b = PostgresBackend(dsn=dsn, schema=schema)
    b.apply_migrations(_MIGRATIONS_DIR)
    yield b

    # Teardown: drop the test schema.
    _drop_test_schema(dsn, schema)


# ---------------------------------------------------------------------------
# Basic identity / connectivity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_backend_name(self, pg_backend) -> None:
        assert pg_backend.backend_name == "postgres"

    def test_connection_opens_and_commits(self, pg_backend) -> None:
        with pg_backend.connection() as conn:
            row = conn.execute("SELECT 1 AS n").fetchone()
        assert row is not None
        assert row["n"] == 1

    def test_snapshot_export_raises(self, pg_backend, tmp_path) -> None:
        with pytest.raises(NotImplementedError):
            pg_backend.export_snapshot(tmp_path / "snap.pgdump")

    def test_snapshot_import_raises(self, pg_backend, tmp_path) -> None:
        with pytest.raises(NotImplementedError):
            pg_backend.import_snapshot(tmp_path / "snap.pgdump")


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------


class TestMigrations:
    def test_schema_migrations_table_created(self, pg_backend) -> None:
        with pg_backend.connection() as conn:
            rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
        versions = [r["version"] for r in rows]
        # Sentinel migrations should be present at the current compatibility boundary.
        assert "001_init" in versions
        assert "021_instruction_discovery" in versions

    def test_all_migrations_applied(self, pg_backend) -> None:
        with pg_backend.connection() as conn:
            rows = conn.execute("SELECT COUNT(*) AS n FROM schema_migrations").fetchone()
        assert rows is not None
        assert rows["n"] >= 21

    def test_apply_migrations_idempotent(self, pg_backend) -> None:
        """Re-running apply_migrations must not duplicate or fail."""
        with pg_backend.connection() as conn:
            before = conn.execute("SELECT COUNT(*) AS n FROM schema_migrations").fetchone()
        pg_backend.apply_migrations(_MIGRATIONS_DIR)
        with pg_backend.connection() as conn:
            after = conn.execute("SELECT COUNT(*) AS n FROM schema_migrations").fetchone()
        assert before is not None and after is not None
        assert before["n"] == after["n"]

    def test_facts_table_exists(self, pg_backend) -> None:
        with pg_backend.connection() as conn:
            conn.execute("SELECT id FROM facts LIMIT 1")

    def test_node_meta_table_exists(self, pg_backend) -> None:
        with pg_backend.connection() as conn:
            conn.execute("SELECT key FROM node_meta LIMIT 1")


# ---------------------------------------------------------------------------
# Transaction isolation
# ---------------------------------------------------------------------------


class TestTransactions:
    def test_rollback_on_exception(self, pg_backend) -> None:
        """Exception inside connection() must rollback; changes must not persist."""
        fact_id = f"txn-rollback-{uuid.uuid4()}"
        caught: RuntimeError | None = None
        try:
            with pg_backend.connection() as conn:
                conn.execute(
                    "INSERT INTO facts "
                    "(id, entity, relation, value_type, value_v, source, "
                    "timestamp, confidence, scope) "
                    "VALUES (?, 'e', 'r', 'string', 'v', 's', "
                    "'2026-01-01T00:00:00Z', 1.0, 'local')",
                    (fact_id,),
                )
                raise RuntimeError("deliberate rollback trigger")
        except RuntimeError as exc:
            caught = exc

        assert caught is not None
        assert str(caught) == "deliberate rollback trigger"

        with pg_backend.connection() as conn:
            row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
        assert row is None, "Rolled-back fact must not be visible"

    def test_commit_on_clean_exit(self, pg_backend) -> None:
        fact_id = f"txn-commit-{uuid.uuid4()}"
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, 'e', 'r', 'string', 'v', 's', '2026-01-01T00:00:00Z', 1.0, 'local')",
                (fact_id,),
            )

        with pg_backend.connection() as conn:
            row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
        assert row is not None
        assert row["id"] == fact_id


# ---------------------------------------------------------------------------
# SQL dialect rewriting
# ---------------------------------------------------------------------------


class TestSQLAdaptation:
    def test_question_mark_params(self, pg_backend) -> None:
        fact_id = f"qmark-{uuid.uuid4()}"
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fact_id,
                    "ent",
                    "rel",
                    "string",
                    "val",
                    "src",
                    "2026-01-01T00:00:00Z",
                    0.9,
                    "local",
                ),
            )
            row = conn.execute("SELECT value_v FROM facts WHERE id = ?", (fact_id,)).fetchone()
        assert row is not None
        assert row["value_v"] == "val"

    def test_insert_or_ignore(self, pg_backend) -> None:
        """INSERT OR IGNORE must silently skip on duplicate primary key."""
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO node_meta (key, value) VALUES (?, ?)",
                ("test_key_ignore", "first"),
            )
            conn.execute(
                "INSERT OR IGNORE INTO node_meta (key, value) VALUES (?, ?)",
                ("test_key_ignore", "second"),  # duplicate — must be ignored
            )
            row = conn.execute(
                "SELECT value FROM node_meta WHERE key = ?", ("test_key_ignore",)
            ).fetchone()
        assert row is not None
        assert row["value"] == "first"  # second insert was ignored

    def test_insert_or_replace(self, pg_backend) -> None:
        """INSERT OR REPLACE must update the existing row."""
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO node_meta (key, value) VALUES (?, ?)",
                ("test_key_replace", "original"),
            )
            conn.execute(
                "INSERT OR REPLACE INTO node_meta (key, value) VALUES (?, ?)",
                ("test_key_replace", "updated"),
            )
            row = conn.execute(
                "SELECT value FROM node_meta WHERE key = ?", ("test_key_replace",)
            ).fetchone()
        assert row is not None
        assert row["value"] == "updated"

    def test_like_pattern_with_percent(self, pg_backend) -> None:
        """LIKE 'stigmem://%' literals must not be mangled; SQL uses '%%' for escaped percent."""
        fact_id = f"like-test-{uuid.uuid4()}"
        nonmatch_id = f"like-test-nonmatch-{uuid.uuid4()}"
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    fact_id,
                    "stigmem://host/agent/alice",
                    "rel",
                    "string",
                    "v",
                    "src",
                    "2026-01-01T00:00:00Z",
                    1.0,
                    "local",
                ),
            )
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    nonmatch_id,
                    "http://example.com/nonmatch",
                    "rel",
                    "string",
                    "v",
                    "src",
                    "2026-01-01T00:00:00Z",
                    1.0,
                    "local",
                ),
            )
            rows = conn.execute(
                "SELECT id FROM facts WHERE entity LIKE 'stigmem://%%'",
            ).fetchall()
            sql_template = "SELECT id FROM %(table)s WHERE entity LIKE 'stigmem://%%%%'"
            sql_with_percent_format = sql_template % {"table": "facts"}
            rows_percent_format = conn.execute(sql_with_percent_format).fetchall()
        returned_ids = {r["id"] for r in rows}
        returned_ids_percent_format = {r["id"] for r in rows_percent_format}
        assert fact_id in returned_ids
        assert nonmatch_id not in returned_ids
        assert fact_id in returned_ids_percent_format
        assert nonmatch_id not in returned_ids_percent_format

    def test_row_dict_access(self, pg_backend) -> None:
        fact_id = f"row-dict-{uuid.uuid4()}"
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fact_id, "e", "r", "string", "hello", "src", "2026-01-01T00:00:00Z", 0.8, "local"),
            )
            row = conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
        assert row is not None
        # Dict-style access
        assert row["id"] == fact_id
        assert row["value_v"] == "hello"
        # Integer index access
        assert row[0] == fact_id
        # .get() with default
        assert row.get("confidence") == pytest.approx(
            0.8, abs=FLOAT_COMPARISON_TOLERANCE
        )
        assert row.get("nonexistent_col", "fallback") == "fallback"
        # .keys()
        assert "id" in row
        assert "entity" in row

        null_fact_id = f"row-dict-null-{uuid.uuid4()}"
        with pg_backend.connection() as conn:
            conn.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    null_fact_id,
                    "e-null",
                    "r",
                    "string",
                    "hello-null",
                    "src",
                    "2026-01-01T00:00:00Z",
                    None,
                    "local",
                ),
            )
            null_row = conn.execute(
                "SELECT * FROM facts WHERE id = ?", (null_fact_id,)
            ).fetchone()
        assert null_row is not None
        assert null_row.get("confidence") is None
        assert null_row.get("confidence", "fallback") is None


# ---------------------------------------------------------------------------
# Composite primary key upsert (boot_stubs)
# ---------------------------------------------------------------------------


class TestCompositeKeyUpsert:
    def test_boot_stubs_insert_or_replace(self, pg_backend) -> None:
        # boot_stubs PK is (agent_id, adapter_profile, tenant_id) after migration
        # 039 — the INSERT OR REPLACE → ON CONFLICT rewrite must target all three
        # columns (_TABLE_PK), and rows for different tenants must NOT collide.
        agent_id = f"agent-{uuid.uuid4()}"
        cols = (
            "(agent_id, adapter_profile, stub_version, body, token_count, "
            "generated_at, manifest_version, tenant_id)"
        )
        with pg_backend.connection() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO boot_stubs {cols} VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, "generic", 1, "# stub v1", 10, 1000, "v1", "default"),
            )
            # Same agent+profile in another tenant — must be a SEPARATE row.
            conn.execute(
                f"INSERT OR REPLACE INTO boot_stubs {cols} VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, "generic", 1, "# stub tenant-x", 9, 1500, "v1", "tenant-x"),
            )
            # Upsert the default-tenant row (same 3-col key) — must overwrite it only.
            conn.execute(
                f"INSERT OR REPLACE INTO boot_stubs {cols} VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (agent_id, "generic", 2, "# stub v2", 12, 2000, "v2", "default"),
            )
            rows = conn.execute(
                """SELECT tenant_id, stub_version, body FROM boot_stubs
                   WHERE agent_id = ? AND adapter_profile = ?
                   ORDER BY tenant_id""",
                (agent_id, "generic"),
            ).fetchall()
        by_tenant = {r["tenant_id"]: (r["stub_version"], r["body"]) for r in rows}
        assert by_tenant == {
            "default": (2, "# stub v2"),  # upserted, not duplicated
            "tenant-x": (1, "# stub tenant-x"),  # isolated, untouched
        }


# ---------------------------------------------------------------------------
# Vector index DDL (skipped when pgvector not installed)
# ---------------------------------------------------------------------------


class TestVectorIndex:
    def test_vec_facts_table_created_when_embed_enabled(self) -> None:
        from stigmem_node.storage.postgres_backend import PostgresBackend

        pytest.importorskip("pgvector", reason="pgvector not installed")
        dsn = _require_pg()
        schema = f"pgvec_{uuid.uuid4().hex[:12]}"
        b = PostgresBackend(dsn=dsn, schema=schema, embed_enabled=True, embed_dimension=4)
        try:
            b.apply_migrations(_MIGRATIONS_DIR)
            with b.connection() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM information_schema.tables "
                    "WHERE table_schema = ? AND table_name = 'vec_facts'",
                    (schema,),
                ).fetchone()
            assert row is not None
            assert row["n"] == 1
        finally:
            _drop_test_schema(dsn, schema)


# ---------------------------------------------------------------------------
# Multiple concurrent connections (pool smoke test)
# ---------------------------------------------------------------------------


class TestConnectionPool:
    def test_multiple_connections(self, pg_backend) -> None:
        """Two concurrent context manager invocations should both succeed."""
        fact_a = f"pool-a-{uuid.uuid4()}"
        fact_b = f"pool-b-{uuid.uuid4()}"

        with pg_backend.connection() as conn_a:
            conn_a.execute(
                "INSERT INTO facts "
                "(id, entity, relation, value_type, value_v, source, timestamp, confidence, scope) "
                "VALUES (?, 'e', 'r', 'string', 'a', 's', '2026-01-01T00:00:00Z', 1.0, 'local')",
                (fact_a,),
            )
            with pg_backend.connection() as conn_b:
                conn_b.execute(
                    "INSERT INTO facts "
                    "(id, entity, relation, value_type, value_v, source, timestamp, "
                    "confidence, scope) "
                    "VALUES (?, 'e', 'r', 'string', 'b', 's', "
                    "'2026-01-01T00:00:00Z', 1.0, 'local')",
                    (fact_b,),
                )

        with pg_backend.connection() as conn:
            rows = conn.execute(
                "SELECT id FROM facts WHERE id IN (?, ?) ORDER BY id", (fact_a, fact_b)
            ).fetchall()
        ids = {r["id"] for r in rows}
        assert fact_a in ids
        assert fact_b in ids
