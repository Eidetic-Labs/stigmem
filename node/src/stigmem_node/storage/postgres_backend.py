"""PostgreSQL implementation of StorageBackend — feature-flagged (Phase 11).

Uses psycopg2 with a SQLite-API-compatible wrapper so all existing SQL
(written for ``?`` placeholders and ``row["col"]`` access) works without
modification.  SQL is translated on the fly:

  * ``?``  → ``%s``  (psycopg2 placeholder style)
  * Literal ``%`` in SQL literals → ``%%`` (psycopg2 escaping)
  * ``INSERT OR IGNORE``  → ``INSERT … ON CONFLICT DO NOTHING``
  * ``INSERT OR REPLACE`` → ``INSERT … ON CONFLICT (pk) DO UPDATE SET …``
  * ``AUTOINCREMENT``     → ``SERIAL`` in migration DDL

The backend applies migrations from a ``migrations_pg/`` sibling directory
when a per-version override exists there, falling back to the standard file.
Overrides handle SQLite-specific DDL: PRAGMA, FTS5 virtual tables, GLOB
patterns, and table-rebuild workarounds for CHECK constraint changes.

Install before use::

    pip install 'stigmem-node[postgres]'

Environment variables::

    STIGMEM_BACKEND=postgres
    DATABASE_URL=postgresql://user:pass@host:5432/dbname
    # or equivalently STIGMEM_DATABASE_URL=...

Per-test schema isolation::

    PostgresBackend(dsn=..., schema="test_mytest_abc123")

The backend creates the schema on first ``apply_migrations()`` call and the
test harness can DROP it when the test finishes.

Note on asyncpg
---------------
The issue spec originally mentioned asyncpg for connection pooling, but asyncpg
is async-only and incompatible with the synchronous ``StorageBackend`` interface.
psycopg2 with ``ThreadedConnectionPool`` provides equivalent pooling for the
sync path.  A future async backend can wrap asyncpg independently.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import StorageBackend

logger = logging.getLogger("stigmem.storage.postgres")

_SCHEMA_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


def _validate_schema_name(schema: str) -> str:
    """Validate a Postgres schema identifier accepted by this backend."""
    if not _SCHEMA_NAME_RE.fullmatch(schema):
        raise ValueError(
            "PostgresBackend schema name must match [a-z][a-z0-9_]{0,62}; "
            f"got {schema!r}"
        )
    return schema


# ---------------------------------------------------------------------------
# Primary-key map for INSERT OR REPLACE rewriting
# ---------------------------------------------------------------------------

# Maps (lowercase) table name → list of primary key columns.
# Add an entry here when a new table uses INSERT OR REPLACE.
_TABLE_PK: dict[str, list[str]] = {
    "node_meta": ["key"],
    "entity_aliases": ["raw_uri"],
    "vec_facts": ["fact_id"],
    "boot_stubs": ["agent_id", "adapter_profile", "tenant_id"],
    "schema_migrations": ["version"],
}

# ---------------------------------------------------------------------------
# SQL transpilation helpers
# ---------------------------------------------------------------------------

_OR_IGNORE_RE = re.compile(r"\bINSERT\s+OR\s+IGNORE\b", re.IGNORECASE)
_OR_REPLACE_RE = re.compile(
    r"\bINSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)
# SQLite strftime('%s', col) → EXTRACT(EPOCH FROM col::timestamptz)
# Must be translated before the % → %% escaping step.
# Bounded quantifiers — defends against the ``py/polynomial-redos`` heuristic
# (CodeQL #21).  Inputs are developer-authored migration SQL in practice, but
# bounding ``\s{0,16}`` and ``[^)]{1,256}?`` removes any theoretical
# superlinear-backtracking case and quiets the analyzer permanently.
_STRFTIME_EPOCH_RE = re.compile(r"strftime\('%s',\s{0,16}([^)]{1,256}?)\)", re.IGNORECASE)


def _rewrite_or_ignore(sql: str) -> str:
    """INSERT OR IGNORE … → INSERT … ON CONFLICT DO NOTHING."""
    if not _OR_IGNORE_RE.search(sql):
        return sql
    sql = _OR_IGNORE_RE.sub("INSERT", sql)
    return sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"


def _rewrite_or_replace(sql: str) -> str:
    """INSERT OR REPLACE INTO table (cols) VALUES (…) → Postgres upsert."""
    m = _OR_REPLACE_RE.search(sql)
    if not m:
        return sql

    table = m.group(1).lower()
    cols = [c.strip() for c in m.group(2).split(",")]
    pk_cols = _TABLE_PK.get(table, [])
    pk_set = set(pk_cols)
    update_cols = [c for c in cols if c not in pk_set]

    # Strip 'OR REPLACE' and rebuild
    sql = _OR_REPLACE_RE.sub(
        lambda mx: f"INSERT INTO {mx.group(1)} ({mx.group(2)})",
        sql,
    )
    sql = sql.rstrip().rstrip(";")

    if pk_cols:
        conflict_target = ", ".join(pk_cols)
        if update_cols:
            set_clauses = ", ".join(f"{c} = EXCLUDED.{c}" for c in update_cols)
            sql += f"\nON CONFLICT ({conflict_target}) DO UPDATE SET {set_clauses}"  # nosec B608 — conflict_target and update_cols are column names from _TABLE_PK (hardcoded schema dict), not user input
        else:
            sql += f"\nON CONFLICT ({conflict_target}) DO NOTHING"
    else:
        logger.warning(
            "INSERT OR REPLACE for unknown table %r — add it to _TABLE_PK; "
            "falling back to ON CONFLICT DO NOTHING",
            table,
        )
        sql += " ON CONFLICT DO NOTHING"

    return sql


def _pg_translate(sql: str) -> str:
    """Translate a SQLite DML/DDL string to psycopg2/Postgres format.

    Applied in order:
    1. Rewrite ``INSERT OR IGNORE`` and ``INSERT OR REPLACE``.
    2. Translate ``strftime('%s', col)`` → ``EXTRACT(EPOCH FROM col::timestamptz)``.
       Must happen before step 3 so the ``%s`` inside strftime is not mangled.
    3. Escape literal ``%`` → ``%%`` (psycopg2 treats bare ``%`` as special).
    4. Replace ``?`` parameter placeholders with ``%s``.
    5. Translate ``INTEGER PRIMARY KEY AUTOINCREMENT`` → ``SERIAL PRIMARY KEY``.
    """
    if _OR_IGNORE_RE.search(sql):
        sql = _rewrite_or_ignore(sql)
    elif _OR_REPLACE_RE.search(sql):
        sql = _rewrite_or_replace(sql)

    sql = _STRFTIME_EPOCH_RE.sub(r"EXTRACT(EPOCH FROM \1::timestamptz)", sql)
    sql = sql.replace("%", "%%")
    sql = sql.replace("?", "%s")
    sql = re.sub(
        r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT",
        "SERIAL PRIMARY KEY",
        sql,
        flags=re.IGNORECASE,
    )
    return sql


def _pg_split_migration(sql: str) -> list[str]:
    """Split a migration script into Postgres-executable statements.

    Strips comments, then splits on ``;``.  Filters out SQLite-specific
    statements (PRAGMA, CREATE VIRTUAL TABLE, fts5 triggers, bare
    transaction keywords left by trigger-body splits).  Remaining
    statements are passed through ``_pg_translate()``.

    When a ``migrations_pg/`` override file is used, this function is still
    called on the override SQL — the override files contain clean Postgres DDL
    so filtering is effectively a no-op for them.
    """
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)

    statements: list[str] = []
    for raw in sql.split(";"):
        stmt = raw.strip()
        if not stmt:
            continue
        upper = stmt.upper()
        # Bare transaction / PL body delimiters left from trigger splits
        if upper in ("BEGIN", "END", "COMMIT", "ROLLBACK"):
            continue
        # SQLite PRAGMA — no Postgres equivalent
        if re.match(r"\s*PRAGMA\b", stmt, re.IGNORECASE):
            continue
        # FTS5 virtual table
        if re.search(r"USING\s+fts5", stmt, re.IGNORECASE):
            continue
        # Any statement touching facts_fts (SQLite FTS5 triggers / inserts)
        if re.search(r"\bfacts_fts\b", stmt, re.IGNORECASE):
            continue
        # Generic CREATE VIRTUAL TABLE guard
        if re.search(r"CREATE\s+VIRTUAL\s+TABLE", stmt, re.IGNORECASE):
            continue
        statements.append(_pg_translate(stmt))

    return statements


# ---------------------------------------------------------------------------
# SQLite-API-compatible row wrapper
# ---------------------------------------------------------------------------


class _PGRow:
    """Dict-like wrapper around a psycopg2 ``RealDictRow``.

    Supports ``row["col"]``, ``row[i]`` (by position), ``row.keys()``, and
    ``row.get(key, default)`` — the same contract as ``sqlite3.Row``.
    """

    __slots__ = ("_d", "_vals")

    def __init__(self, d: dict[str, Any], vals: tuple[Any, ...]) -> None:
        self._d = d
        self._vals = vals

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._vals[key]
        return self._d[key]

    def __iter__(self) -> Any:
        return iter(self._vals)

    def keys(self) -> list[str]:
        return list(self._d.keys())

    def get(self, key: str, default: Any = None) -> Any:
        return self._d.get(key, default)


# ---------------------------------------------------------------------------
# Cursor wrapper
# ---------------------------------------------------------------------------


class _PGCursor:
    """Wraps a psycopg2 ``RealDictCursor`` to match the sqlite3 cursor API."""

    def __init__(self, cur: Any) -> None:
        self._cur = cur

    def fetchall(self) -> list[_PGRow]:
        rows = self._cur.fetchall()
        return [_PGRow(dict(r), tuple(r.values())) for r in rows]

    def fetchone(self) -> _PGRow | None:
        r = self._cur.fetchone()
        if r is None:
            return None
        return _PGRow(dict(r), tuple(r.values()))

    def __iter__(self) -> Any:
        for r in self._cur:
            yield _PGRow(dict(r), tuple(r.values()))

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Connection wrapper
# ---------------------------------------------------------------------------


class _PGConn:
    """SQLite-API-compatible wrapper around a psycopg2 connection.

    Creates a fresh ``RealDictCursor`` per ``execute()`` call so multiple
    cursors can be open concurrently, matching sqlite3 semantics.
    """

    def __init__(self, pg_conn: Any) -> None:
        self._conn = pg_conn

    def execute(self, sql: str, params: Any = ()) -> _PGCursor:
        import psycopg2.extras

        translated = _pg_translate(sql)
        cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(translated, params or ())
        return _PGCursor(cur)

    def executemany(self, sql: str, seq: Any) -> None:
        translated = _pg_translate(sql)
        cur = self._conn.cursor()
        cur.executemany(translated, seq)

    def executescript(self, sql: str) -> None:
        """Execute a SQL script (multiple statements separated by ';')."""
        for stmt in _pg_split_migration(sql):
            cur = self._conn.cursor()
            cur.execute(stmt)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        # Pool connection — returned to pool by the context manager; do nothing.
        pass


# ---------------------------------------------------------------------------
# PostgresBackend
# ---------------------------------------------------------------------------


class PostgresBackend(StorageBackend):
    """PostgreSQL backend using psycopg2 with a ``ThreadedConnectionPool``.

    Args:
        dsn:        libpq connection string, e.g.
                    ``"postgresql://user:pw@localhost/stigmem"``.
        schema:     Postgres schema for all tables (default ``"public"``).
                    Use a unique value per test run for schema-level isolation.
        pool_min:   Minimum pool size (default 2).
        pool_max:   Maximum pool size (default 10).
        embed_enabled:  When True, creates a pgvector ``vec_facts`` table.
        embed_dimension: Vector dimension (must match embedding model).
    """

    def __init__(
        self,
        dsn: str,
        schema: str = "public",
        pool_min: int = 2,
        pool_max: int = 10,
        embed_enabled: bool = False,
        embed_dimension: int = 768,
    ) -> None:
        self._dsn = dsn
        self._schema = _validate_schema_name(schema)
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._embed_enabled = embed_enabled
        self._embed_dimension = embed_dimension
        self._pool: Any = None

    @property
    def backend_name(self) -> str:
        return "postgres"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_pool(self) -> Any:
        """Lazily create and return the thread-safe psycopg2 connection pool."""
        if self._pool is not None:
            return self._pool
        try:
            import psycopg2.pool
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2 is required for the PostgreSQL backend. "
                "Install it with: pip install 'stigmem-node[postgres]'"
            ) from exc
        self._pool = psycopg2.pool.ThreadedConnectionPool(
            self._pool_min,
            self._pool_max,
            self._dsn,
        )
        return self._pool

    def _open_raw_conn(self) -> Any:
        """Open a direct psycopg2 connection (used by apply_migrations)."""
        try:
            import psycopg2
        except ImportError as exc:
            raise RuntimeError(
                "psycopg2 is required for the PostgreSQL backend. "
                "Install it with: pip install 'stigmem-node[postgres]'"
            ) from exc
        return psycopg2.connect(self._dsn)

    def _set_search_path(self, conn: Any) -> None:
        """Set the active schema using identifier quoting."""
        from psycopg2 import sql

        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(self._schema))
            )

    def _pg_migrations(self, migrations_dir: Path) -> list[Path]:
        """Ordered migration files, preferring Postgres-specific overrides.

        Looks for a ``migrations_pg/`` sibling to *migrations_dir*.  For each
        version present there, the pg-specific file takes precedence.
        """
        pg_dir = migrations_dir.parent / "migrations_pg"
        overrides: dict[str, Path] = {}
        if pg_dir.is_dir():
            for f in pg_dir.glob("*.sql"):
                overrides[f.stem] = f

        files: list[Path] = []
        for f in sorted(migrations_dir.glob("*.sql")):
            files.append(overrides.get(f.stem, f))
        return files

    # ------------------------------------------------------------------
    # StorageBackend interface
    # ------------------------------------------------------------------

    @contextmanager
    def connection(self) -> Generator[_PGConn, None, None]:
        pool = self._get_pool()
        pg_conn = pool.getconn()
        wrapped = _PGConn(pg_conn)
        try:
            self._set_search_path(pg_conn)
            yield wrapped
            pg_conn.commit()
        except Exception:
            pg_conn.rollback()
            raise
        finally:
            pool.putconn(pg_conn)

    def apply_migrations(self, migrations_dir: Path) -> None:
        conn = self._open_raw_conn()
        try:
            # Ensure the target schema exists (for per-test schema isolation).
            from psycopg2 import sql

            with conn.cursor() as cur:
                cur.execute(
                    sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                        sql.Identifier(self._schema)
                    )
                )
            self._set_search_path(conn)
            conn.commit()

            # Bootstrap schema_migrations table.
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        id         SERIAL PRIMARY KEY,
                        version    TEXT NOT NULL UNIQUE,
                        applied_at TEXT NOT NULL
                    )
                    """
                )
            conn.commit()

            import psycopg2.extras

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT version FROM schema_migrations")
                applied: set[str] = {r["version"] for r in cur.fetchall()}

            for f in self._pg_migrations(migrations_dir):
                version = f.stem
                if version in applied:
                    continue

                logger.info("Applying migration %s (%s)", version, f.name)
                stmts = _pg_split_migration(f.read_text())
                try:
                    with conn.cursor() as cur:
                        for stmt in stmts:
                            cur.execute(stmt)
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO schema_migrations (version, applied_at) VALUES (%s, %s)",
                            (version, datetime.now(UTC).isoformat()),
                        )
                    conn.commit()
                    logger.info("Migration %s applied", version)
                except Exception:
                    conn.rollback()
                    raise

            if self._embed_enabled:
                self._ensure_vec_table(conn)
        finally:
            conn.close()

    def _ensure_vec_table(self, conn: Any) -> None:
        """Create the pgvector ``vec_facts`` table and index (idempotent)."""
        try:
            from pgvector.psycopg2 import register_vector
        except ImportError as exc:
            raise RuntimeError(
                "pgvector is required for Postgres vector search. "
                "Install it with: pip install 'stigmem-node[postgres]'"
            ) from exc

        register_vector(conn)
        dim = self._embed_dimension
        with conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS vec_facts (
                    fact_id   TEXT PRIMARY KEY,
                    embedding vector({dim})
                )
                """
            )
        with conn.cursor() as cur:
            try:
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS vec_facts_embedding_idx
                    ON vec_facts USING ivfflat (embedding vector_cosine_ops)
                    WITH (lists = 100)
                    """
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not create ivfflat index on vec_facts: %s", exc)
                conn.rollback()
        conn.commit()

    # ------------------------------------------------------------------
    # Snapshot hooks — Postgres backup is an operator concern
    # ------------------------------------------------------------------

    def export_snapshot(self, dest: Path) -> None:
        raise NotImplementedError(
            "PostgresBackend does not support snapshot export. "
            "Use pg_dump or your cloud provider's managed backup tooling."
        )

    def import_snapshot(self, src: Path) -> None:
        raise NotImplementedError(
            "PostgresBackend does not support snapshot import. "
            "Use pg_restore or your cloud provider's managed restore tooling."
        )
