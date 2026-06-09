"""libSQL / Turso adapter for StorageBackend.

Supports two modes:
  * **Local** — ``db_path`` only; behaves like SQLite but via the libsql client.
  * **Embedded-replica** — ``db_path`` + ``sync_url`` + ``auth_token``; local
    SQLite file kept in sync with a Turso database.  Drop-in for Fly.io
    persistent volumes.

Encryption-at-rest is enabled by passing *encryption_key* (32 bytes).  The key
is forwarded to ``libsql.connect()`` as a hex string.  Both local and
embedded-replica modes support encryption; the Turso cloud primary uses its own
server-side encryption independently of the local replica key.

Install the optional dependency before use::

    pip install "stigmem-node[libsql]"
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import StorageBackend


def _split_sql(sql: str) -> list[str]:
    """Split a SQL script into individual statements, stripping comments.

    libsql-experimental does not expose ``executescript()``, so we split
    scripts into complete SQLite statements before executing each one. Trigger
    bodies contain ``BEGIN...END`` blocks with inner semicolons, so a plain
    string split would emit incomplete fragments. FTS5 virtual tables and their
    sync triggers are SQLite-only and are silently dropped so libsql-experimental
    (which lacks FTS5) can still run every migration.
    """
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    stmts: list[str] = []
    pending: list[str] = []

    for line in sql.splitlines():
        if not line.strip():
            continue
        pending.append(line)
        candidate = "\n".join(pending).strip()
        if not sqlite3.complete_statement(candidate):
            continue

        pending.clear()
        stmt = candidate.removesuffix(";").strip()
        upper = stmt.upper()
        # Bare keywords left after splitting trigger/transaction bodies
        if upper in ("BEGIN", "END", "COMMIT", "ROLLBACK"):
            continue
        # FTS5 virtual table — not supported by libsql-experimental
        if re.search(r"CREATE\s+VIRTUAL\s+TABLE", stmt, re.IGNORECASE):
            continue
        # Trigger bodies and backfill inserts that reference facts_fts
        if re.search(r"\bfacts_fts\b", stmt, re.IGNORECASE):
            continue
        stmts.append(stmt)

    if pending:
        raise ValueError("incomplete SQL statement in migration")

    return stmts


class _LibSQLRow:
    """Dict-like row wrapper that supports ``row["col"]`` and ``row[i]`` access.

    libsql-experimental's ``row_factory`` protocol mirrors sqlite3: the factory
    is called as ``factory(cursor, row_tuple)`` for each fetched row.
    """

    __slots__ = ("_data", "_values")

    def __init__(self, cursor: Any, row: tuple[Any, ...]) -> None:
        cols = [d[0] for d in cursor.description]
        self._values: tuple[Any, ...] = row
        self._data: dict[str, Any] = dict(zip(cols, row, strict=True))

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._data[key]

    def __iter__(self) -> Any:
        return iter(self._values)

    def keys(self) -> list[str]:
        return list(self._data.keys())

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)


class _LibSQLCursor:
    """Wraps a raw libsql-experimental cursor and returns _LibSQLRow objects.

    libsql-experimental has no row_factory on the connection; we wrap at the
    cursor level instead so all fetch methods return dict-accessible rows.
    """

    __slots__ = ("_cur",)

    def __init__(self, cur: Any) -> None:
        self._cur = cur

    @property
    def description(self) -> Any:
        return self._cur.description

    @property
    def lastrowid(self) -> Any:
        return self._cur.lastrowid

    @property
    def rowcount(self) -> int:
        count: int = self._cur.rowcount
        return count

    def fetchone(self) -> Any:
        row = self._cur.fetchone()
        return None if row is None else _LibSQLRow(self._cur, row)

    def fetchall(self) -> list[_LibSQLRow]:
        return [_LibSQLRow(self._cur, r) for r in self._cur.fetchall()]

    def fetchmany(self, size: int | None = None) -> list[_LibSQLRow]:
        rows = self._cur.fetchmany(size) if size is not None else self._cur.fetchmany()
        return [_LibSQLRow(self._cur, r) for r in rows]


class _LibSQLConnection:
    """Wraps a raw libsql-experimental connection so execute() returns _LibSQLCursor."""

    __slots__ = ("_conn",)

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: str, params: Any = ()) -> _LibSQLCursor:
        # libsql-experimental only accepts tuples, not lists, for parameters.
        if isinstance(params, list):
            params = tuple(params)
        return _LibSQLCursor(self._conn.execute(sql, params))

    def executemany(self, sql: str, params: Any = ()) -> _LibSQLCursor:
        if not isinstance(params, list):
            params = list(params)
        return _LibSQLCursor(self._conn.executemany(sql, params))

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()


class LibSQLBackend(StorageBackend):
    """libSQL backend (Turso-compatible).

    In embedded-replica mode (``sync_url`` set) the local file acts as the
    read/write store; the client syncs with Turso on every new connection.
    In local mode (no ``sync_url``) the behaviour is equivalent to SQLite.

    Pass *encryption_key* (32 bytes) to enable at-rest encryption for the local
    replica file.  Requires ``libsql-experimental >= 0.0.4`` or a build that
    exposes the ``encryption_key`` parameter in ``libsql.connect()``.
    """

    def __init__(
        self,
        db_path: str,
        sync_url: str = "",
        auth_token: str = "",  # nosec B107 — empty string is the correct default for optional Turso auth
        encryption_key: bytes | None = None,
    ) -> None:
        self._db_path = db_path
        self._sync_url = sync_url
        self._auth_token = auth_token
        self._encryption_key = encryption_key

    @property
    def backend_name(self) -> str:
        return "libsql"

    def _connect(self) -> Any:
        try:
            import libsql_experimental as libsql
        except ImportError as exc:
            raise RuntimeError(
                "libsql-experimental is required for the libSQL backend. "
                "Install it with: pip install 'stigmem-node[libsql]'"
            ) from exc

        enc_kwargs: dict[str, str] = {}
        if self._encryption_key is not None:
            enc_kwargs["encryption_key"] = self._encryption_key.hex()

        if self._sync_url:
            conn = libsql.connect(
                database=self._db_path,
                sync_url=self._sync_url,
                auth_token=self._auth_token,
                **enc_kwargs,
            )
            conn.sync()
        else:
            conn = libsql.connect(database=self._db_path, **enc_kwargs)

        conn.execute("PRAGMA foreign_keys=ON")
        return _LibSQLConnection(conn)

    @contextmanager
    def connection(self) -> Generator[Any, None, None]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def apply_migrations(self, migrations_dir: Path) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS schema_migrations (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    version    TEXT NOT NULL UNIQUE,
                    applied_at TEXT NOT NULL
                )"""
            )
            conn.commit()

            applied = {
                row["version"]
                for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
            }

            for f in sorted(migrations_dir.glob("*.sql")):
                version = f.stem
                if version in applied:
                    continue
                # Apply each migration atomically (audit F-MIG-TXN): statements +
                # the schema_migrations record commit together; any failure rolls
                # the whole file back so a rebuild can't leave a half-applied
                # schema. (_split_sql strips in-file BEGIN/COMMIT, so the runner
                # owns the transaction boundary here.)
                try:
                    for stmt in _split_sql(f.read_text()):
                        conn.execute(stmt)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                        (version, datetime.now(UTC).isoformat()),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise
        finally:
            conn.close()
