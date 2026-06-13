"""Per-session read/write graph controls for R-21 feedback-loop defense."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status

from .auth import Identity

SESSION_HEADER = "Stigmem-Session"
SUMMARIZE_WITH_PROVENANCE = "summarize_with_provenance"


def normalize_session_id(session_id: str | None) -> str | None:
    """Return a bounded session id, or None when the caller did not opt in."""
    if session_id is None:
        return None
    normalized = session_id.strip()
    if not normalized:
        return None
    if len(normalized) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="session_id_too_long",
        )
    return normalized


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def record_read_scopes(
    conn: Any,
    *,
    identity: Identity,
    session_id: str | None,
    scopes: set[str],
) -> None:
    """Record scopes read by a caller in a session."""
    normalized = normalize_session_id(session_id)
    if normalized is None:
        return
    now = _now_iso()
    for scope in scopes:
        conn.execute(
            """INSERT OR IGNORE INTO session_scope_access
               (id, session_id, entity_uri, tenant_id, scope, access_type, ts)
               VALUES (?, ?, ?, ?, ?, 'read', ?)""",
            (
                str(uuid.uuid4()),
                normalized,
                identity.entity_uri,
                identity.tenant_id,
                scope,
                now,
            ),
        )


def record_write_scope(
    conn: Any,
    *,
    identity: Identity,
    session_id: str | None,
    scope: str,
) -> None:
    """Record a scope written by a caller in a session."""
    normalized = normalize_session_id(session_id)
    if normalized is None:
        return
    conn.execute(
        """INSERT OR IGNORE INTO session_scope_access
           (id, session_id, entity_uri, tenant_id, scope, access_type, ts)
           VALUES (?, ?, ?, ?, ?, 'write', ?)""",
        (
            str(uuid.uuid4()),
            normalized,
            identity.entity_uri,
            identity.tenant_id,
            scope,
            _now_iso(),
        ),
    )


def _read_scopes_for_session(conn: Any, *, identity: Identity, session_id: str) -> set[str]:
    rows = conn.execute(
        """SELECT scope FROM session_scope_access
           WHERE session_id = ?
             AND entity_uri = ?
             AND tenant_id = ?
             AND access_type = 'read'""",
        (session_id, identity.entity_uri, identity.tenant_id),
    ).fetchall()
    return {row["scope"] for row in rows}


def _provenance_scopes(
    conn: Any, derived_from: list[dict[str, Any]], tenant_id: str
) -> set[str]:
    scopes: set[str] = set()
    for entry in derived_from:
        fact_id = entry.get("fact_id")
        hash_val = entry.get("hash")
        row = None
        if fact_id:
            row = conn.execute(
                "SELECT scope FROM facts WHERE id = ? AND tenant_id = ?",
                (fact_id, tenant_id),
            ).fetchone()
        elif isinstance(hash_val, str) and hash_val.startswith("sha256:"):
            alias = conn.execute(
                "SELECT fact_id FROM fact_cid_aliases WHERE cid = ? AND tenant_id = ?",
                (hash_val, tenant_id),
            ).fetchone()
            if alias is not None:
                row = conn.execute(
                    "SELECT scope FROM facts WHERE id = ? AND tenant_id = ?",
                    (alias["fact_id"], tenant_id),
                ).fetchone()
        if row is not None:
            scopes.add(row["scope"])
    return scopes


def ensure_write_allowed(
    conn: Any,
    *,
    identity: Identity,
    session_id: str | None,
    target_scope: str,
    write_mode: str,
    derived_from: list[dict[str, Any]],
) -> None:
    """Reject read-then-write same-scope loops unless provenance is carried forward."""
    normalized = normalize_session_id(session_id)
    if normalized is None:
        return

    read_scopes = _read_scopes_for_session(conn, identity=identity, session_id=normalized)
    if target_scope not in read_scopes:
        return

    if write_mode == SUMMARIZE_WITH_PROVENANCE and target_scope in _provenance_scopes(
        conn, derived_from, identity.tenant_id
    ):
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "code": "feedback_loop_provenance_required",
            "message": (
                "writes into scopes read earlier in the same session require "
                "write_mode='summarize_with_provenance' and source provenance"
            ),
            "session_id": normalized,
            "scope": target_scope,
        },
    )


def encode_derived_from(derived_from: list[dict[str, Any]]) -> str | None:
    if not derived_from:
        return None
    return json.dumps(derived_from, sort_keys=True, separators=(",", ":"))
