"""Operator-confirm quarantine for the DNSSEC first-trust ladder (Rev 6 I9/§9).

DB layer over ``pending_first_trust`` (migration 055). Operator-confirm is the
SOLE non-DNSSEC first-trust fallback (Rev 6 §2/§15.1): when the ladder cannot
root an unknown origin via an operator-pin or a DNSSEC binding, the candidate
binding is parked here for an explicit human action (paste/confirm the
fingerprint out-of-band, never one-click). Because it is the only fallback for
the entire non-DNSSEC long tail, the queue MUST be bounded so an untrusted relay
cannot flood it (I9 / NF-R5C-4):

  * ``quarantine`` parks/refreshes a row keyed by ``(entity_uri, node_id)``,
    enforcing a per-``relay_peer`` insert cap (a NEW row from a peer already
    at/over the cap is rejected + audited; a REFRESH of an existing row is always
    allowed so a legitimate re-observation is never starved).
  * ``evict_expired`` deletes rows older than the TTL by ``seen_at``.

``list_pending`` / ``get_pending`` / ``remove_pending`` are the read/delete layer
the operator-confirm CLI + admin API (next batch) will call. This module builds
NO routes and is not wired into the resolver yet (off-path). It imports
``settings`` for the cap/TTL defaults and ``emit_nofail`` function-locally for
the flood audit; no DNSSEC / ``dnspython`` import is reachable from it (I11). All
helpers take an open connection and participate in its transaction; the caller
owns commit/rollback.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

# The operator-facing columns surfaced by get_pending/list_pending (the API/CLI
# render exactly these). Kept in one place so the row-dict shape is consistent.
_ROW_COLUMNS = (
    "entity_uri",
    "node_id",
    "candidate_key_fpr",
    "source",
    "relay_peer",
    "seen_at",
)
# Pre-built SELECT strings. The column list is the hardcoded tuple above (never
# user input), so interpolating it is safe — the nosec annotations mark the two
# f-strings bandit flags (B608) as constant-only, not injectable.
_ROW_COLUMNS_SQL = ", ".join(_ROW_COLUMNS)
_SELECT_ALL_SQL = (
    f"SELECT {_ROW_COLUMNS_SQL} FROM pending_first_trust ORDER BY seen_at DESC"  # noqa: S608  # nosec B608
)
_SELECT_ONE_SQL = (
    f"SELECT {_ROW_COLUMNS_SQL} FROM pending_first_trust WHERE entity_uri=? AND node_id=?"  # noqa: S608  # nosec B608
)

# Sentinel so callers can pass cap=None / ttl=None meaning "use the setting".
_UNSET = object()


def _row_to_dict(row: Any) -> dict[str, Any]:
    return dict(zip(_ROW_COLUMNS, row, strict=True))


def _peer_pending_count(conn: Any, relay_peer: str | None) -> int:
    """Number of currently-parked rows attributed to ``relay_peer``."""
    if relay_peer is None:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_first_trust WHERE relay_peer IS NULL"
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) FROM pending_first_trust WHERE relay_peer=?", (relay_peer,)
        ).fetchone()
    return int(row[0])


def _audit_cap_exceeded(entity_uri: str, node_id: str, relay_peer: str | None) -> None:
    """Best-effort flood-signal audit (never blocks the caller)."""
    from ...observability.audit_event import emit_nofail

    emit_nofail(
        "federation_dnssec_pending_first_trust_cap_exceeded",
        entity_uri=entity_uri,
        source="federation_relay",
        detail={
            "entity_uri": entity_uri,
            "node_id": node_id,
            "relay_peer": relay_peer,
        },
    )


def quarantine(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
    candidate_key_fpr: str,
    source: str,
    relay_peer: str | None,
    now: datetime,
    cap: Any = _UNSET,
) -> bool:
    """Park (or refresh) a candidate binding in ``pending_first_trust`` (I9).

    Returns True if the row is now parked (inserted or refreshed), False if a NEW
    insert was rejected because ``relay_peer`` is already at/over ``cap`` (an
    audit event is emitted naming the peer).

    * If a row already exists for ``(entity_uri, node_id)`` it is REFRESHED in
      place (candidate_key_fpr / source / relay_peer / seen_at) regardless of the
      cap — refreshing adds no row, so it cannot contribute to a flood.
    * Otherwise a NEW row is inserted only if ``relay_peer`` has fewer than
      ``cap`` parked rows; at/over the cap the insert is rejected + audited.

    ``cap`` defaults to ``settings.federation_dnssec_pending_confirm_cap`` when
    left unset. The caller owns the transaction.
    """
    if cap is _UNSET:
        from ...settings import settings

        cap = settings.federation_dnssec_pending_confirm_cap

    seen_at = now.isoformat()

    existing = conn.execute(
        "SELECT entity_uri FROM pending_first_trust WHERE entity_uri=? AND node_id=?",
        (entity_uri, node_id),
    ).fetchone()

    if existing is not None:
        # Refresh in place — never counts against the cap.
        conn.execute(
            "UPDATE pending_first_trust "
            "SET candidate_key_fpr=?, source=?, relay_peer=?, seen_at=? "
            "WHERE entity_uri=? AND node_id=?",
            (candidate_key_fpr, source, relay_peer, seen_at, entity_uri, node_id),
        )
        return True

    if _peer_pending_count(conn, relay_peer) >= cap:
        # Flood bound hit: refuse the NEW row and surface the signal to the
        # operator. Distinct event so it is not confused with an ordinary
        # unknown-origin confirm.
        _audit_cap_exceeded(entity_uri, node_id, relay_peer)
        return False

    conn.execute(
        "INSERT INTO pending_first_trust "
        "(entity_uri, node_id, candidate_key_fpr, source, relay_peer, seen_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entity_uri, node_id, candidate_key_fpr, source, relay_peer, seen_at),
    )
    return True


def evict_expired(conn: Any, *, now: datetime, ttl: Any = _UNSET) -> int:
    """Delete unconfirmed rows older than ``ttl`` seconds by ``seen_at`` (I9).

    A row is expired when ``seen_at < now - ttl`` (strict, so a row exactly at
    the TTL boundary is kept). Returns the number of rows removed. ``ttl``
    defaults to ``settings.federation_dnssec_pending_confirm_ttl`` when unset. The
    caller owns the transaction.
    """
    if ttl is _UNSET:
        from ...settings import settings

        ttl = settings.federation_dnssec_pending_confirm_ttl

    cutoff = (now - timedelta(seconds=ttl)).isoformat()
    cur = conn.execute(
        "DELETE FROM pending_first_trust WHERE seen_at < ?", (cutoff,)
    )
    return int(cur.rowcount)


def list_pending(conn: Any) -> list[dict[str, Any]]:
    """Return every parked binding (the operator-confirm queue), newest first."""
    rows = conn.execute(_SELECT_ALL_SQL).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_pending(conn: Any, entity_uri: str, node_id: str) -> dict[str, Any] | None:
    """Return the parked binding for ``(entity_uri, node_id)``, or None."""
    row = conn.execute(_SELECT_ONE_SQL, (entity_uri, node_id)).fetchone()
    return _row_to_dict(row) if row is not None else None


def remove_pending(conn: Any, entity_uri: str, node_id: str) -> bool:
    """Delete the parked binding for ``(entity_uri, node_id)``.

    Returns True if a row was removed (the operator confirmed or rejected it),
    False if there was nothing to remove. The caller owns the transaction.
    """
    cur = conn.execute(
        "DELETE FROM pending_first_trust WHERE entity_uri=? AND node_id=?",
        (entity_uri, node_id),
    )
    return int(cur.rowcount) > 0
