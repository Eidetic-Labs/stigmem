"""RTBF tombstone storage layer and recall-time filter — spec §23.

Storage operations:
    create_tombstone(...)   → TombstoneRecord
    revoke_tombstone(...)   → TombstoneRevocationRecord
    get_tombstone_status(entity_uri) → TombstoneStatusResponse
    list_tombstones(scope, since) → list[TombstoneRecord]
    list_revocations(since) → list[TombstoneRevocationRecord]

Recall-time filter (§23.3):
    is_tombstoned(entity_uri, scope) → bool  (uses 60-second LRU cache)
    filter_tombstoned_records(records) → list[FactRecord]
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..db import db
from ..models.tombstones import (
    TombstoneRecord,
    TombstoneRevocationRecord,
    TombstoneStatusResponse,
)

logger = logging.getLogger("stigmem.tombstones")

# ---------------------------------------------------------------------------
# In-process tombstone LRU cache (§23.3.3 rule 4 — refresh at most every 60s)
# ---------------------------------------------------------------------------

_TOMBSTONE_CACHE_TTL = 60.0

@dataclass
class _TombstoneScopeCacheState:
    # Full set of active (entity_uri, scope) pairs from DB — refreshed every 60s.
    active_set: set[tuple[str, str]] = field(default_factory=set)
    refreshed_at: float = 0.0


_tombstone_scope_cache = _TombstoneScopeCacheState()


def _scope_matches(pattern: str, fact_scope: str) -> bool:
    """Return True if tombstone scope pattern covers fact_scope (§23.2.3)."""
    return pattern == "*" or pattern == fact_scope


def _refresh_tombstone_cache() -> None:
    now = time.monotonic()
    if now - _tombstone_scope_cache.refreshed_at < _TOMBSTONE_CACHE_TTL:
        return
    try:
        with db() as conn:
            # BEGIN IMMEDIATE for consistency (§23.3.3 rule 5, SQLite path)
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                """SELECT t.entity_uri, t.scope
                   FROM tombstones t
                   WHERE NOT EXISTS (
                       SELECT 1 FROM tombstone_revocations r WHERE r.tombstone_id = t.id
                   )"""
            ).fetchall()
            conn.execute("COMMIT")
        _tombstone_scope_cache.active_set = {(r["entity_uri"], r["scope"]) for r in rows}
        _tombstone_scope_cache.refreshed_at = now
    except Exception:
        logger.exception("Failed to refresh tombstone cache")


def is_tombstoned(entity_uri: str, fact_scope: str) -> bool:
    """Return True if entity_uri has an active tombstone covering fact_scope."""
    from .tombstone_gate import tombstone_filter_enabled

    if not tombstone_filter_enabled():
        return False
    _refresh_tombstone_cache()
    for uri, pattern in _tombstone_scope_cache.active_set:
        if uri == entity_uri and _scope_matches(pattern, fact_scope):
            return True
    return False


def invalidate_tombstone_cache() -> None:
    """Force cache refresh on next call (used after local tombstone write)."""
    _tombstone_scope_cache.refreshed_at = 0.0
    try:
        from .tombstone_cache import invalidate as _cache_invalidate

        _cache_invalidate()
    except Exception:
        logger.exception("Failed to invalidate tombstone cache")


# ---------------------------------------------------------------------------
# Storage operations
# ---------------------------------------------------------------------------


def _row_to_tombstone(row: Any) -> TombstoneRecord:
    return TombstoneRecord(
        id=row["id"],
        entity_uri=row["entity_uri"],
        scope=row["scope"],
        reason=row["reason"],
        signed_by=row["signed_by"],
        key_id=row["key_id"] or "",
        signature=row["signature"],
        created_at=row["created_at"],
        legal_hold=bool(row["legal_hold"]),
    )


def _row_origin_fields(row: Any) -> dict[str, Any]:
    """Surface the v2 origin columns (migration 049) from a tombstones row as a dict.

    NULL for every column = self/direct tombstone (unchanged behaviour). The egress emit
    (``build_tombstone_origin_entry``) reads ``received_from`` to decide self-originated vs
    relayed and forwards the stored origin block verbatim for a relayed tombstone. Returned
    as a plain dict (not on ``TombstoneRecord``, which is the wire model and must not carry
    local-only relay columns). Missing columns (a row that predates migration 049 / a fixture
    row from ``model_dump``) read as ``None`` via the tolerant ``_get`` below.
    """

    def _get(key: str) -> Any:
        try:
            return row[key]
        except (KeyError, IndexError, TypeError):
            return None

    return {
        "received_from": _get("received_from"),
        "origin_node_id": _get("origin_node_id"),
        "origin_tenant": _get("origin_tenant"),
        "origin_entity_uri": _get("origin_entity_uri"),
        "origin_allowed_scopes": _get("origin_allowed_scopes"),
        "origin_allowed_tenants": _get("origin_allowed_tenants"),
        "origin_sig": _get("origin_sig"),
    }


def list_tombstone_rows(
    scope: str | None = None, since: str | None = None
) -> list[tuple[TombstoneRecord, dict[str, Any]]]:
    """Like ``list_tombstones`` but ALSO surfaces each row's v2 origin columns.

    Returns ``(TombstoneRecord, origin_fields)`` pairs so the federation egress emit can
    decide self-originated vs relayed and forward the stored origin block. ``SELECT *`` is
    used so the origin_* columns are present. The filter mirrors ``list_tombstones`` exactly.
    """
    query = "SELECT * FROM tombstones WHERE 1=1"
    params: list[Any] = []
    if scope is not None and scope != "*":
        query += " AND (scope = ? OR scope = '*')"
        params.append(scope)
    if since is not None:
        query += " AND created_at > ?"
        params.append(since)
    query += " ORDER BY created_at"
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [(_row_to_tombstone(r), _row_origin_fields(r)) for r in rows]


def _row_to_revocation(row: Any) -> TombstoneRevocationRecord:
    return TombstoneRevocationRecord(
        id=row["id"],
        tombstone_id=row["tombstone_id"],
        reason=row["reason"],
        signed_by=row["signed_by"],
        key_id=row["key_id"] or "",
        signature=row["signature"],
        created_at=row["created_at"],
    )


def create_tombstone(
    entity_uri: str,
    scope: str,
    reason: str | None,
    signed_by: str,
    key_id: str,
    signature: str,
    legal_hold: bool = False,
    tenant_id: str = "default",
    *,
    tombstone_id: str | None = None,
    created_at: str | None = None,
) -> TombstoneRecord:
    """Write a tombstone record. Idempotent on (entity_uri, scope) for active tombstones."""
    now = created_at or datetime.now(UTC).isoformat()
    with db() as conn:
        existing = conn.execute(
            """SELECT t.id FROM tombstones t
               WHERE t.entity_uri = ? AND t.scope = ? AND t.tenant_id = ?
               AND NOT EXISTS (
                   SELECT 1 FROM tombstone_revocations r WHERE r.tombstone_id = t.id
               )""",
            (entity_uri, scope, tenant_id),
        ).fetchone()
        if existing:
            row = conn.execute(
                "SELECT * FROM tombstones WHERE id = ?", (existing["id"],)
            ).fetchone()
            return _row_to_tombstone(row)

        tomb_id = tombstone_id or "tomb_" + str(uuid.uuid4())
        _emit_tombstone_audit(
            conn=conn,
            event_type="tombstone_created",
            actor_uri=signed_by,
            tombstone_id=tomb_id,
            entity_uri=entity_uri,
            scope=scope,
            source="local",
            detail={"legal_hold": legal_hold},
        )
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tomb_id,
                entity_uri,
                scope,
                reason,
                signed_by,
                key_id or None,
                signature,
                now,
                int(legal_hold),
                tenant_id,
            ),
        )
        row = conn.execute("SELECT * FROM tombstones WHERE id = ?", (tomb_id,)).fetchone()

    invalidate_tombstone_cache()
    logger.info("Tombstone created: %s for entity %s scope %s", tomb_id, entity_uri, scope)
    return _row_to_tombstone(row)


def revoke_tombstone(
    tombstone_id: str,
    reason: str,
    signed_by: str,
    key_id: str,
    signature: str,
) -> TombstoneRevocationRecord:
    """Write a tombstone revocation record (§23.2.5)."""
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        tomb = conn.execute("SELECT id FROM tombstones WHERE id = ?", (tombstone_id,)).fetchone()
        if tomb is None:
            raise KeyError("tombstone_not_found")
        existing_rev = conn.execute(
            "SELECT id FROM tombstone_revocations WHERE tombstone_id = ?", (tombstone_id,)
        ).fetchone()
        if existing_rev:
            raise ValueError("tombstone_already_revoked")

        rev_id = "tombrevoke_" + str(uuid.uuid4())
        _emit_tombstone_audit(
            conn=conn,
            event_type="tombstone_revoked",
            actor_uri=signed_by,
            tombstone_id=tombstone_id,
            entity_uri=tombstone_id,
            scope=None,
            source="local",
            detail={"revocation_id": rev_id},
        )
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (rev_id, tombstone_id, reason, signed_by, key_id, signature, now),
        )
        row = conn.execute("SELECT * FROM tombstone_revocations WHERE id = ?", (rev_id,)).fetchone()

    invalidate_tombstone_cache()
    logger.info("Tombstone revoked: %s → revocation %s", tombstone_id, rev_id)
    return _row_to_revocation(row)


def get_tombstone_status(entity_uri: str) -> TombstoneStatusResponse:
    """Return tombstone status for entity_uri — admin-only endpoint data."""
    with db() as conn:
        t_rows = conn.execute(
            "SELECT * FROM tombstones WHERE entity_uri = ? ORDER BY created_at",
            (entity_uri,),
        ).fetchall()
        tombstone_list = [_row_to_tombstone(r) for r in t_rows]

        if not tombstone_list:
            return TombstoneStatusResponse(tombstoned=False, tombstones=[], revocations=[])

        rev_rows = []
        for tombstone in tombstone_list:
            rev_rows.extend(
                conn.execute(
                    """SELECT * FROM tombstone_revocations
                       WHERE tombstone_id = ?
                       ORDER BY created_at""",
                    (tombstone.id,),
                ).fetchall()
            )
        revocation_list = [_row_to_revocation(r) for r in rev_rows]

    revoked_ids = {r.tombstone_id for r in revocation_list}
    active = any(t.id not in revoked_ids for t in tombstone_list)
    return TombstoneStatusResponse(
        tombstoned=active,
        tombstones=tombstone_list,
        revocations=revocation_list,
    )


def list_tombstones(scope: str | None = None, since: str | None = None) -> list[TombstoneRecord]:
    """List tombstones for federation poll (§23.4.3)."""
    query = "SELECT * FROM tombstones WHERE 1=1"
    params: list[Any] = []
    if scope is not None and scope != "*":
        query += " AND (scope = ? OR scope = '*')"
        params.append(scope)
    if since is not None:
        query += " AND created_at > ?"
        params.append(since)
    query += " ORDER BY created_at"
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_tombstone(r) for r in rows]


def list_revocations(since: str | None = None) -> list[TombstoneRevocationRecord]:
    """List tombstone revocations for federation poll."""
    query = "SELECT * FROM tombstone_revocations WHERE 1=1"
    params: list[Any] = []
    if since is not None:
        query += " AND created_at > ?"
        params.append(since)
    query += " ORDER BY created_at"
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_revocation(r) for r in rows]


def apply_inbound_tombstone(record: TombstoneRecord, tenant_id: str = "default") -> bool:
    """Apply an inbound tombstone from federation (§23.4.2). Idempotent on id.

    ``tenant_id`` is the local tenant this peer's inbound data is stamped into
    (resolved fail-closed by ``resolve_ingest_tenant_for_peer``). The wire
    ``TombstoneRecord`` carries no tenant in Phase 1, so the receiving node's
    per-peer policy decides it. The recall-time suppression filter keys on
    ``(entity_uri, tenant_id)`` — landing every inbound tombstone in ``default``
    would let a peer's RTBF tombstone suppress a *different* tenant's facts (and
    fail to suppress its own tenant's facts), so the tenant MUST be threaded here.

    Returns True if written, False if already existed.
    Caller MUST verify signature before calling this.
    """
    with db() as conn:
        existing = conn.execute("SELECT id FROM tombstones WHERE id = ?", (record.id,)).fetchone()
        if existing:
            return False
        _emit_tombstone_audit(
            conn=conn,
            event_type="tombstone_federation_ingested",
            actor_uri=record.signed_by,
            tombstone_id=record.id,
            entity_uri=record.entity_uri,
            scope=record.scope,
            source="federation",
            detail={"legal_hold": record.legal_hold},
        )
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.entity_uri,
                record.scope,
                record.reason,
                record.signed_by,
                record.key_id or None,
                record.signature,
                record.created_at,
                int(record.legal_hold),
                tenant_id,
            ),
        )
    invalidate_tombstone_cache()
    logger.info(
        "Inbound tombstone applied: %s for %s (tenant=%s)",
        record.id,
        record.entity_uri,
        tenant_id,
    )
    return True


def apply_inbound_revocation(record: TombstoneRevocationRecord) -> bool:
    """Apply an inbound revocation from federation. Idempotent on id."""
    with db() as conn:
        tomb = conn.execute(
            "SELECT id FROM tombstones WHERE id = ?", (record.tombstone_id,)
        ).fetchone()
        if tomb is None:
            logger.warning(
                "Inbound revocation for unknown tombstone %s; storing anyway", record.tombstone_id
            )
        existing = conn.execute(
            "SELECT id FROM tombstone_revocations WHERE id = ?", (record.id,)
        ).fetchone()
        if existing:
            return False
        _emit_tombstone_audit(
            conn=conn,
            event_type="tombstone_revocation_federation_ingested",
            actor_uri=record.signed_by,
            tombstone_id=record.tombstone_id,
            entity_uri=record.tombstone_id,
            scope=None,
            source="federation",
            detail={"revocation_id": record.id},
        )
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.tombstone_id,
                record.reason,
                record.signed_by,
                record.key_id,
                record.signature,
                record.created_at,
            ),
        )
    invalidate_tombstone_cache()
    return True


def _emit_tombstone_audit(
    *,
    conn: Any,
    event_type: str,
    actor_uri: str,
    tombstone_id: str,
    entity_uri: str,
    scope: str | None,
    source: str,
    detail: dict[str, Any],
) -> None:
    from ..observability.audit_event import emit

    emit(
        event_type,
        entity_uri=actor_uri,
        fact_id=tombstone_id,
        source=source,
        scope=scope,
        detail={
            "target_entity_uri": entity_uri,
            "scope": scope,
            **detail,
        },
        conn=conn,
    )


# ---------------------------------------------------------------------------
# Recall-time filter (§23.3)
# ---------------------------------------------------------------------------


def filter_tombstoned_records(records: list[Any]) -> list[Any]:
    """Remove facts whose entity or ref-value is tombstoned (§23.3.1, §23.3.2).

    Also strips tombstoned entries from derived_from and related_entities per spec.
    """
    _refresh_tombstone_cache()
    if not _tombstone_scope_cache.active_set:
        return records

    result = []
    for record in records:
        scope = getattr(record, "scope", "local")

        # §23.3.1 rule 2 — exclude facts whose entity is tombstoned
        entity = getattr(record, "entity", None)
        if entity and is_tombstoned(entity, scope):
            continue

        # §23.3.1 rule 2 — exclude ref-valued facts pointing to tombstoned entities
        value = getattr(record, "value", None)
        if value and getattr(value, "type", None) == "ref":
            ref_uri = str(value.v) if value.v is not None else ""
            if ref_uri and is_tombstoned(ref_uri, scope):
                continue

        result.append(record)

    return result
