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


def _json_token(value: str) -> str:
    """Return the canonical JSON-quoted token for *value* (``foo`` → ``"foo"``).

    Mirrors ``routes.federation.replication._json_token`` (W2.3). Stored
    ``origin_allowed_scopes`` / ``origin_allowed_tenants`` are ``json.dumps(sorted([...]))``
    TEXT, so each element appears verbatim as a JSON string literal; searching for the
    quoted token makes a ``LIKE '%…%'`` membership test exact (the surrounding quotes
    prevent a prefix/substring false match). Postgres-safe: a portable ``LIKE`` against the
    canonical text, NO ``json_each``.
    """
    import json as _json

    return _json.dumps(value)


def list_federatable_tombstones(
    *,
    peer: dict[str, Any] | None,
    relay_enabled: bool,
    since: str | None = None,
    limit: int,
) -> tuple[list[tuple[TombstoneRecord, dict[str, Any]]], bool]:
    """Federation-egress variant of ``list_tombstone_rows`` with the W6.6 relay gate.

    Mirrors the FACT egress gate (``replication.pull_facts`` W2.3): a RELAYED tombstone
    (``received_from IS NOT NULL``) may only re-federate to THIS peer when the origin's
    signed grant permits it, enforced ENTIRELY in SQL so ``LIMIT`` applies post-filter (no
    Python post-filtering → no short pages / skipped cursor). The egress WHERE is:

    * relay OFF → ``received_from IS NULL`` (Phase-1 identical; byte-for-byte the self-only
      set the admin path always returned).
    * relay ON →
      ``received_from IS NULL OR (received_from IS NOT NULL AND <scope_in_origin>
        AND (<tenant_overlap>))`` where
        - ``<scope_in_origin>`` = the tombstone's ``scope`` column is a member of its
          stored ``origin_allowed_scopes`` JSON — the portable ``LIKE '%"' || scope || '"%'``
          column-concat technique (no param, PG-safe).
        - ``<tenant_overlap>`` = ``origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅`` — an
          OR-of-LIKE over the peer's known tenant set, each bound as ``json.dumps(tenant)``.
      A peer authorised for no tenant (or no resolvable peer row) ⇒ relay can never apply ⇒
      self-only (fail-closed).

    Returns ``(rows, has_more)`` where ``rows`` is at most ``limit`` ``(TombstoneRecord,
    origin_fields)`` pairs (``has_more`` is computed by over-reading one row, mirroring the
    fact pull route). The admin ``list_tombstones`` / ``list_tombstone_rows`` paths are
    untouched.
    """
    from ..routes.federation.common import _allowed_output_tenants  # noqa: PLC0415

    relay_clause: str
    relay_params: list[Any] = []
    if relay_enabled and peer is not None:
        peer_tenants = _allowed_output_tenants(peer)
        if peer_tenants:
            # scope ∈ origin_allowed_scopes: ``scope`` is a COLUMN (not a bind value), so the
            # JSON quotes are added in SQL via ``||`` concat (portable: SQLite + Postgres). No
            # param. The stored grant is the canonical sorted-JSON text, so the scope appears
            # verbatim as ``"scope"``.
            scope_in_origin = "origin_allowed_scopes LIKE '%\"' || scope || '\"%'"
            # origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅: OR over the peer's known
            # tenant set (sorted for deterministic SQL + param order). Each tenant is bound
            # as the json-quoted token ``"tenant"`` so the LIKE match is exact.
            tenant_overlap = " OR ".join(
                "origin_allowed_tenants LIKE '%' || ? || '%'" for _ in peer_tenants
            )
            relay_clause = (
                "(received_from IS NULL"
                f" OR (received_from IS NOT NULL AND {scope_in_origin}"
                f" AND ({tenant_overlap})))"
            )
            # Params, in the EXACT order their ? appears in relay_clause: one per peer tenant
            # for tenant_overlap (sorted to match the clause order). scope_in_origin carries
            # NO param (column-only concat).
            relay_params.extend(_json_token(t) for t in sorted(peer_tenants))
        else:
            relay_clause = "received_from IS NULL"
    else:
        relay_clause = "received_from IS NULL"  # do not re-federate inbound tombstones

    query = f"SELECT * FROM tombstones WHERE {relay_clause}"  # noqa: S608  # nosec B608 — clause is a literal fragment; values in params
    params: list[Any] = list(relay_params)
    if since is not None:
        query += " AND created_at > ?"
        params.append(since)
    query += " ORDER BY created_at LIMIT ?"
    params.append(limit + 1)
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return [(_row_to_tombstone(r), _row_origin_fields(r)) for r in rows], has_more


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


def _revocation_origin_fields(row: Any) -> dict[str, Any]:
    """Surface the v2 origin columns (migration 050) from a tombstone_revocations row.

    Mirrors ``_row_origin_fields`` for tombstones. NULL for every column = self/direct
    revocation (unchanged behaviour). The egress emit (``build_revocation_origin_entry``)
    reads ``received_from`` to decide self-originated vs relayed and forwards the stored
    origin block verbatim for a relayed revocation. Returned as a plain dict (not on
    ``TombstoneRevocationRecord``, which is the wire model and must not carry local-only
    relay columns). Missing columns (a row that predates migration 050 / a fixture row
    from ``model_dump``) read as ``None`` via the tolerant ``_get`` below.
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


def list_federatable_revocations(
    *,
    peer: dict[str, Any] | None,
    relay_enabled: bool,
    since: str | None = None,
    limit: int,
) -> tuple[list[tuple[TombstoneRevocationRecord, dict[str, Any]]], bool]:
    """Federation-egress variant of ``list_revocations`` with the Rev-2 relay gate.

    Mirrors ``list_federatable_tombstones`` (W6.6) but the gate is TENANT-ONLY: a
    revocation references a tombstone by id and has NO scope of its own, so there is no
    scope-membership clause — only ``origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅``.
    Enforced ENTIRELY in SQL so ``LIMIT`` applies post-filter (no Python post-filtering →
    no short pages / skipped cursor). The egress WHERE is:

    * relay OFF → ``received_from IS NULL`` (self-only; byte-for-byte the self-only set).
    * relay ON →
      ``received_from IS NULL OR (received_from IS NOT NULL AND <tenant_overlap>)`` where
        - ``<tenant_overlap>`` = an OR-of-LIKE over the peer's known tenant set, each bound
          as ``json.dumps(tenant)``.
      A peer authorised for no tenant (or no resolvable peer row) ⇒ relay can never apply ⇒
      self-only (fail-closed).

    Returns ``(rows, has_more)`` where ``rows`` is at most ``limit``
    ``(TombstoneRevocationRecord, origin_fields)`` pairs. The admin ``list_revocations``
    path is untouched.
    """
    from ..routes.federation.common import _allowed_output_tenants  # noqa: PLC0415

    relay_clause: str
    relay_params: list[Any] = []
    if relay_enabled and peer is not None:
        peer_tenants = _allowed_output_tenants(peer)
        if peer_tenants:
            # origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅: OR over the peer's known
            # tenant set (sorted for deterministic SQL + param order). Each tenant is bound
            # as the json-quoted token ``"tenant"`` so the LIKE match is exact. NO scope
            # clause — a revocation has no scope of its own (tenant-only gate, Rev-2).
            tenant_overlap = " OR ".join(
                "origin_allowed_tenants LIKE '%' || ? || '%'" for _ in peer_tenants
            )
            relay_clause = (
                "(received_from IS NULL"
                f" OR (received_from IS NOT NULL AND ({tenant_overlap})))"
            )
            relay_params.extend(_json_token(t) for t in sorted(peer_tenants))
        else:
            relay_clause = "received_from IS NULL"
    else:
        relay_clause = "received_from IS NULL"  # do not re-federate inbound revocations

    query = f"SELECT * FROM tombstone_revocations WHERE {relay_clause}"  # noqa: S608  # nosec B608 — clause is a literal fragment; values in params
    params: list[Any] = list(relay_params)
    if since is not None:
        query += " AND created_at > ?"
        params.append(since)
    query += " ORDER BY created_at LIMIT ?"
    params.append(limit + 1)
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return [(_row_to_revocation(r), _revocation_origin_fields(r)) for r in rows], has_more


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


def apply_inbound_tombstone(
    record: TombstoneRecord,
    tenant_id: str = "default",
    *,
    origin_node_id: str | None = None,
    origin_tenant: str | None = None,
    origin_entity_uri: str | None = None,
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
    origin_sig: str | None = None,
    received_from: str | None = None,
) -> bool:
    """Apply an inbound tombstone from federation (§23.4.2). Idempotent on id.

    ``tenant_id`` is the local tenant this peer's inbound data is stamped into
    (resolved fail-closed by ``resolve_ingest_tenant_for_peer``). The wire
    ``TombstoneRecord`` carries no tenant in Phase 1, so the receiving node's
    per-peer policy decides it. The recall-time suppression filter keys on
    ``(entity_uri, tenant_id)`` — landing every inbound tombstone in ``default``
    would let a peer's RTBF tombstone suppress a *different* tenant's facts (and
    fail to suppress its own tenant's facts), so the tenant MUST be threaded here.

    The optional ``origin_*`` + ``received_from`` kwargs persist the verified v2
    origin block (migration 049 columns) for a RELAYED tombstone (Phase 2c W6.7),
    mirroring ``ingest_fact``'s origin persistence. The egress relay gate
    (``list_federatable_tombstones``, W6.6) reads these columns to decide whether
    this node may re-federate the tombstone onward, and ``build_tombstone_origin_entry``
    forwards the stored origin block + signature verbatim. ALL default None ⇒ a
    self/direct tombstone (every origin column stays NULL — unchanged W6.5 behaviour).
    ``origin_allowed_scopes`` / ``origin_allowed_tenants`` are stored as
    ``json.dumps(sorted([...]))`` TEXT, the SAME canonical encoding the fact ingest
    path uses, so the egress LIKE-membership gate matches exactly.

    Returns True if written, False if already existed.
    Caller MUST verify signature before calling this.
    """
    import json as _json

    scopes_json = (
        _json.dumps(sorted(origin_allowed_scopes)) if origin_allowed_scopes is not None else None
    )
    tenants_json = (
        _json.dumps(sorted(origin_allowed_tenants))
        if origin_allowed_tenants is not None
        else None
    )
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
                created_at, legal_hold, tenant_id,
                received_from, origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                received_from,
                origin_node_id,
                origin_tenant,
                origin_entity_uri,
                scopes_json,
                tenants_json,
                origin_sig,
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


def apply_inbound_revocation(
    record: TombstoneRevocationRecord,
    *,
    origin_node_id: str | None = None,
    origin_tenant: str | None = None,
    origin_entity_uri: str | None = None,
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
    origin_sig: str | None = None,
    received_from: str | None = None,
) -> bool:
    """Apply an inbound revocation from federation. Idempotent on id.

    The optional ``origin_*`` + ``received_from`` kwargs persist the verified v2 origin
    block (migration 050 columns) for a RELAYED revocation (Phase 2c Rev-3), mirroring
    ``apply_inbound_tombstone``'s origin persistence (W6.7). The egress relay gate
    (``list_federatable_revocations``, Rev-2) reads these columns to decide whether this
    node may re-federate the revocation onward, and the emit path forwards the stored
    origin block + signature verbatim. ALL default None ⇒ a self/direct revocation (every
    origin column stays NULL — unchanged Rev-2 behaviour). ``origin_allowed_scopes`` /
    ``origin_allowed_tenants`` are stored as ``json.dumps(sorted([...]))`` TEXT, the SAME
    canonical encoding the fact/tombstone ingest paths use, so the egress LIKE-membership
    gate matches exactly.

    Caller MUST verify both signatures before calling this for a relayed revocation.
    """
    import json as _json

    scopes_json = (
        _json.dumps(sorted(origin_allowed_scopes)) if origin_allowed_scopes is not None else None
    )
    tenants_json = (
        _json.dumps(sorted(origin_allowed_tenants))
        if origin_allowed_tenants is not None
        else None
    )
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
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at,
                received_from, origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.tombstone_id,
                record.reason,
                record.signed_by,
                record.key_id,
                record.signature,
                record.created_at,
                received_from,
                origin_node_id,
                origin_tenant,
                origin_entity_uri,
                scopes_json,
                tenants_json,
                origin_sig,
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
