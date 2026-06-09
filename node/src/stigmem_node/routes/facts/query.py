"""GET /v1/facts query route and query helpers."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Query, Response, status

from ... import settings as _settings_pkg
from ...auth import Identity, resolve_identity
from ...db import db
from ...entity_normalizer import NormalizationError, normalize_entity_uri
from ...garden_acl import get_garden_by_garden_uri, require_garden_read
from ...memory_garden_acl_gate import garden_acl_enforced
from ...metrics import FACT_READ
from ...models.constants import VALID_SCOPES
from ...models.facts import FactRecord, QueryResponse, row_to_record
from ...models.tombstones import TombstoneNotice
from ...plugins import Deny, Failure, Success, TenantContext, get_registry
from ...recall.recall_pipeline import apply_recall_pipeline
from ...session_graph import record_read_scopes
from ..cid_integrity import enforce_read_path_cid
from ..time_travel_gate import require_time_travel_enabled
from .common import _get_tombstone_filter, logger, router


def _validate_as_of(as_of: str) -> datetime:
    """Parse and validate an as_of timestamp per §24.2.2."""
    import re

    # URL query strings decode + as space; restore the + in timezone offsets like "+00:00".
    normalized = re.sub(r" (\d{2}:\d{2})$", r"+\1", as_of).replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "as_of_invalid_timestamp", "message": str(exc)},
        ) from exc
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    if ts > datetime.now(UTC) + timedelta(seconds=5):
        raise HTTPException(
            status_code=400,
            detail={"code": "as_of_future", "message": "as_of must not be in the future (§24.2.2)"},
        )
    floor = _settings_pkg.settings.as_of_retention_floor
    if floor:
        try:
            floor_ts = datetime.fromisoformat(floor.replace("Z", "+00:00"))
            if floor_ts.tzinfo is None:
                floor_ts = floor_ts.replace(tzinfo=UTC)
            if ts < floor_ts:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "code": "as_of_before_retention_floor",
                        "message": "as_of predates the retention horizon for this deployment (§24.2.2)",  # noqa: E501
                    },
                )
        except HTTPException:
            raise
        except Exception as exc:  # nosec B110
            logger.warning("could not read retention floor while validating as_of: %s", exc)
    return ts


def _legal_hold_blocks_query(conn: Any, entity: str) -> bool:
    """F-14 §24.3.2: True if a legal-hold tombstone covers *entity* (no active revocation)."""
    legal_hold_row = conn.execute(
        """SELECT 1 FROM tombstones t
           WHERE t.entity_uri = ?
           AND t.legal_hold = 1
           AND NOT EXISTS (
               SELECT 1 FROM tombstone_revocations r WHERE r.tombstone_id = t.id
           )
           LIMIT 1""",
        (entity,),
    ).fetchone()
    return legal_hold_row is not None


_AS_OF_SELECT_SQL = (
    "SELECT f.* FROM facts f"
    " WHERE f.tenant_id = ?"
    " AND f.timestamp <= ?"
    " AND (f.valid_until IS NULL OR f.valid_until > ?)"
    " AND NOT EXISTS ("
    "    SELECT 1 FROM fact_retractions fr"
    "     WHERE fr.fact_id = f.id AND fr.retracted_at <= ?"
    " )"
    " AND (? IS NULL"
    "      OR f.entity = ?"
    "      OR f.entity IN ("
    "          SELECT raw_uri FROM entity_aliases WHERE canonical_uri = ? AND tenant_id = ?))"
    " AND (? IS NULL OR f.relation = ?)"
    " AND (? IS NULL OR f.scope = ?)"
    " AND (? IS NULL OR f.id > ?)"
    " ORDER BY f.timestamp DESC, f.id DESC"
    " LIMIT ?"
)

_GARDEN_VISIBILITY_NONE = 0
_GARDEN_VISIBILITY_EXACT = 1
_GARDEN_VISIBILITY_VISIBLE_SET = 2
_GARDEN_VISIBILITY_NULL_ONLY = 3

_FACT_QUERY_SQL = (
    "SELECT f.*, "
    "COALESCE(fvo.valid_until, f.valid_until) AS projected_valid_until, "
    "COALESCE(fvo.confidence, f.confidence) AS projected_confidence, "
    "COALESCE(fgm.garden_id, f.garden_id) AS projected_garden_id, "
    "COALESCE(fqs.quarantine_status, f.quarantine_status) AS projected_quarantine_status, "
    "COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id) "
    "AS projected_quarantine_garden_id, "
    "COALESCE(f.cid, (SELECT fca.cid FROM fact_cid_aliases fca "
    "WHERE fca.fact_id = f.id ORDER BY fca.cid LIMIT 1)) AS projected_cid"
    " FROM facts f"
    " LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id"
    " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
    " LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id"
    " WHERE COALESCE(fvo.confidence, f.confidence) >= ?"
    " AND f.tenant_id = ?"
    " AND ("
    "   ? = 0"
    "   OR (? = 1 AND COALESCE(fgm.garden_id, f.garden_id) = ?)"
    "   OR (? = 2 AND (COALESCE(fgm.garden_id, f.garden_id) IS NULL"
    "       OR EXISTS (SELECT 1 FROM _query_visible_gardens qvg"
    "                  WHERE qvg.id = COALESCE(fgm.garden_id, f.garden_id))))"
    "   OR (? = 3 AND COALESCE(fgm.garden_id, f.garden_id) IS NULL)"
    " )"
    " AND (? IS NULL OR f.attested = ?)"
    " AND (? IS NULL"
    "      OR f.entity = ?"
    "      OR f.entity IN ("
    "          SELECT raw_uri FROM entity_aliases WHERE canonical_uri = ? AND tenant_id = ?))"
    " AND (? IS NULL OR f.relation = ?)"
    " AND (? IS NULL"
    "      OR f.source = ?"
    "      OR f.source IN ("
    "          SELECT raw_uri FROM entity_aliases WHERE canonical_uri = ? AND tenant_id = ?))"
    " AND (? IS NULL OR f.scope = ?)"
    " AND (? IS NULL OR f.timestamp > ?)"
    " AND (? IS NULL OR f.id > ?)"
    " AND (? = 1"
    "      OR COALESCE(fvo.valid_until, f.valid_until) IS NULL"
    "      OR COALESCE(fvo.valid_until, f.valid_until) > ?)"
    " ORDER BY f.timestamp DESC, f.id DESC LIMIT ?"
)

def _build_as_of_params(
    *,
    entity: str | None,
    scope: str | None,
    relation: str | None,
    as_of: str,
    tenant_id: str,
    cursor: str | None,
    limit: int,
) -> list[Any]:
    """Return the bind values for ``_AS_OF_SELECT_SQL``.

    The SQL text is the ``_AS_OF_SELECT_SQL`` module-level constant; this
    helper only computes bind values.  Keeping the SQL string out of any
    function that takes user input prevents CodeQL from interprocedurally
    tainting it — see issue #121 for why a function that takes user
    inputs and returns ``(sql, params)`` still trips ``py/sql-injection``
    even when the returned SQL value is invariant.
    """
    if scope is not None and scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope must be one of {VALID_SCOPES}")

    # Normalize empty strings to None so the IS NULL gate matches the
    # previous ``if entity:`` truthiness behaviour.
    entity_p = entity or None
    relation_p = relation or None
    scope_p = scope or None
    cursor_p = cursor or None

    return [
        tenant_id,
        as_of,
        as_of,
        as_of,
        entity_p,
        entity_p,
        entity_p,
        tenant_id,  # entity-alias subquery tenant scope
        relation_p,
        relation_p,
        scope_p,
        scope_p,
        cursor_p,
        cursor_p,
        limit + 1,
    ]


def _query_facts_as_of_impl(
    conn: Any,
    *,
    entity: str | None,
    scope: str | None,
    relation: str | None,
    as_of: str,
    is_admin_caller: bool,
    tenant_id: str,
    limit: int,
    cursor: str | None,
) -> QueryResponse:
    """Return facts visible at as_of per §24.4.

    Retraction gating uses fact_retractions.retracted_at (append-only log), NOT facts.confidence.
    Expiry gating uses facts.valid_until.
    Tombstone filter per §24.3: retroactive RTBF unless legal_hold=true AND is_admin_caller.
    """
    # F-14 §24.3.2: pre-check — agent-key callers get empty results if a legal-hold
    # tombstone covers the queried entity (short-circuit before executing the query)
    if entity and not is_admin_caller and _legal_hold_blocks_query(conn, entity):
        return QueryResponse(facts=[], total=None, cursor=None)

    params = _build_as_of_params(
        entity=entity,
        scope=scope,
        relation=relation,
        as_of=as_of,
        tenant_id=tenant_id,
        cursor=cursor,
        limit=limit,
    )

    rows = conn.execute(_AS_OF_SELECT_SQL, params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]

    seen: dict[tuple[str, str, str], int] = {}
    for r in rows:
        key = (r["entity"], r["relation"], r["scope"])
        seen[key] = seen.get(key, 0) + 1

    for r in rows:
        enforce_read_path_cid(r)
    records = [
        row_to_record(r, contradicted=seen[(r["entity"], r["relation"], r["scope"])] > 1)
        for r in rows
    ]

    # §24.3: tombstone filter for as_of queries
    tombstone_notices: list[TombstoneNotice] = []
    tombstone_filtered = False
    if records:
        entity_uris = list({r.entity for r in records})
        excluded, tombstone_notices = _get_tombstone_filter(
            conn, entity_uris, scope or "local", is_admin_caller
        )
        if excluded:
            records = [r for r in records if r.entity not in excluded]
            tombstone_filtered = True

    next_cursor = rows[-1]["id"] if has_more and rows else None
    # §23.3.3 r.3: suppress total when tombstone filtering was applied to prevent oracle leakage
    total = None if tombstone_filtered else len(records)
    return QueryResponse(
        facts=records,
        total=total,
        cursor=next_cursor,
        tombstone_notices=tombstone_notices,
    )


@router.get("", response_model=QueryResponse)
def query_facts(
    identity: Annotated[Identity, Depends(resolve_identity)],
    response: Response,
    session_id: Annotated[str | None, Header(alias="Stigmem-Session")] = None,
    entity: str | None = Query(None),
    relation: str | None = Query(None),
    source: str | None = Query(None),
    scope: str | None = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    include_contradicted: bool = Query(False),
    include_expired: bool = Query(False),
    after: str | None = Query(
        None, description="Return facts with timestamp > this ISO 8601 value"
    ),  # noqa: E501
    cursor: str | None = Query(None, description="Opaque pagination cursor (fact id)"),
    limit: int = Query(50, ge=1, le=500),
    garden_id: str | None = Query(
        None, description="Filter to facts in this garden (Spec-02-Scopes-and-ACL)"
    ),  # noqa: E501
    attested: bool | None = Query(
        None, description="Filter by source-attestation status (Spec-X6-Source-Attestation)"
    ),  # noqa: E501
    include_low_trust: bool = Query(
        False,
        description="Include facts with effective_confidence < 0.3 (Spec-05-Federation-Trust)",
    ),  # noqa: E501
    as_of: str | None = Query(
        None,
        description="Time-travel query: return facts visible at this ISO 8601 timestamp (Spec-X3-Time-Travel-Queries)",  # noqa: E501
    ),  # noqa: E501
) -> QueryResponse:
    """Query facts by pattern (Spec-03-HTTP-API).

    Omitted fields are wildcards. Entity/source are normalized by Spec-01-Fact-Model.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )  # noqa: E501

    request_id = str(uuid.uuid4())
    tenant = TenantContext(
        tenant_id=identity.tenant_id,
        metadata={"tenant_context_source": "hook"},
    )
    registry = get_registry()
    query_payload: dict[str, Any] = {
        "entity": entity,
        "relation": relation,
        "source": source,
        "scope": scope,
        "min_confidence": min_confidence,
        "include_contradicted": include_contradicted,
        "include_expired": include_expired,
        "after": after,
        "cursor": cursor,
        "limit": limit,
        "garden_id": garden_id,
        "attested": attested,
        "include_low_trust": include_low_trust,
        "as_of": as_of,
    }
    decision = registry.fire_voting(
        "pre_recall_authorize",
        identity=identity,
        tenant=tenant,
        request_id=request_id,
        query=query_payload,
    )
    if isinstance(decision, Deny):
        registry.fire_fire_and_forget(
            "post_recall_audit",
            result=None,
            identity=identity,
            tenant=tenant,
            request_id=request_id,
            outcome=Failure(reason=decision.reason),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    rewritten_query = registry.fire_filter_chain(
        "pre_recall_rewrite",
        query_payload,
        identity=identity,
        tenant=tenant,
        request_id=request_id,
    )
    entity = rewritten_query["entity"]
    relation = rewritten_query["relation"]
    source = rewritten_query["source"]
    scope = rewritten_query["scope"]
    min_confidence = rewritten_query["min_confidence"]
    include_contradicted = rewritten_query["include_contradicted"]
    include_expired = rewritten_query["include_expired"]
    after = rewritten_query["after"]
    cursor = rewritten_query["cursor"]
    limit = rewritten_query["limit"]
    garden_id = rewritten_query["garden_id"]
    attested = rewritten_query["attested"]
    include_low_trust = rewritten_query["include_low_trust"]
    as_of = rewritten_query["as_of"]

    # §24.4: time-travel query — delegate to as_of implementation
    if as_of is not None:
        require_time_travel_enabled(registry, surface="fact_query")
        _validate_as_of(as_of)
        with db() as conn:
            result = _query_facts_as_of_impl(
                conn,
                entity=entity,
                scope=scope,
                relation=relation,
                as_of=as_of,
                is_admin_caller=identity.is_admin(),
                tenant_id=identity.tenant_id,
                limit=limit,
                cursor=cursor,
            )
        if result.total is not None:
            response.headers["X-Total-Count"] = str(result.total)
        with db() as conn:
            record_read_scopes(
                conn,
                identity=identity,
                session_id=session_id,
                scopes={fact.scope for fact in result.facts},
            )
        registry.fire_fire_and_forget(
            "post_recall_audit",
            result=result,
            identity=identity,
            tenant=tenant,
            request_id=request_id,
            outcome=Success(),
        )
        return result

    FACT_READ.labels(principal=identity.entity_uri, tenant=identity.tenant_id).inc()

    # Garden ACL: resolve and enforce membership before querying (spec §5.20, §17.3)
    garden = _resolve_garden_or_404(garden_id, identity)

    with db() as conn:
        garden_visibility_mode, exact_garden_id, visible_garden_ids = _resolve_garden_visibility(
            conn, garden, identity
        )
        _prepare_garden_visibility_table(conn, visible_garden_ids)
        params = _build_query_params(
            identity=identity,
            garden_visibility_mode=garden_visibility_mode,
            exact_garden_id=exact_garden_id,
            entity=entity,
            relation=relation,
            source=source,
            scope=scope,
            min_confidence=min_confidence,
            attested=attested,
            after=after,
            cursor=cursor,
            include_expired=include_expired,
            limit=limit,
        )
        rows = conn.execute(_FACT_QUERY_SQL, params).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]

    records = _rows_to_records(rows)
    if not include_contradicted:
        records = [r for r in records if not r.contradicted]

    # v1.1: apply recall-time trust multiplier + content sanitizer (§19.4.4, §19.7)
    records = apply_recall_pipeline(records, identity=identity, include_low_trust=include_low_trust)

    # §23.3: tombstone filter — must be applied after scope filtering, before packing
    records, tombstone_filtered = _apply_tombstone_filter(records, scope, identity)
    records = registry.fire_filter_chain(
        "recall_filter",
        records,
        identity=identity,
        tenant=tenant,
        request_id=request_id,
    )
    score_deltas = registry.fire_score_delta(
        "recall_rank",
        records,
        identity=identity,
        tenant=tenant,
        request_id=request_id,
    )
    if score_deltas:
        records = sorted(records, key=lambda record: score_deltas.get(record.id, 0.0), reverse=True)

    next_cursor = rows[-1]["id"] if has_more and rows else None
    # §23.3.3 r.3: suppress total when tombstone filtering was applied to prevent oracle leakage
    total = None if tombstone_filtered else len(records)
    result = QueryResponse(facts=records, total=total, cursor=next_cursor)
    if result.total is not None:
        response.headers["X-Total-Count"] = str(result.total)
    with db() as conn:
        record_read_scopes(
            conn,
            identity=identity,
            session_id=session_id,
            scopes={fact.scope for fact in records},
        )
    registry.fire_fire_and_forget(
        "post_recall_audit",
        result=result,
        identity=identity,
        tenant=tenant,
        request_id=request_id,
        outcome=Success(),
    )
    return result


def _resolve_garden_or_404(garden_id: str | None, identity: Identity) -> Any:
    """Return the garden row when ``garden_id`` is set; 404 if missing; enforce read ACL."""
    if garden_id is None:
        return None
    garden = get_garden_by_garden_uri(garden_id, tenant_id=identity.tenant_id)
    if garden is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="garden not found")
    require_garden_read(garden, identity)
    return garden


def _resolve_garden_visibility(
    conn: Any,
    garden: Any,
    identity: Identity,
) -> tuple[int, str | None, list[str]]:
    """Return query visibility mode, exact garden id, and visible garden id set."""
    if garden is not None:
        return _GARDEN_VISIBILITY_EXACT, garden["id"], []
    if not garden_acl_enforced():
        return _GARDEN_VISIBILITY_NONE, None, []

    visible_garden_ids = [
        row["id"]
        for row in conn.execute(
            "SELECT g.id FROM gardens g"
            " WHERE g.tenant_id = ?"
            " AND EXISTS ("
            "     SELECT 1 FROM garden_members gm"
            "      WHERE gm.garden_id = g.id AND gm.entity_uri = ?"
            " )",
            (identity.tenant_id, identity.entity_uri),
        ).fetchall()
    ]
    if visible_garden_ids:
        return _GARDEN_VISIBILITY_VISIBLE_SET, None, visible_garden_ids
    return _GARDEN_VISIBILITY_NULL_ONLY, None, []


def _prepare_garden_visibility_table(conn: Any, visible_garden_ids: list[str]) -> None:
    """Populate the per-connection visibility table referenced by ``_FACT_QUERY_SQL``."""
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _query_visible_gardens (id TEXT PRIMARY KEY)")
    conn.execute("DELETE FROM _query_visible_gardens")
    for garden_id in visible_garden_ids:
        conn.execute("INSERT OR IGNORE INTO _query_visible_gardens (id) VALUES (?)", (garden_id,))


def _normalise_uri_or_raw(raw_value: str) -> str:
    """Best-effort URI normalisation; falls back to the raw value on failure."""
    try:  # noqa: SIM105
        return normalize_entity_uri(raw_value)
    except NormalizationError:
        return raw_value  # malformed — fall through to exact match


def _build_query_params(  # noqa: PLR0913 — narrow internal helper, keeps query_facts signature flat
    *,
    identity: Identity,
    garden_visibility_mode: int,
    exact_garden_id: str | None,
    entity: str | None,
    relation: str | None,
    source: str | None,
    scope: str | None,
    min_confidence: float,
    attested: bool | None,
    after: str | None,
    cursor: str | None,
    include_expired: bool,
    limit: int,
) -> list[Any]:
    """Return bind values for the fixed ``_FACT_QUERY_SQL`` template."""
    if scope and scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope must be one of {VALID_SCOPES}")

    normalised_entity = _normalise_uri_or_raw(entity) if entity else None
    normalised_source = _normalise_uri_or_raw(source) if source else None
    attested_value = None if attested is None else 1 if attested else 0
    now = datetime.now(UTC).isoformat()
    return [
        min_confidence,
        identity.tenant_id,
        garden_visibility_mode,
        garden_visibility_mode,
        exact_garden_id,
        garden_visibility_mode,
        garden_visibility_mode,
        attested_value,
        attested_value,
        normalised_entity,
        normalised_entity,
        normalised_entity,
        identity.tenant_id,  # entity-alias subquery tenant scope
        relation or None,
        relation or None,
        normalised_source,
        normalised_source,
        normalised_source,
        identity.tenant_id,  # source-alias subquery tenant scope
        scope or None,
        scope or None,
        after or None,
        after or None,
        cursor or None,
        cursor or None,
        1 if include_expired else 0,
        now,
        limit + 1,
    ]


def _rows_to_records(rows: list[Any]) -> list[FactRecord]:
    """Convert raw rows into FactRecords; mark within-key duplicates contradicted."""
    seen: dict[tuple[str, str, str], int] = {}
    for r in rows:
        enforce_read_path_cid(r)
        key = (r["entity"], r["relation"], r["scope"])
        seen[key] = seen.get(key, 0) + 1
    return [
        row_to_record(r, contradicted=seen[(r["entity"], r["relation"], r["scope"])] > 1)
        for r in rows
    ]


def _apply_tombstone_filter(
    records: list[FactRecord],
    scope: str | None,
    identity: Identity,
) -> tuple[list[FactRecord], bool]:
    """Return (filtered, tombstone_filtered_flag). Empty input → no work."""
    if not records:
        return records, False
    entity_uris_in_result = list({r.entity for r in records})
    with db() as _tc_conn:
        excluded, _notices = _get_tombstone_filter(
            _tc_conn, entity_uris_in_result, scope or "local", identity.is_admin()
        )
    if not excluded:
        return records, False
    return [r for r in records if r.entity not in excluded], True
