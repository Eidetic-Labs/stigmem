"""Scope synthesis route — Phase 6 (spec §synthesize)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import Identity, resolve_identity
from ..db import db
from ..fact_visibility import caller_read_scope
from ..models.constants import VALID_SCOPES

router = APIRouter(prefix="/v1/scopes", tags=["synthesis"])

_SYS_PREFIX = "stigmem:"
_URI_PREFIX = "stigmem://"


def _is_system(entity: str, relation: str) -> bool:
    return (entity.startswith(_SYS_PREFIX) and not entity.startswith(_URI_PREFIX)) or (
        relation.startswith(_SYS_PREFIX) and not relation.startswith(_URI_PREFIX)
    )


_SYNTHESIZE_SQL = (
    "SELECT f.*, "
    "       COALESCE(fvo.valid_until, f.valid_until) AS projected_valid_until, "
    "       COALESCE(fvo.confidence, f.confidence) AS projected_confidence, "
    "       COALESCE(fgm.garden_id, f.garden_id) AS projected_garden_id "
    "FROM facts f "
    "LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id "
    "LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
    " WHERE f.scope = ?"
    "   AND f.tenant_id = ?"
    "   AND (? = 1"
    "        OR COALESCE(fvo.valid_until, f.valid_until) IS NULL"
    "        OR COALESCE(fvo.valid_until, f.valid_until) > ?)"
    " ORDER BY COALESCE(fvo.confidence, f.confidence) DESC, f.timestamp DESC"
    " LIMIT ?"
)


def _build_synthesize_params(
    scope: str, tenant_id: str, include_expired: bool, limit: int, now: str
) -> list[Any]:
    """Return the bind values for ``_SYNTHESIZE_SQL`` (tenant-scoped, audit synthesize).

    The SQL text is a module-level constant; this helper only computes
    bind values.  Keeping the SQL string out of any function that
    accepts user input prevents CodeQL from interprocedurally tainting
    it — see issue #121 for why a function that takes user inputs and
    returns ``(sql, params)`` still trips ``py/sql-injection`` even
    when the returned SQL value is invariant.
    """
    expired_flag = 1 if include_expired else 0
    return [scope, tenant_id, expired_flag, now, limit]


def _count_pair_occurrences(rows: list[Any]) -> dict[tuple[str, str], int]:
    """Count (entity, relation) occurrences for non-system facts."""
    seen: dict[tuple[str, str], int] = {}
    for r in rows:
        if not _is_system(r["entity"], r["relation"]):
            key = (r["entity"], r["relation"])
            seen[key] = seen.get(key, 0) + 1
    return seen


def _row_age_seconds(timestamp: str) -> float:
    """Return seconds elapsed since the row's ISO timestamp; 0.0 on parse error."""
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return (datetime.now(UTC) - ts).total_seconds()
    except (ValueError, TypeError):
        return 0.0


def _build_synthesized_fact(
    r: Any, is_expired: bool, age_seconds: float, contradicted: bool
) -> dict[str, Any]:
    """Build the per-fact dict returned by synthesize_scope."""
    return {
        "id": r["id"],
        "entity": r["entity"],
        "relation": r["relation"],
        "value": {"type": r["value_type"], "v": r["value_v"]},
        "confidence": r["projected_confidence"],
        "timestamp": r["timestamp"],
        "valid_until": r["projected_valid_until"],
        "is_expired": is_expired,
        "age_seconds": age_seconds,
        "contradicted": contradicted,
        "source": r["source"],
    }


@router.get("/{scope}/synthesize")
def synthesize_scope(
    scope: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    include_expired: bool = Query(False),
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    """Confidence-weighted summary of all facts in a scope (Phase 6).

    Returns facts sorted by confidence descending, with contradiction flags and
    freshness metadata for each fact, plus aggregate statistics.
    """
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")
    if scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope must be one of {VALID_SCOPES}")

    now = datetime.now(UTC).isoformat()

    params = _build_synthesize_params(scope, identity.tenant_id, include_expired, limit, now)

    with db() as conn:
        rows = conn.execute(_SYNTHESIZE_SQL, params).fetchall()

    # Garden ACL (audit synthesize sibling of H1/M3): drop facts whose projected
    # garden the caller cannot see BEFORE aggregating, so the summary and stats
    # never expose restricted-garden content. Fail-closed + batched.
    read_scope = caller_read_scope(identity)
    rows = [r for r in rows if read_scope.garden_allows(r["projected_garden_id"])]

    # Count occurrences per (entity, relation) among non-system facts to detect contradictions
    seen = _count_pair_occurrences(rows)

    facts_out: list[dict[str, Any]] = []
    contradiction_count = 0
    expired_count = 0

    for r in rows:
        is_expired = (
            r["projected_valid_until"] is not None and r["projected_valid_until"] <= now
        )
        if is_expired:
            expired_count += 1

        contradicted = False
        if not _is_system(r["entity"], r["relation"]):
            contradicted = seen.get((r["entity"], r["relation"]), 0) > 1
            if contradicted:
                contradiction_count += 1

        age_seconds = _row_age_seconds(r["timestamp"])

        facts_out.append(_build_synthesized_fact(r, is_expired, age_seconds, contradicted))

    confidences = [f["confidence"] for f in facts_out]
    mean_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    timestamps = [f["timestamp"] for f in facts_out]

    return {
        "scope": scope,
        "fact_count": len(facts_out),
        "facts": facts_out,
        "contradiction_count": contradiction_count,
        "mean_confidence": mean_confidence,
        "freshest_timestamp": max(timestamps) if timestamps else None,
        "oldest_timestamp": min(timestamps) if timestamps else None,
        "expired_fact_count": expired_count,
        "synthesized_at": now,
    }
