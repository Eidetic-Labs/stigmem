"""Configurable decay sweeper — marks stale facts as expired (Phase 6)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from ..db import db
from ..settings import settings
from .immutability import set_fact_validity_override


def _resolve_effective_ttl(ttl_seconds: int | None) -> int | None:
    """Resolve the effective TTL: explicit arg overrides settings; 0 means "expire all"."""
    if ttl_seconds is not None:
        return ttl_seconds  # 0 is valid: expire everything
    if settings.decay_ttl_seconds > 0:
        return settings.decay_ttl_seconds
    return None


def _resolve_effective_min_conf(min_confidence: float | None) -> float | None:
    """Resolve the effective confidence floor: explicit arg overrides settings."""
    if min_confidence is not None and min_confidence > 0.0:
        return min_confidence
    if settings.decay_min_confidence > 0.0:
        return settings.decay_min_confidence
    return None


def _select_ttl_candidates(
    conn: Any, effective_ttl: int, scope: str | None, now_dt: datetime, tenant_id: str
) -> list[str]:
    """Return fact ids whose timestamp is older than (now - effective_ttl)."""
    cutoff = (now_dt - timedelta(seconds=effective_ttl)).isoformat()
    sql = (
        "SELECT f.id FROM facts f "
        "LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id "
        "WHERE f.timestamp <= ? "
        "AND f.tenant_id = ? "
        "AND COALESCE(fvo.valid_until, f.valid_until) IS NULL "
        "AND NOT (entity LIKE 'stigmem:%' AND entity NOT LIKE 'stigmem://%') "
        "AND NOT (relation LIKE 'stigmem:%' AND relation NOT LIKE 'stigmem://%')"
    )
    params: list[Any] = [cutoff, tenant_id]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    return [r["id"] for r in conn.execute(sql, params).fetchall()]


def _select_confidence_candidates(
    conn: Any, effective_min_conf: float, scope: str | None, now: str, tenant_id: str
) -> list[str]:
    """Return active fact ids whose confidence is below the floor."""
    sql = (
        "SELECT f.id FROM facts f "
        "LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id "
        "WHERE COALESCE(fvo.confidence, f.confidence) < ? "
        "AND f.tenant_id = ? "
        "AND COALESCE(fvo.confidence, f.confidence) > 0.0 "
        "AND (COALESCE(fvo.valid_until, f.valid_until) IS NULL "
        "OR COALESCE(fvo.valid_until, f.valid_until) > ?) "
        "AND NOT (entity LIKE 'stigmem:%' AND entity NOT LIKE 'stigmem://%') "
        "AND NOT (relation LIKE 'stigmem:%' AND relation NOT LIKE 'stigmem://%')"
    )
    params: list[Any] = [effective_min_conf, tenant_id, now]
    if scope:
        sql += " AND scope = ?"
        params.append(scope)
    return [r["id"] for r in conn.execute(sql, params).fetchall()]


def _apply_decay(conn: Any, candidates: list[str], conf_ids: list[str], now: str) -> None:
    """Persist decay: mark candidates expired, log confidence retractions, sync graph."""
    for fact_id in candidates:
        set_fact_validity_override(
            conn,
            fact_id=fact_id,
            valid_until=now,
            reason="decay_sweep",
            updated_by="stigmem:system:decay",
        )
    # Append-only retraction log for confidence-floor drops (§24.2.1 c.3)
    if conf_ids:
        conn.executemany(
            "INSERT INTO fact_retractions (id, fact_id, retracted_at, retracted_by) "
            "VALUES (?,?,?,?)",
            [(str(uuid.uuid4()), fid, now, "stigmem:system:decay") for fid in conf_ids],
        )
    # Graph adjacency index (§20.1.2): propagate expiry to entity_edges
    from ..recall.graph_index import sync_edge_expiry

    sync_edge_expiry(conn, candidates, now)


def run_decay_sweep(
    ttl_seconds: int | None = None,
    min_confidence: float | None = None,
    scope: str | None = None,
    dry_run: bool = False,
    *,
    tenant_id: str,
) -> dict[str, Any]:
    """Mark stale facts as expired by setting valid_until to now.

    - TTL decay: non-expiring facts whose timestamp is at or before (now - ttl_seconds).
      Passing ttl_seconds=0 expires all non-expiring facts regardless of age.
    - Confidence decay: active facts whose confidence is below min_confidence.
    - System facts (stigmem: entity/relation, not stigmem://) are never decayed.
    - dry_run=True returns counts without writing.
    - Candidate selection is scoped to ``tenant_id`` so a caller can only
      expire/count facts in its own tenant (no cross-tenant write or count
      oracle).

    Returns {"scanned": N, "decayed": M, "dry_run": bool}.
    """
    now_dt = datetime.now(UTC)
    now = now_dt.isoformat()

    # Explicit args override settings defaults; settings=0/0.0 means "disabled"
    effective_ttl = _resolve_effective_ttl(ttl_seconds)
    effective_min_conf = _resolve_effective_min_conf(min_confidence)

    ttl_ids: list[str] = []
    conf_ids: list[str] = []

    with db() as conn:
        if effective_ttl is not None:
            ttl_ids = _select_ttl_candidates(conn, effective_ttl, scope, now_dt, tenant_id)

        if effective_min_conf is not None:
            conf_ids = _select_confidence_candidates(
                conn, effective_min_conf, scope, now, tenant_id
            )

        candidates = list({*ttl_ids, *conf_ids})

        if not dry_run and candidates:
            _apply_decay(conn, candidates, conf_ids, now)

    return {
        "scanned": len(candidates),
        "decayed": len(candidates) if not dry_run else 0,
        "dry_run": dry_run,
    }
