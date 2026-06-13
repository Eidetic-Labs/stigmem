"""Shared recall route helpers and compatibility utilities."""

from __future__ import annotations

import logging
import sys
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from ...auth import Identity
from ...models.facts import FactRecord, row_to_record
from ..cid_integrity import enforce_read_path_cid

logger = logging.getLogger("stigmem.recall")

router = APIRouter(prefix="/v1/recall", tags=["recall"])

def _public_module() -> Any:
    """Return the public recall module so test monkey-patches stay visible."""
    return sys.modules["stigmem_node.routes.recall"]

def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _estimate_tokens(record: FactRecord) -> int:
    """Rough token estimate: 4 chars ≈ 1 token (GPT tokeniser heuristic)."""
    text = f"{record.entity} {record.relation} {record.value.v or ''} {record.source}"
    return max(1, len(text) // 4)


def _recency_score(timestamp_str: str) -> float:
    """Normalised recency: 1.0 = now, 0.0 = ≥1 year old."""
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        days_old = (datetime.now(UTC) - ts).days
        return max(0.0, 1.0 - days_old / 365.0)
    except Exception:
        return 0.5


def _fetch_facts_by_ids(
    conn: Any,
    fact_ids: list[str],
) -> dict[str, FactRecord]:
    """Bulk-fetch facts by ID; returns {id: FactRecord}."""
    if not fact_ids:
        return {}
    placeholders = ",".join("?" * len(fact_ids))
    rows = conn.execute(
        f"""
        SELECT f.*,
               COALESCE(fvo.valid_until, f.valid_until) AS projected_valid_until,
               COALESCE(fvo.confidence, f.confidence) AS projected_confidence,
               COALESCE(fgm.garden_id, f.garden_id) AS projected_garden_id,
               COALESCE(fqs.quarantine_status, f.quarantine_status)
                 AS projected_quarantine_status,
               COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id)
                 AS projected_quarantine_garden_id,
               COALESCE(f.cid, (
                 SELECT fca.cid
                 FROM fact_cid_aliases fca
                 WHERE fca.fact_id = f.id
                 ORDER BY fca.cid
                 LIMIT 1
               )) AS projected_cid
        FROM facts f
        LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id
        LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id
        LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id
        WHERE f.id IN ({placeholders})
        """,  # noqa: S608  # nosec B608
        fact_ids,
    ).fetchall()
    for row in rows:
        enforce_read_path_cid(row)
    return {row["id"]: row_to_record(row) for row in rows}


def _write_recall_audit(
    conn: Any,
    recall_id: str,
    identity: Identity,
    query_hash: str,
    scope: str,
    token_budget: int,
    facts_returned: int,
    tokens_used: int,
    truncated: bool,
) -> None:
    now = _now_iso()
    try:
        conn.execute(
            """
            INSERT INTO recall_audit_log
              (id, entity_uri, query_hash, scope, token_budget,
               facts_returned, tokens_used, truncated, tenant_id, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                recall_id,
                identity.entity_uri,
                query_hash,
                scope,
                token_budget,
                facts_returned,
                tokens_used,
                1 if truncated else 0,
                identity.tenant_id,
                now,
            ),
        )
    except Exception as exc:
        logger.error("Failed to write recall_audit_log: %s", exc)
