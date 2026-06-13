"""Quarantine admin API — spec §19.5.

GET  /v1/quarantine             — list quarantined facts (all or by garden)
POST /v1/quarantine/{fact_id}/admit  — shorthand: promote fact to main fabric
POST /v1/quarantine/{fact_id}/reject — shorthand: reject a quarantined fact

These endpoints are convenience wrappers over the garden-level promote/reject
endpoints (POST /v1/gardens/:id/promote|reject).  They operate node-globally:
the caller addresses a fact by ID without needing to know its quarantine garden.
Requires node admin (write) permission.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..audit_event import INSTRUCTION_PROMOTED, emit_instruction_event_if_applicable
from ..auth import Identity, resolve_identity
from ..db import db
from ..garden_acl import get_garden_by_slug_or_id, require_quarantine_moderator_or_admin
from ..lifecycle.immutability import (
    set_fact_garden_membership,
    set_fact_quarantine_status,
    set_fact_validity_override,
)
from ..models.constants import QUARANTINE_PENDING
from ..models.gardens import (
    QuarantineListResponse,
    QuarantineRecord,
)

router = APIRouter(prefix="/v1/quarantine", tags=["quarantine"])


def _require_write(identity: Identity) -> None:
    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="write permission required"
        )


# ---------------------------------------------------------------------------
# List quarantined facts
# ---------------------------------------------------------------------------


@router.get("", response_model=QuarantineListResponse)
def list_quarantined_facts(
    identity: Annotated[Identity, Depends(resolve_identity)],
    garden_id: str | None = Query(None, description="Filter by quarantine garden UUID or slug"),
    quarantine_status: str | None = Query(
        None, description="Filter by status: pending, promoted, rejected"
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> QuarantineListResponse:
    """List facts in the quarantine system (Spec-08-Quarantine-Garden).

    Scoped to the caller's tenant: admins see all quarantined facts within their
    own tenant. Other callers see facts only in quarantine gardens where they
    hold a member role. No caller can read another tenant's quarantine.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    projection_joins = (
        " LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id"
        " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
    )
    quarantine_garden_expr = "COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id)"
    quarantine_status_expr = "COALESCE(fqs.quarantine_status, f.quarantine_status)"
    # Tenant scope: applies to ALL callers (admins included). A per-NODE admin
    # is NOT cross-tenant — quarantine moderation is per-TENANT (R-2 / F-SBOLA5).
    # Kept as a LITERAL leading predicate in the WHERE f-string below (NOT appended
    # to `filters`) so the static fact-query tenant-scope guard can verify it.
    params: list[Any] = [identity.tenant_id]
    filters: list[str] = [f"{quarantine_garden_expr} IS NOT NULL"]

    if quarantine_status:
        filters.append(f"{quarantine_status_expr} = ?")
        params.append(quarantine_status)
    else:
        filters.append(f"{quarantine_status_expr} IS NOT NULL")

    if garden_id:
        # Resolve slug to UUID
        garden = get_garden_by_slug_or_id(garden_id, tenant_id=identity.tenant_id)
        if garden is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="garden not found")
        filters.append(f"{quarantine_garden_expr} = ?")
        params.append(garden["id"])
    elif not identity.can_write():
        # Non-admins: only see facts in gardens they're members of
        filters.append(
            f"{quarantine_garden_expr} IN ("  # nosec B608
            "  SELECT gm.garden_id FROM garden_members gm"
            "  WHERE gm.entity_uri = ?"
            ")"
        )
        params.append(identity.entity_uri)

    where_clause = " AND ".join(filters)

    with db() as conn:
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM facts f {projection_joins}"
            f" WHERE f.tenant_id = ? AND {where_clause}",  # nosec B608
            params,
        ).fetchone()
        total: int = count_row[0] if count_row else 0

        rows = conn.execute(
            f"""SELECT f.id, f.entity, f.relation, f.source,
                       {quarantine_status_expr} AS quarantine_status,
                       {quarantine_garden_expr} AS quarantine_garden_id,
                       COALESCE(fqs.quarantine_reason, f.quarantine_reason) AS quarantine_reason,
                       COALESCE(fqs.quarantine_acted_by, f.quarantine_acted_by)
                         AS quarantine_acted_by,
                       COALESCE(fqs.quarantine_acted_at, f.quarantine_acted_at)
                         AS quarantine_acted_at,
                       f.source_trust, f.received_from, f.timestamp
                FROM facts f {projection_joins}
                WHERE f.tenant_id = ? AND {where_clause}
                ORDER BY f.timestamp DESC
                LIMIT ? OFFSET ?""",  # nosec B608
            [*params, limit, offset],
        ).fetchall()

    items = [
        QuarantineRecord(
            fact_id=r["id"],
            entity=r["entity"],
            relation=r["relation"],
            source=r["source"],
            quarantine_status=r["quarantine_status"] or "",
            quarantine_garden_id=r["quarantine_garden_id"],
            quarantine_reason=r["quarantine_reason"],
            quarantine_acted_by=r["quarantine_acted_by"],
            quarantine_acted_at=r["quarantine_acted_at"],
            source_trust=float(r["source_trust"]) if r["source_trust"] is not None else None,
            received_from=r["received_from"],
            timestamp=r["timestamp"],
        )
        for r in rows
    ]

    return QuarantineListResponse(items=items, total=total)


# ---------------------------------------------------------------------------
# Admit (promote) a fact from quarantine to the main fabric
# ---------------------------------------------------------------------------


@router.post("/{fact_id}/admit", status_code=status.HTTP_200_OK)
def admit_fact(
    fact_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    target_garden_id: str | None = Query(None, description="Target garden UUID or slug"),
    reason: str = Query("", description="Reason for admission"),
) -> dict[str, Any]:
    """Promote a quarantined fact to the main fabric (or a specific target garden).

    Node admins may admit quarantined facts as last-resort moderation
    authority. Other callers require quarantine:moderator or admin role in the
    fact's quarantine garden.
    """
    _require_write(identity)

    fact_row, garden = _get_quarantined_fact(fact_id, identity)
    now = datetime.now(UTC).isoformat()

    # Resolve target garden
    target_db_id: str | None = None
    if target_garden_id:
        tg = get_garden_by_slug_or_id(target_garden_id, tenant_id=identity.tenant_id)
        # get_garden_by_slug_or_id's UUID branch is NOT tenant-scoped, so a caller
        # could pass another tenant's garden UUID and link their own fact into it.
        # Reject (as 404, to avoid revealing existence) any resolved garden that is
        # not in the caller's tenant.
        if tg is None or tg["tenant_id"] != identity.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="target garden not found"
            )
        target_db_id = tg["id"]

    with db() as conn:
        set_fact_garden_membership(
            conn,
            fact_id=fact_id,
            garden_id=target_db_id,
            updated_by=identity.entity_uri,
        )
        set_fact_quarantine_status(
            conn,
            fact_id=fact_id,
            quarantine_garden_id=garden["id"],
            quarantine_status="promoted",
            quarantine_reason=reason or "admitted via admin API",
            quarantine_acted_by=identity.entity_uri,
            quarantine_acted_at=now,
        )
        _write_quarantine_audit(conn, fact_id, "quarantine_promote", identity, now)
        emit_instruction_event_if_applicable(
            INSTRUCTION_PROMOTED,
            fact_id=fact_id,
            fact_entity=fact_row["entity"],
            fact_relation=fact_row["relation"],
            fact_interpret_as=fact_row["interpret_as"],
            actor_uri=identity.entity_uri,
            tenant_id=identity.tenant_id,
            oidc_sub=identity.oidc_sub,
            source=identity.entity_uri,
            detail={
                "reason": reason or "admitted via admin API",
                "quarantine_garden_id": garden["id"],
                "target_garden_id": target_db_id,
            },
            conn=conn,
        )

    return {
        "fact_id": fact_id,
        "action": "admitted",
        "target_garden_id": target_db_id,
        "acted_by": identity.entity_uri,
        "acted_at": now,
    }


# ---------------------------------------------------------------------------
# Reject a quarantined fact
# ---------------------------------------------------------------------------


@router.post("/{fact_id}/reject", status_code=status.HTTP_200_OK)
def reject_fact(
    fact_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    reason: str = Query("", description="Reason for rejection"),
) -> dict[str, Any]:
    """Permanently reject a quarantined fact.

    Sets confidence = 0.0 and quarantine_status = 'rejected'.
    Node admins may reject quarantined facts as last-resort moderation
    authority. Other callers require quarantine:moderator or admin role in the
    fact's quarantine garden.
    """
    _require_write(identity)

    _fact_row, garden = _get_quarantined_fact(fact_id, identity)
    now = datetime.now(UTC).isoformat()

    with db() as conn:
        set_fact_validity_override(
            conn,
            fact_id=fact_id,
            confidence=0.0,
            reason=reason or "rejected via admin API",
            updated_by=identity.entity_uri,
        )
        set_fact_quarantine_status(
            conn,
            fact_id=fact_id,
            quarantine_garden_id=garden["id"],
            quarantine_status="rejected",
            quarantine_reason=reason or "rejected via admin API",
            quarantine_acted_by=identity.entity_uri,
            quarantine_acted_at=now,
        )
        # Append-only retraction log (§24.2.1 c.3)
        conn.execute(
            "INSERT INTO fact_retractions"
            " (id, fact_id, retracted_at, retracted_by) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), fact_id, now, identity.entity_uri),
        )
        _write_quarantine_audit(conn, fact_id, "quarantine_reject", identity, now)

    return {
        "fact_id": fact_id,
        "action": "rejected",
        "acted_by": identity.entity_uri,
        "acted_at": now,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_quarantined_fact(
    fact_id: str, identity: Identity
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (fact_row, garden_row) for a pending quarantined fact.

    Scoped to the caller's tenant: a fact in another tenant returns 404 (R-2 /
    F-SBOLA5). Within the caller's tenant, admins are the last-resort moderation
    authority; garden-scoped moderators must hold quarantine:moderator or admin
    role in the fact's quarantine garden.
    """
    with db() as conn:
        row = conn.execute(
            """SELECT f.*,
                      COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id)
                        AS projected_quarantine_garden_id,
                      COALESCE(fqs.quarantine_status, f.quarantine_status)
                        AS projected_quarantine_status,
                      COALESCE(fqs.quarantine_reason, f.quarantine_reason)
                        AS projected_quarantine_reason
               FROM facts f
               LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id
               WHERE f.id = ?
                 AND f.tenant_id = ?
                 AND COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id) IS NOT NULL""",
            (fact_id, identity.tenant_id),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="quarantined fact not found"
        )

    if row["projected_quarantine_status"] != QUARANTINE_PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="fact_not_quarantine_pending",
        )

    garden = get_garden_by_slug_or_id(
        row["projected_quarantine_garden_id"], tenant_id=identity.tenant_id
    )
    if garden is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="quarantine garden not found"
        )

    if not identity.can_write():
        require_quarantine_moderator_or_admin(garden, identity)

    return dict(row), garden


def _write_quarantine_audit(
    conn: Any, fact_id: str, event_type: str, identity: Identity, now: str
) -> None:
    audit_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fact_audit_log"
        " (id, fact_id, event_type, entity_uri, oidc_sub, source,"
        "  attested_key_id, ts)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (
            audit_id,
            fact_id,
            event_type,
            identity.entity_uri,
            identity.oidc_sub,
            identity.entity_uri,
            None,
            now,
        ),
    )
