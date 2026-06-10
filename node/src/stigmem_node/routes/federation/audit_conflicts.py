"""Federation audit and conflict routes."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query, status

from ...auth import Identity, resolve_identity
from ...db import db
from ...hlc import node_hlc
from ...models.facts import row_to_record
from ...models.federation import ConflictResolveRequest
from .common import router


@router.get("/v1/federation/audit")
def get_audit_log(
    identity: Annotated[Identity, Depends(resolve_identity)],
    peer_id: str | None = Query(None),
    event_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    cursor: str | None = Query(None),
) -> dict[str, Any]:
    if not identity.can_federate():
        raise HTTPException(status_code=403, detail="federate permission required")

    conditions: list[str] = []
    params: list[Any] = []
    if peer_id:
        conditions.append("peer_id = ?")
        params.append(peer_id)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if cursor:
        conditions.append("id > ?")
        params.append(cursor)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit + 1)

    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM federation_audit {where} ORDER BY ts DESC, id DESC LIMIT ?",  # noqa: S608  # nosec B608 — where built from literal fragments; values in params
            params,
        ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = rows[-1]["id"] if has_more and rows else None

    return {
        "entries": [
            {
                "id": r["id"],
                "peer_id": r["peer_id"],
                "event_type": r["event_type"],
                "detail": json.loads(r["detail"]) if r["detail"] else None,
                "ts": r["ts"],
            }
            for r in rows
        ],
        "cursor": next_cursor,
        "has_more": has_more,
    }


# ---------------------------------------------------------------------------
# GET /v1/conflicts — list conflicts (§5.9)
# ---------------------------------------------------------------------------


@router.get("/v1/conflicts")
def list_conflicts(
    identity: Annotated[Identity, Depends(resolve_identity)],
    conflict_status: str | None = Query(None, alias="status"),
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
) -> dict[str, Any]:
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")

    # F-FED-CONFLICT-TENANT: the conflicts table carries no tenant_id, but the
    # facts it references do (ingest stamps tenant on both the facts and the
    # conflict facts). Scope the operator view to the caller's tenant by requiring
    # the conflict's fact_a to live in identity.tenant_id — otherwise an admin
    # scoped to tenant A could enumerate a conflict (and its facts) from tenant B.
    conditions: list[str] = [
        "EXISTS (SELECT 1 FROM facts f WHERE f.id = c.fact_a_id AND f.tenant_id = ?)"
    ]
    params: list[Any] = [identity.tenant_id]
    if conflict_status:
        conditions.append("c.status = ?")
        params.append(conflict_status)
    if cursor:
        conditions.append("c.id > ?")
        params.append(cursor)

    where = f"WHERE {' AND '.join(conditions)}"
    params.append(limit + 1)

    with db() as conn:
        sql = (
            "SELECT c.id, c.fact_a_id, c.fact_b_id, c.status, c.resolution_fact_id, "  # noqa: S608  # nosec B608
            f"c.detected_at FROM conflicts c {where} ORDER BY c.detected_at DESC, "
            "c.id DESC LIMIT ?"
        )
        rows = conn.execute(
            sql,
            params,
        ).fetchall()

        conflicts: list[dict[str, Any]] = []
        for r in rows[:limit]:
            fa = conn.execute(
                "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
                (r["fact_a_id"], identity.tenant_id),
            ).fetchone()
            fb = conn.execute(
                "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
                (r["fact_b_id"], identity.tenant_id),
            ).fetchone()
            conflicts.append(
                {
                    "conflict_id": r["id"],
                    "fact_a": row_to_record(fa).model_dump() if fa else None,
                    "fact_b": row_to_record(fb).model_dump() if fb else None,
                    "status": r["status"],
                    "resolved_by": r["resolution_fact_id"],
                    "detected_at": r["detected_at"],
                }
            )

    has_more = len(rows) > limit
    next_cursor = rows[limit - 1]["id"] if has_more and len(rows) >= limit else None
    return {"conflicts": conflicts, "cursor": next_cursor, "has_more": has_more}


# ---------------------------------------------------------------------------
# POST /v1/conflicts/:conflict_id/resolve — resolve a conflict (§5.10)
# ---------------------------------------------------------------------------


def _encode_value(vtype: str, v: Any) -> str:
    if vtype == "null":
        return "null"
    if vtype == "boolean":
        return "true" if v else "false"
    return str(v)


@router.post("/v1/conflicts/{conflict_id}/resolve")
def resolve_conflict(
    conflict_id: str,
    req: ConflictResolveRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Assert a canonical resolution fact and close the conflict (Spec-15-Fact-Semantics)."""
    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="write permission required"
        )

    with db() as conn:
        conflict = conn.execute("SELECT * FROM conflicts WHERE id = ?", (conflict_id,)).fetchone()

        # F-FED-CONFLICT-TENANT: a conflict is only visible/resolvable to a caller
        # whose tenant owns the conflicting facts. Treat a cross-tenant conflict as
        # not found (don't leak its existence) by requiring fact_a to live in the
        # caller's tenant.
        if conflict is not None:
            owns = conn.execute(
                "SELECT 1 FROM facts WHERE id = ? AND tenant_id = ?",
                (conflict["fact_a_id"], identity.tenant_id),
            ).fetchone()
            if owns is None:
                conflict = None

        if conflict is None:
            raise HTTPException(status_code=404, detail="conflict not found")
        if conflict["status"] == "resolved":
            raise HTTPException(status_code=409, detail="conflict already resolved")

        fact_a = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
            (conflict["fact_a_id"], identity.tenant_id),
        ).fetchone()
        fact_b = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
            (conflict["fact_b_id"], identity.tenant_id),
        ).fetchone()

        if fact_a is None or fact_b is None:
            raise HTTPException(status_code=500, detail="conflicting facts not found in store")

        # Determine value for the resolution fact
        if req.new_value is not None:
            res_type = req.new_value.type
            res_v = _encode_value(req.new_value.type, req.new_value.v)
        elif req.winning_fact_id is not None:
            if req.winning_fact_id == fact_a["id"]:
                winner = fact_a
            elif req.winning_fact_id == fact_b["id"]:
                winner = fact_b
            else:
                raise HTTPException(
                    status_code=422,
                    detail="winning_fact_id must be one of the conflicting facts",
                )
            res_type = winner["value_type"]
            res_v = winner["value_v"]
        else:
            raise HTTPException(status_code=422, detail="provide winning_fact_id or new_value")

        resolution_fact_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        caller = identity.entity_uri

        # 1. Assert resolution fact under a namespaced entity so it never shares the
        #    (entity, relation, scope) triple with the conflicting facts. Writing under
        #    the original entity+relation would trigger a new contradiction wave when the
        #    fact is federated to peers (spec §resolution-semantics, EG-51).
        resolution_entity = f"stigmem:resolution:{conflict_id}"
        hlc_res = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                resolution_fact_id,
                resolution_entity,
                fact_a["relation"],
                res_type,
                res_v,
                caller,
                now,
                None,
                1.0,
                fact_a["scope"],
                hlc_res,
                None,
                identity.tenant_id,
            ),
        )

        # 2. Assert stigmem:resolves meta-fact (spec §5.10)
        hlc_meta = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                resolution_fact_id,
                "stigmem:resolves",
                "ref",
                conflict_id,
                "system:stigmem",
                now,
                None,
                1.0,
                fact_a["scope"],
                hlc_meta,
                None,
                identity.tenant_id,
            ),
        )

        # 3. Record updated conflict:status as a new fact (status changes are immutable appends)
        hlc_status = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                conflict_id,
                "stigmem:conflict:status",
                "string",
                "resolved",
                "system:stigmem",
                now,
                None,
                1.0,
                fact_a["scope"],
                hlc_status,
                None,
                identity.tenant_id,
            ),
        )

        # 4. Update conflicts table
        conn.execute(
            "UPDATE conflicts SET status = 'resolved', resolution_fact_id = ? WHERE id = ?",
            (resolution_fact_id, conflict_id),
        )

    return {"resolution_fact_id": resolution_fact_id, "conflict_status": "resolved"}
