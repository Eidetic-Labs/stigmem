"""Single-fact retrieval route."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from ...auth import Identity, resolve_identity
from ...cid import is_cid, is_valid_cid
from ...db import db
from ...garden_acl import require_garden_read
from ...models.facts import FactRecord, row_to_record
from ...recall.recall_pipeline import apply_recall_pipeline
from ...session_graph import record_read_scopes
from ..cid_integrity import enforce_read_path_cid
from .common import FACT_PROJECTION_JOINS, FACT_PROJECTION_SELECT, router


@router.get("/{fact_id}", response_model=FactRecord)
def get_fact(
    fact_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    session_id: Annotated[str | None, Header(alias="Stigmem-Session")] = None,
) -> FactRecord:
    """Retrieve a single fact by UUID or sha256: CID.

    Covered by Spec-03-HTTP-API and Spec-21-Content-Addressed-IDs.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )  # noqa: E501

    # §25.5: dual addressing — resolve CID to UUID via alias table
    resolved_fact_id = fact_id
    if is_cid(fact_id):
        if not is_valid_cid(fact_id):
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "cid_malformed",
                    "message": "CID must be 'sha256:' followed by 64 hex chars",
                },  # noqa: E501
            )
        with db() as conn:
            alias = conn.execute(
                "SELECT fact_id FROM fact_cid_aliases WHERE cid = ? AND tenant_id = ?",
                (fact_id, identity.tenant_id),
            ).fetchone()
        if alias is None:
            raise HTTPException(status_code=404, detail="fact not found")
        resolved_fact_id = alias["fact_id"]

    with db() as conn:
        row = conn.execute(
            f"SELECT {FACT_PROJECTION_SELECT} FROM facts f {FACT_PROJECTION_JOINS} "  # noqa: S608  # nosec B608
            "WHERE f.id = ? AND f.tenant_id = ?",
            (resolved_fact_id, identity.tenant_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="fact not found")

    # F-11 §25.6.1/§23.3.3: tombstone indistinguishability — tombstoned facts return 404
    from ...lifecycle.tombstone_cache import is_tombstoned as _is_tombstoned_check

    if _is_tombstoned_check(row["entity"], identity.tenant_id):
        raise HTTPException(status_code=404, detail="fact not found")

    # Garden ACL: fact in a garden is only readable by members (spec §17.3)
    row_keys = row.keys()
    garden_id = (
        row["projected_garden_id"] if "projected_garden_id" in row_keys else row["garden_id"]
    )
    if garden_id is not None:
        with db() as conn:
            garden_row = conn.execute(
                "SELECT * FROM gardens WHERE id = ? AND tenant_id = ?",
                (garden_id, identity.tenant_id),
            ).fetchone()
        if garden_row is not None:
            require_garden_read(dict(garden_row), identity)

    with db() as conn:
        sibling_count: int = conn.execute(
            "SELECT COUNT(*) FROM facts WHERE entity=? AND relation=? AND scope=? AND tenant_id=?",
            (row["entity"], row["relation"], row["scope"], identity.tenant_id),
        ).fetchone()[0]
    enforce_read_path_cid(row)
    record = row_to_record(row, contradicted=sibling_count > 1)
    # v1.1: recall pipeline (trust multiplier + sanitizer)
    pipeline_results = apply_recall_pipeline([record], identity=identity, include_low_trust=True)
    if pipeline_results:
        with db() as conn:
            record_read_scopes(
                conn,
                identity=identity,
                session_id=session_id,
                scopes={pipeline_results[0].scope},
            )
        return pipeline_results[0]
    # Pending-quarantine facts return 404 to normal callers
    raise HTTPException(status_code=404, detail="fact not found")
