"""CID verification route for facts."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from ...auth import Identity, resolve_identity
from ...cid import compute_cid_from_row, stored_cid_from_row
from ...db import db
from ...garden_acl import require_fact_garden_read
from .common import logger, router


class _CidVerifyResponse(BaseModel):
    cid_valid: bool
    computed_cid: str
    stored_cid: str | None
    mismatch_reason: str | None = None


@router.post("/{fact_id}/verify-cid", response_model=_CidVerifyResponse, tags=["facts"])
def verify_cid(
    fact_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> _CidVerifyResponse:
    """Verify a fact's stored CID against a freshly computed one.

    Covered by Spec-21-Content-Addressed-IDs.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )  # noqa: E501
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
            (fact_id, identity.tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="fact not found")
        # Garden ACL: a restricted-garden fact's CID is an existence/content
        # oracle — hide it from non-members (spec §17.3; sibling of single-get).
        require_fact_garden_read(conn, fact_id, identity.tenant_id, identity)
    computed = compute_cid_from_row(row)
    stored = stored_cid_from_row(row)
    if stored is None:
        return _CidVerifyResponse(
            cid_valid=False,
            computed_cid=computed,
            stored_cid=None,
            mismatch_reason="stored_cid is null (pre-Phase-13 record pending backfill)",
        )
    if computed == stored:
        return _CidVerifyResponse(cid_valid=True, computed_cid=computed, stored_cid=stored)
    logger.warning("CID mismatch for fact %s: computed=%s stored=%s", fact_id, computed, stored)
    return _CidVerifyResponse(
        cid_valid=False,
        computed_cid=computed,
        stored_cid=stored,
        mismatch_reason="stored_cid does not match computed_cid",
    )
