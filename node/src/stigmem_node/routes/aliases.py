"""Entity alias management routes — spec §2.6 Phase 6.

POST   /v1/aliases            — register a user-defined semantic alias
GET    /v1/aliases            — list aliases (filterable by kind / canonical_uri)
DELETE /v1/aliases/{raw_uri}  — remove a user-defined alias (migration aliases protected)
"""

from __future__ import annotations

from typing import Annotated, Any
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import Identity, resolve_identity
from ..db import db
from ..models.aliases import AliasRecord, AliasRequest
from ..recall.fuzzy_resolver import register_alias

router = APIRouter(prefix="/v1/aliases", tags=["aliases"])

_VALID_KINDS = {"user", "migration"}


@router.post("", response_model=AliasRecord, status_code=status.HTTP_201_CREATED)
def create_alias(
    req: AliasRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> AliasRecord:
    """Register a user-defined semantic alias (raw_uri ≡ canonical_uri)."""
    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="write permission required"
        )

    with db() as conn:
        try:
            result = register_alias(
                conn, req.raw_uri, req.canonical_uri, kind="user", tenant_id=identity.tenant_id
            )
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return AliasRecord(**result)


@router.get("", response_model=list[AliasRecord])
def list_aliases(
    identity: Annotated[Identity, Depends(resolve_identity)],
    kind: str | None = Query(None, description="Filter by kind: 'user' or 'migration'"),
    canonical_uri: str | None = Query(
        None, description="Return all aliases that resolve to this URI"
    ),
) -> list[AliasRecord]:
    """List registered entity aliases."""
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    if kind and kind not in _VALID_KINDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"kind must be one of {sorted(_VALID_KINDS)}",
        )

    # Always scope to the caller's tenant (aliases are tenant-isolated). The
    # base `tenant_id = ?` predicate is inlined in the SQL literal (not a
    # variable) so it is statically verifiable by the tenant-scope CI guard.
    params: list[Any] = [identity.tenant_id]
    extra = ""
    if kind:
        extra += " AND kind = ?"
        params.append(kind)
    if canonical_uri:
        extra += " AND canonical_uri = ?"
        params.append(canonical_uri)

    sql = (
        "SELECT raw_uri, canonical_uri, kind, created_at FROM entity_aliases"
        " WHERE tenant_id = ?" + extra + " ORDER BY created_at DESC"
    )
    with db() as conn:
        rows = conn.execute(sql, params).fetchall()  # noqa: S608  # nosec B608 — fragments are literal; values in params

    return [AliasRecord(**dict(r)) for r in rows]


@router.delete("/{raw_uri:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_alias(
    raw_uri: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> None:
    """Remove a user-defined alias. Migration aliases cannot be deleted via API."""
    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="write permission required"
        )

    decoded = unquote(raw_uri)

    with db() as conn:
        row = conn.execute(
            "SELECT kind FROM entity_aliases WHERE raw_uri = ? AND tenant_id = ?",
            (decoded, identity.tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alias not found")
        if row["kind"] != "user":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "migration aliases are managed by the migration sweep "
                    "and cannot be deleted via API"
                ),
            )
        conn.execute(
            "DELETE FROM entity_aliases WHERE raw_uri = ? AND tenant_id = ?",
            (decoded, identity.tenant_id),
        )
