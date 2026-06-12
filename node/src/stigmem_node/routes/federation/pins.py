"""Admin routes for the operator origin-pin store — Phase 2c W4.1.

All three endpoints are gated on ``admin:federation`` (403 otherwise) and each
mutating call writes a federation audit event, mirroring ``patch_peer_policy``
in ``peers.py``.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from ...auth import Identity, resolve_identity
from ...db import db
from ...federation.origin_pins import (
    delete_origin_pin,
    get_origin_pin,
    list_origin_pins,
    put_origin_pin,
)
from .common import _public_module, router

# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class OriginPinRequest(BaseModel):
    """Body for POST /v1/federation/origin-pins."""

    entity_uri: str
    node_id: str
    key_fingerprint: str


# ---------------------------------------------------------------------------
# POST /v1/federation/origin-pins — create/replace a pin
# ---------------------------------------------------------------------------


@router.post(
    "/v1/federation/origin-pins",
    status_code=status.HTTP_200_OK,
)
def create_origin_pin(
    req: OriginPinRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Pin an origin's (entity_uri, node_id, key_fingerprint) out-of-band.

    Idempotent: re-pinning the same key is a no-op update; re-pinning a
    different key replaces the previous fingerprint (explicit operator action).
    Requires admin:federation.
    """
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")
    with db() as conn:
        put_origin_pin(
            conn,
            entity_uri=req.entity_uri,
            node_id=req.node_id,
            key_fingerprint=req.key_fingerprint,
            pinned_by=identity.entity_uri,
        )
        conn.commit()
        row = get_origin_pin(conn, entity_uri=req.entity_uri, node_id=req.node_id)
    _public_module().write_audit_log(
        req.entity_uri,
        "origin_pin_set",
        {
            "entity_uri": req.entity_uri,
            "node_id": req.node_id,
            "key_fingerprint": req.key_fingerprint,
            "pinned_by": identity.entity_uri,
        },
    )
    return row  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# GET /v1/federation/origin-pins — list all pins
# ---------------------------------------------------------------------------


@router.get("/v1/federation/origin-pins")
def list_pins(
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """List all operator-pinned origins. Requires admin:federation."""
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")
    with db() as conn:
        pins = list_origin_pins(conn)
    return {"pins": pins}


# ---------------------------------------------------------------------------
# DELETE /v1/federation/origin-pins/{entity_uri}/{node_id} — remove a pin
# ---------------------------------------------------------------------------


@router.delete("/v1/federation/origin-pins")
def delete_pin(
    entity_uri: str,
    node_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Remove an operator pin for (entity_uri, node_id). Requires admin:federation.

    ``entity_uri`` and ``node_id`` are passed as query parameters to avoid
    path-encoding complications with ``://`` URIs.  Returns 404 when no such
    pin exists.
    """
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")
    with db() as conn:
        deleted = delete_origin_pin(conn, entity_uri=entity_uri, node_id=node_id)
        if deleted:
            conn.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="origin pin not found")
    _public_module().write_audit_log(
        entity_uri,
        "origin_pin_deleted",
        {
            "entity_uri": entity_uri,
            "node_id": node_id,
            "deleted_by": identity.entity_uri,
        },
    )
    return {"entity_uri": entity_uri, "node_id": node_id, "deleted": True}
