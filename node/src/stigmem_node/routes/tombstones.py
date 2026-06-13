"""RTBF tombstone admin API — spec §23.6.

Routes:
  POST /v1/tombstones                          — issue a tombstone (admin)
  GET  /v1/tombstones/{entity_uri_encoded}     — check tombstone status (admin)
  POST /v1/tombstones/{tombstone_id}/revoke    — revoke a tombstone (admin)

All endpoints require an admin API key.
"""

from __future__ import annotations

import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import Identity, resolve_identity
from ..lifecycle.tombstone_signing import get_node_key_id, sign_revocation, sign_tombstone
from ..lifecycle.tombstones import (
    create_tombstone,
    get_tombstone_status,
)
from ..lifecycle.tombstones import (
    revoke_tombstone as _revoke_tombstone,
)
from ..models.tombstones import (
    TombstoneCreateRequest,
    TombstoneRecord,
    TombstoneRevocationRecord,
    TombstoneRevokeRequest,
    TombstoneStatusResponse,
)

router = APIRouter(prefix="/v1/tombstones", tags=["tombstones"])

_VALID_SCOPES = {"local", "team", "company", "public", "*"}


def _require_admin(identity: Identity) -> None:
    if not identity.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin API key required",
        )


# ---------------------------------------------------------------------------
# POST /v1/tombstones — issue a tombstone
# ---------------------------------------------------------------------------


@router.post("", status_code=status.HTTP_201_CREATED, response_model=TombstoneRecord)
def issue_tombstone(
    req: TombstoneCreateRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> TombstoneRecord:
    _require_admin(identity)

    if req.scope not in _VALID_SCOPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="tombstone_invalid_scope",
        )

    if (
        "://" not in req.entity_uri
        and not req.entity_uri.startswith("urn:")
        and ":" not in req.entity_uri
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="tombstone_entity_uri_invalid",
        )

    key_id = get_node_key_id() or ""

    tombstone_id = "tomb_" + str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat()
    draft = TombstoneRecord(
        id=tombstone_id,
        entity_uri=req.entity_uri,
        scope=req.scope,
        reason=req.reason,
        signed_by=identity.entity_uri,
        key_id=key_id,
        signature="",
        created_at=created_at,
        legal_hold=req.legal_hold,
    )

    signed = sign_tombstone(draft)

    try:
        record = create_tombstone(
            entity_uri=signed.entity_uri,
            scope=signed.scope,
            reason=signed.reason,
            signed_by=signed.signed_by,
            key_id=signed.key_id,
            signature=signed.signature,
            legal_hold=signed.legal_hold,
            # Scope issuance to the caller's tenant (R-3 / F-SBOLA3): without this the row
            # defaults to "default", so an admin-issued tombstone could never suppress a
            # non-default tenant's facts and would land in the wrong partition.
            tenant_id=identity.tenant_id,
            tombstone_id=signed.id,
            created_at=signed.created_at,
        )
    except Exception as exc:
        if "already exists" in str(exc) or "UNIQUE" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="tombstone_already_exists",
            ) from exc
        raise

    # Enqueue outbound federation rebroadcast (§23.4.1) — best-effort background
    _enqueue_tombstone_rebroadcast(record)

    return record


# ---------------------------------------------------------------------------
# GET /v1/tombstones/{entity_uri_encoded} — check tombstone status
# ---------------------------------------------------------------------------


@router.get("/{entity_uri_encoded:path}", response_model=TombstoneStatusResponse)
def check_tombstone_status(
    entity_uri_encoded: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> TombstoneStatusResponse:
    _require_admin(identity)
    entity_uri = urllib.parse.unquote(entity_uri_encoded)
    return get_tombstone_status(entity_uri, identity.tenant_id)


# ---------------------------------------------------------------------------
# POST /v1/tombstones/{tombstone_id}/revoke — revoke a tombstone
# ---------------------------------------------------------------------------


@router.post("/{tombstone_id}/revoke", response_model=TombstoneRevocationRecord)
def revoke_tombstone_endpoint(
    tombstone_id: str,
    req: TombstoneRevokeRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> TombstoneRevocationRecord:
    _require_admin(identity)

    key_id = get_node_key_id()
    if key_id is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="node signing key not configured",
        )

    try:
        record = _revoke_tombstone(
            tombstone_id=tombstone_id,
            reason=req.reason,
            signed_by=identity.entity_uri,
            key_id=key_id,
            signature="pending",
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="tombstone_not_found"
        ) from exc
    except ValueError as exc:
        if "already_revoked" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="tombstone_already_revoked"
            ) from exc
        raise

    signed_record = sign_revocation(record)
    # Update the stored signature
    from ..db import db

    with db() as conn:
        conn.execute(
            "UPDATE tombstone_revocations SET signature = ?, key_id = ? WHERE id = ?",
            (signed_record.signature, signed_record.key_id, signed_record.id),
        )
    return signed_record


# ---------------------------------------------------------------------------
# Background federation rebroadcast
# ---------------------------------------------------------------------------


def _enqueue_tombstone_rebroadcast(record: TombstoneRecord) -> None:
    """Best-effort outbound push of tombstone to all active federation peers (§23.4.1)."""
    import threading

    t = threading.Thread(target=_push_tombstone_to_peers, args=(record,), daemon=True)
    t.start()


def _push_tombstone_to_peers(record: TombstoneRecord) -> None:
    import logging

    import httpx

    from ..db import db
    from ..federation.peer_token import create_peer_token

    log = logging.getLogger("stigmem.tombstones.federation")
    try:
        with db() as conn:
            peers = conn.execute(
                "SELECT node_id, node_url, allowed_scopes FROM peers WHERE status = 'active'"
            ).fetchall()
    except Exception:
        log.exception("Failed to fetch peers for tombstone rebroadcast")
        return

    payload = record.model_dump()
    for peer in peers:
        try:
            import json as _json

            allowed_scopes = _json.loads(peer["allowed_scopes"])
            token = create_peer_token(peer["node_id"], allowed_scopes)
            resp = httpx.post(
                f"{peer['node_url'].rstrip('/')}/v1/federation/tombstones/ingest",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            if resp.status_code not in (200, 201, 409):
                log.warning(
                    "Peer %s returned %s on tombstone push", peer["node_url"], resp.status_code
                )
        except Exception:
            log.warning("Failed to push tombstone to peer %s", peer["node_url"], exc_info=True)
