"""Federation peer registration and listing routes."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, field_validator

from ...auth import Identity, resolve_identity
from ...db import db
from ...models.federation import (
    PeerApprovalRequest,
    PeerApprovalResponse,
    PeerRegisterRequest,
    PeerRegisterResponse,
)
from .._federation_impl import approve_peer_impl, register_peer_impl
from .common import _public_module, router


@router.post(
    "/v1/federation/peers",
    response_model=PeerRegisterResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_peer(
    req: PeerRegisterRequest,
    background_tasks: BackgroundTasks,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> PeerRegisterResponse:
    """Register a peer.

    Fetches its well-known doc and verifies declaration_sig
    (Spec-05-Federation-Trust).
    """
    # Implementation lives in _federation_impl.register_peer_impl.
    return await register_peer_impl(req, background_tasks, identity)


@router.post(
    "/v1/federation/peers/{peer_id}/approve",
    response_model=PeerApprovalResponse,
)
def approve_peer(
    peer_id: str,
    req: PeerApprovalRequest,
    background_tasks: BackgroundTasks,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> PeerApprovalResponse:
    """Approve a pending peer after out-of-band public-key confirmation."""
    return approve_peer_impl(peer_id, req.pubkey_fingerprint, background_tasks, identity)


# ---------------------------------------------------------------------------
# PATCH /v1/federation/peers/{peer_id} — set per-peer tenant policy (mig. 041)
# ---------------------------------------------------------------------------


class PeerPolicyPatch(BaseModel):
    """Operator-settable per-peer tenant policy (migration 041)."""

    pull_tenant: str | None = None
    ingest_tenant: str | None = None
    allowed_tenants: list[str] | None = None
    trust_tier: str | None = None

    @field_validator("trust_tier")
    @classmethod
    def _tier(cls, v: str | None) -> str | None:
        if v is not None and v not in ("cross_org", "same_domain"):
            raise ValueError("trust_tier must be 'cross_org' or 'same_domain'")
        return v


@router.patch("/v1/federation/peers/{peer_id}")
def patch_peer_policy(
    peer_id: str,
    req: PeerPolicyPatch,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="federation admin required")
    sets: list[str] = []
    params: list[Any] = []
    if req.pull_tenant is not None:
        sets.append("pull_tenant = ?")
        params.append(req.pull_tenant)
    if req.ingest_tenant is not None:
        sets.append("ingest_tenant = ?")
        params.append(req.ingest_tenant)
    if req.allowed_tenants is not None:
        sets.append("allowed_tenants = ?")
        params.append(json.dumps(req.allowed_tenants))
    if req.trust_tier is not None:
        sets.append("trust_tier = ?")
        params.append(req.trust_tier)
    if not sets:
        raise HTTPException(status_code=400, detail="no policy fields provided")
    params.append(peer_id)
    with db() as conn:
        cur = conn.execute(
            f"UPDATE peers SET {', '.join(sets)} WHERE id = ?",  # noqa: S608  # nosec B608 — set clauses are literal column fragments; values in params
            params,
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="peer not found")
        conn.commit()
    updated = [s.split(" =")[0] for s in sets]
    _public_module().write_audit_log(
        peer_id,
        "peer_policy_updated",
        {"updated": updated, "by": identity.entity_uri},
    )
    return {"peer_id": peer_id, "updated": updated}


# ---------------------------------------------------------------------------
# GET /v1/federation/peers — list peers (§5.7)
# ---------------------------------------------------------------------------


def _decode_allowed_tenants(raw: Any) -> list[str]:
    """Defensively json-decode ``allowed_tenants``; default ``[]`` when null/blank."""
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return decoded if isinstance(decoded, list) else []


@router.get("/v1/federation/peers")
def list_peers(
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    if not identity.can_federate():
        raise HTTPException(status_code=403, detail="federate permission required")
    with db() as conn:
        rows = conn.execute(
            "SELECT id, node_id, node_url, status, allowed_scopes, established_at, "
            "pull_tenant, ingest_tenant, allowed_tenants, trust_tier FROM peers"
        ).fetchall()
    return {
        "peers": [
            {
                "peer_id": r["id"],
                "node_id": r["node_id"],
                "node_url": r["node_url"],
                "status": r["status"],
                "allowed_scopes": json.loads(r["allowed_scopes"]),
                "established_at": r["established_at"],
                "pull_tenant": r["pull_tenant"],
                "ingest_tenant": r["ingest_tenant"],
                "allowed_tenants": _decode_allowed_tenants(r["allowed_tenants"]),
                "trust_tier": r["trust_tier"],
            }
            for r in rows
        ]
    }
