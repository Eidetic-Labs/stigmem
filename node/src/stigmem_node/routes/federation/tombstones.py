"""Federation tombstone routes."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Header, HTTPException, Request, status

from ...identity.capability import CapabilityTokenError, verify_token
from ...identity.trust_store import get_peer_manifest
from ...lifecycle.tombstones import list_revocations, list_tombstones
from ...models.tombstones import FederationTombstonesResponse
from .._federation_impl import federation_ingest_tombstone_impl
from .common import _get_mtls_peer_cert, _public_module, _try_peer_token_auth, router


@router.get("/v1/federation/tombstones", response_model=FederationTombstonesResponse)
def federation_list_tombstones(
    request: Request,
    since: str | None = None,
    limit: int = 200,
    token_header: Annotated[str | None, Header(alias="Authorization")] = None,
) -> FederationTombstonesResponse:
    """Tombstone poll route.

    Requires tombstone:read capability token. Covered by Spec-X2-RTBF-Tombstones.
    """
    raw_token = None
    if token_header and token_header.startswith("Bearer "):
        raw_token = token_header[7:]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="capability token required",
        )

    fed_settings = _public_module().settings
    if fed_settings.trust_mode != "off":
        try:
            import json as _json

            token_data = _json.loads(raw_token) if raw_token.startswith("{") else {}
            verbs = token_data.get("verbs", token_data.get("verb", ""))
            if isinstance(verbs, str):
                verbs = [v.strip() for v in verbs.split(",")] if verbs else []
            if "tombstone:read" not in verbs and "admin" not in verbs:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="tombstone:read capability required",
                )
            verify_token(
                raw_token,
                lambda uri: get_peer_manifest(
                    uri, refresh_if_expired=True, trust_mode=fed_settings.trust_mode
                ),
                trust_mode=fed_settings.trust_mode,
            )
        except CapabilityTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    else:
        import logging as _logging

        _logging.getLogger("stigmem.federation").warning(
            "tombstone poll: trust_mode=off — token signature verification skipped"
        )

    tombstone_list = list_tombstones(since=since)[:limit]
    revocation_list = list_revocations(since=since)[:limit]
    cursor = tombstone_list[-1].created_at if tombstone_list else None
    return FederationTombstonesResponse(
        tombstones=tombstone_list,
        revocations=revocation_list,
        cursor=cursor,
    )


@router.post("/v1/federation/tombstones/ingest", status_code=status.HTTP_200_OK)
def federation_ingest_tombstone(
    request: Request,
    payload: dict[str, Any],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_stigmem_capability: Annotated[str | None, Header(alias="x-stigmem-capability")] = None,
) -> dict[str, Any]:
    """Inbound tombstone push from a federation peer.

    Auth: peer JWT or capability token with tombstone:write verb (mirrors push_facts).
    Verifies signature against org manifest, writes to local tombstones table.
    Covered by Spec-X2-RTBF-Tombstones.
    """
    # Implementation lives in _federation_impl.federation_ingest_tombstone_impl.
    return federation_ingest_tombstone_impl(
        request,
        payload,
        authorization,
        x_stigmem_capability,
        _try_peer_token_auth,
        _get_mtls_peer_cert,
    )
