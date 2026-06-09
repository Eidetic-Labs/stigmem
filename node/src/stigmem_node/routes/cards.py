"""Memory cards route — spec §20 (Phase 9).

GET /v1/cards/{entity_uri}  Fetch (and optionally force-refresh) the memory card
                            for a specific entity.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import Identity, resolve_identity
from ..card_materializer import get_fresh_card, refresh_card
from ..db import db
from ..entity_normalizer import NormalizationError, normalize_entity_uri
from ..fact_visibility import caller_read_scope
from ..models.cards import MemoryCardResponse
from ..models.constants import VALID_SCOPES

router = APIRouter(prefix="/v1/cards", tags=["cards"])


@router.get("/{entity_uri:path}", response_model=MemoryCardResponse)
def get_card(
    entity_uri: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    scope: str = Query("local"),
    refresh: bool = Query(False, description="Force refresh even if card is fresh"),
) -> MemoryCardResponse:
    """Fetch the synthesized memory card for an entity (Spec-X11-Recall-Graph).

    Returns 404 when the entity has no live facts.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="read permission required",
        )
    if scope not in VALID_SCOPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"scope must be one of {sorted(VALID_SCOPES)}",
        )

    try:
        entity_uri = normalize_entity_uri(entity_uri)
    except NormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_entity_uri: {exc}",
        ) from exc

    read_scope = caller_read_scope(identity)
    with db() as conn:
        # Garden ACL: the card summary aggregates the entity's fact values
        # verbatim with no garden filter, so it must not be served when any
        # contributing fact lives in a (projected) garden the caller cannot see
        # (audit cards-route sibling of H1). Hide as 404, don't reveal existence.
        if read_scope.enforce_gardens:
            garden_rows = conn.execute(
                "SELECT DISTINCT COALESCE(fgm.garden_id, f.garden_id) AS gid FROM facts f"
                " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
                " WHERE f.entity = ? AND f.scope = ? AND f.tenant_id = ?"
                "   AND f.confidence > 0"
                "   AND (f.quarantine_status IS NULL OR f.quarantine_status != 'pending')"
                "   AND COALESCE(fgm.garden_id, f.garden_id) IS NOT NULL",
                (entity_uri, scope, read_scope.tenant_id),
            ).fetchall()
            if any(r["gid"] not in read_scope.visible_gardens for r in garden_rows):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="no facts found for entity",
                )

        card = (
            refresh_card(entity_uri, scope, read_scope.tenant_id, conn)
            if refresh
            else get_fresh_card(entity_uri, scope, read_scope.tenant_id, conn)
        )

    if card is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no facts found for entity",
        )

    return MemoryCardResponse(
        entity_uri=card.entity_uri,
        scope=card.scope,
        summary=card.summary,
        fact_hashes=card.fact_hashes,
        avg_confidence=card.avg_confidence,
        refreshed_at=card.refreshed_at,
        is_stale=card.is_stale,
        has_contradictions=card.has_contradictions,
    )
