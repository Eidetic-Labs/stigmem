"""Memory cards route — spec §20 (Phase 9).

GET /v1/cards/{entity_uri}  Fetch (and optionally force-refresh) the memory card
                            for a specific entity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..auth import Identity, resolve_identity
from ..card_materializer import get_fresh_card, refresh_card
from ..db import db
from ..entity_normalizer import NormalizationError, normalize_entity_uri
from ..memory_garden_acl_gate import garden_acl_enforced
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

    with db() as conn:
        # Garden ACL: the card summary aggregates the entity's fact values
        # verbatim with no garden filter, so it must not be served when any
        # contributing fact lives in a (projected) garden the caller cannot see
        # (audit cards-route sibling of H1). Reuse the recall card gate so the
        # two routes serving the same card cannot diverge. Hide as 404.
        from .recall.orchestration import _caller_sees_all_card_gardens

        now = datetime.now(UTC).isoformat()
        if garden_acl_enforced() and not _caller_sees_all_card_gardens(
            entity_uri, scope, identity, conn, now
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="no facts found for entity",
            )

        card = (
            refresh_card(entity_uri, scope, identity.tenant_id, conn)
            if refresh
            else get_fresh_card(entity_uri, scope, identity.tenant_id, conn)
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
