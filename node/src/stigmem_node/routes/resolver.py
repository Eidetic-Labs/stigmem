"""Entity resolver route — spec §2.6.6 (v0.8).

GET /v1/entities/resolve?uri=<raw>&top_k=<int>&threshold=<float>

Three-layer entity resolution:
  Layer 1 — canonical normalisation (deterministic)
  Layer 2 — alias table lookup (entity_aliases)
  Layer 3 — token-fuzzy scoring over live fact graph (same-type prefix)

Returns the best resolved URI and scored candidates.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ..auth import Identity, resolve_identity
from ..db import db
from ..recall.entity_resolver import FUZZY_SCORE_THRESHOLD, resolve_entity

router = APIRouter(prefix="/v1/entities", tags=["entities"])


@router.get("/resolve")
def resolve_entity_uri(
    identity: Annotated[Identity, Depends(resolve_identity)],
    uri: str = Query(..., description="Raw entity URI to resolve"),
    top_k: int = Query(5, ge=1, le=20, description="Max Layer 3 fuzzy candidates to return"),
    threshold: float = Query(
        FUZZY_SCORE_THRESHOLD,
        ge=0.0,
        le=1.0,
        description="Minimum fuzzy score threshold for Layer 3 candidates",
    ),
) -> dict[str, Any]:
    """Resolve a raw entity URI using 3-layer fuzzy resolution (Spec-01-Fact-Model).

    Layer 1: canonical normalisation (case/whitespace collapse).
    Layer 2: alias table lookup (explicit pre-registered mappings).
    Layer 3: token-fuzzy scoring over entities of the same type prefix in the fact graph.

    Returns the best resolved URI and scored candidates with match details.
    """
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")

    with db() as conn:
        result = resolve_entity(
            uri, conn, tenant_id=identity.tenant_id, top_k=top_k, threshold=threshold
        )

    return {
        "query": result.query,
        "canonical": result.canonical,
        "best": result.best,
        "resolution_layer": (
            1
            if result.layer1_match
            else 2
            if result.layer2_match
            else 3
            if result.layer3_candidates
            else None
        ),
        "layer1_match": result.layer1_match,
        "layer2_match": result.layer2_match,
        "layer3_candidates": [
            {
                "uri": c.uri,
                "score": round(c.score, 4),
                "match_note": c.match_note,
            }
            for c in result.layer3_candidates
        ],
    }
