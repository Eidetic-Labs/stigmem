"""Recall route orchestration."""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from ...auth import Identity, resolve_identity
from ...card_materializer import CARD_MIN_CONFIDENCE, get_fresh_card
from ...db import db
from ...garden_acl import caller_can_see_garden
from ...lifecycle.tombstone_cache import is_tombstoned as _is_tombstoned
from ...memory_garden_acl_gate import recall_filter_enabled
from ...metrics import FACT_READ, RECALL_RANKER_DURATION, observe_duration
from ...models.constants import VALID_SCOPES
from ...models.facts import FactRecord, FactValue
from ...models.recall import (
    FactChainProof,
    RecallRequest,
    RecallResponse,
    ScoreBreakdown,
    ScoredFact,
)
from ...plugins import get_registry
from ...recall.graph import MAX_DEPTH
from ...recall.recall_pipeline import apply_recall_pipeline
from ...session_graph import record_read_scopes
from ...tracing import start_span
from ..time_travel_gate import require_time_travel_enabled
from .as_of import _recall_as_of_impl
from .common import (
    _estimate_tokens,
    _fetch_facts_by_ids,
    _now_iso,
    _write_recall_audit,
    logger,
    router,
)
from .graph import _MAX_SEED_ENTITIES, _graph_expand
from .lexical import _lexical_search
from .ranking import _filter_visible_gardens, _greedy_pack, _score_candidates
from .vector import _semantic_search

_MAX_CANDIDATES = 500
@router.post("", response_model=RecallResponse)
def recall(
    req: RecallRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
    response: Response,
    session_id: Annotated[str | None, Header(alias="Stigmem-Session")] = None,
    verify_mode: Annotated[str | None, Header(alias="Stigmem-Verify")] = None,
    legacy_format: Annotated[
        bool,
        Query(
            description=(
                "Return the temporary legacy recall response shape without "
                "`content` / `instructions` channel fields."
            )
        ),
    ] = False,
) -> RecallResponse | JSONResponse:
    """Hybrid recall — return the most salient facts for a query, within budget.

    Combines lexical (FTS5/BM25), dense-vector, and graph-traversal signals.
    Honors Spec-02-Scopes-and-ACL and Spec-05-Federation-Trust at every step.
    """
    with start_span(
        "stigmem.recall",
        **{
            "stigmem.tenant": identity.tenant_id,
            "stigmem.principal": identity.entity_uri,
            "stigmem.scope": req.scope,
        },
    ) as _span:
        result = _recall_impl(
            req,
            identity,
            _span,
            session_id=session_id,
            verify_full=verify_mode == "full",
        )
    headers = {}
    if result.total_scored is not None:
        headers["X-Total-Count"] = str(result.total_scored)
        response.headers["X-Total-Count"] = headers["X-Total-Count"]
    if legacy_format:
        return JSONResponse(content=_legacy_recall_payload(result), headers=headers)
    return result


def _legacy_recall_payload(result: RecallResponse) -> dict[str, Any]:
    """Return the one-minor-version compatibility shape for pre-channel clients."""
    return result.model_dump(mode="json", exclude={"content", "instructions"})


def _split_interpretation_channels(
    packed: list[ScoredFact],
) -> tuple[list[ScoredFact], list[ScoredFact]]:
    content = [scored for scored in packed if scored.fact.value.interpret_as != "instruction"]
    instructions = [scored for scored in packed if scored.fact.value.interpret_as == "instruction"]
    return content, instructions


def _validate_recall_request(req: RecallRequest, identity: Identity) -> None:
    """Auth + scope + depth validation. Raises HTTPException on failure."""
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )
    FACT_READ.labels(principal=identity.entity_uri, tenant=identity.tenant_id).inc()
    if req.scope not in VALID_SCOPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_scope: must be one of {sorted(VALID_SCOPES)}",
        )
    if req.depth > MAX_DEPTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "graph_depth_exceeded", "message": f"depth must be ≤ {MAX_DEPTH}"},
        )


def _chain_proof_or_409(conn: Any, tenant_id: str) -> FactChainProof:
    from ...fact_chain import FactChainIntegrityError, build_fact_chain_proof

    try:
        return FactChainProof(**build_fact_chain_proof(conn, tenant_id=tenant_id))
    except FactChainIntegrityError as exc:
        result = exc.result
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "fact_chain_mismatch",
                "message": "local fact hash chain verification failed",
                "mismatch_reason": result.mismatch_reason,
                "fact_id": result.fact_id,
                "chain_seq": result.chain_seq,
            },
        ) from exc


def _handle_as_of_recall(
    req: RecallRequest,
    identity: Identity,
    *,
    verify_full: bool = False,
) -> RecallResponse:
    """§24 time-travel path. Validates as_of, runs the as_of impl, returns the response."""
    from ..facts import _validate_as_of

    require_time_travel_enabled(get_registry(), surface="recall")
    _validate_as_of(req.as_of)  # type: ignore[arg-type]  # caller guarantees as_of is not None
    recall_id = str(uuid.uuid4())
    query_hash = hashlib.sha256(req.query.encode()).hexdigest()
    with db() as conn:
        packed, notices, tombstone_filtered = _recall_as_of_impl(
            conn,
            query=req.query,
            scope=req.scope,
            as_of=req.as_of,  # type: ignore[arg-type]
            is_admin_caller=identity.is_admin(),
            tenant_id=identity.tenant_id,
            max_chunks=req.limit,
            include_graph=req.include_neighbors,
            identity=identity,
            weights=req.weights,
            depth=req.depth,
        )
        chain_proof = _chain_proof_or_409(conn, identity.tenant_id) if verify_full else None
    tokens_used = sum(sf.token_estimate for sf in packed)
    content, instructions = _split_interpretation_channels(packed)
    return RecallResponse(
        recall_id=recall_id,
        query_hash=query_hash,
        facts=packed,
        content=content,
        instructions=instructions,
        # §23.3.3 r.3: suppress total_scored when tombstone filtering was applied
        total_scored=None if tombstone_filtered else len(packed),
        token_budget=req.token_budget,
        tokens_used=tokens_used,
        truncated=False,
        tombstone_notices=notices,
        chain_proof=chain_proof,
    )


def _gather_direct_matches(
    conn: Any,
    req: RecallRequest,
    identity: Identity,
    now: str,
) -> tuple[dict[str, float], dict[str, float]]:
    """Run the lexical + semantic searches that produce direct-match scores."""
    lex_scores = (
        _lexical_search(
            conn,
            req.query,
            req.scope,
            identity.tenant_id,
            req.limit,
            req.min_confidence,
            now,
        )
        if req.weights.lexical > 0
        else {}
    )
    sem_scores = (
        _semantic_search(conn, req.query, req.scope, identity.tenant_id, req.limit)
        if req.weights.semantic > 0
        else {}
    )
    return lex_scores, sem_scores


def _expand_graph_neighbours(
    conn: Any,
    req: RecallRequest,
    identity: Identity,
    direct_ids: set[str],
    lex_scores: dict[str, float],
    sem_scores: dict[str, float],
    now: str,
) -> dict[str, int]:
    """Optionally BFS from the top direct-match seeds. Returns {fact_id: hop_distance}."""
    if not (req.include_neighbors and req.weights.graph > 0 and direct_ids):
        return {}
    top_seeds = sorted(
        direct_ids,
        key=lambda fid: lex_scores.get(fid, 0) + sem_scores.get(fid, 0),
        reverse=True,
    )[:_MAX_SEED_ENTITIES]
    return _graph_expand(
        conn,
        top_seeds,
        req.depth,
        req.scope,
        identity.tenant_id,
        identity,
        req.limit,
        req.min_confidence,
        now,
    )


def _caller_sees_all_card_gardens(
    entity_uri: str, scope: str, identity: Identity, conn: Any, now: str
) -> bool:
    """True if the caller may see every garden contributing to this entity's card.

    The card summary aggregates an entity's fact values verbatim and bypasses the
    ranker's per-fact garden ACL, so the card must not be served when any
    contributing fact lives in a garden the caller cannot see (audit H1).
    """
    rows = conn.execute(
        "SELECT DISTINCT garden_id FROM facts"
        " WHERE entity = ? AND scope = ? AND tenant_id = ?"
        "   AND confidence > 0"
        "   AND (valid_until IS NULL OR valid_until > ?)"
        "   AND (quarantine_status IS NULL OR quarantine_status != 'pending')"
        "   AND garden_id IS NOT NULL",
        (entity_uri, scope, identity.tenant_id, now),
    ).fetchall()
    return all(caller_can_see_garden(row["garden_id"], identity) for row in rows)


def _build_card_for_entity(
    entity_uri: str,
    entity_fact_ids: list[str],
    req: RecallRequest,
    identity: Identity,
    conn: Any,
    now: str,
) -> tuple[ScoredFact, list[str]] | None:
    """Try to build a synthetic ScoredFact from a fresh, high-confidence card.

    Returns (scored_fact, owned_fact_ids) on success, None when no card qualifies.
    """
    if _is_tombstoned(entity_uri, identity.tenant_id):
        # §23.3.2 r.3: cards whose about_entity is tombstoned are fully excluded.
        return None
    # Garden ACL (audit H1): the card path bypasses the ranker's per-fact ACL,
    # so a non-member must not receive a card aggregated from a garden's facts.
    if recall_filter_enabled() and not _caller_sees_all_card_gardens(
        entity_uri, req.scope, identity, conn, now
    ):
        return None
    card = get_fresh_card(entity_uri, req.scope, identity.tenant_id, conn)
    if (
        card is None
        or card.is_stale
        or card.has_contradictions
        or card.avg_confidence < CARD_MIN_CONFIDENCE
    ):
        return None
    card_record = FactRecord(
        id=f"card:{entity_uri}",
        entity=entity_uri,
        relation="stigmem:card:summary",
        value=FactValue(type="text", v=card.summary),
        source="system:stigmem:materializer",
        timestamp=card.refreshed_at or now,
        confidence=card.avg_confidence,
        scope=req.scope,
    )
    sf = ScoredFact(
        fact=card_record,
        score=round(card.avg_confidence, 6),
        score_breakdown=ScoreBreakdown(
            source_trust=round(card.avg_confidence, 4),
            weighted_total=round(card.avg_confidence, 6),
        ),
        hop_distance=0,
        token_estimate=_estimate_tokens(card_record),
        from_card=True,
    )
    return sf, list(entity_fact_ids)


def _try_card_fast_path(
    all_facts_raw: dict[str, FactRecord],
    req: RecallRequest,
    identity: Identity,
    conn: Any,
    now: str,
) -> tuple[list[ScoredFact], set[str]]:
    """Build card-derived ScoredFacts for any candidate entity that has a fresh card.

    Returns (card_facts, card_owned_fact_ids). Logs and returns ([], set()) on any error
    so the recall path can fall through to raw-fact scoring.
    """
    card_facts: list[ScoredFact] = []
    card_entity_ids: set[str] = set()
    try:
        candidate_entities: dict[str, list[str]] = {}
        for fid, record in all_facts_raw.items():
            candidate_entities.setdefault(record.entity, []).append(fid)
        for entity_uri, entity_fact_ids in candidate_entities.items():
            built = _build_card_for_entity(entity_uri, entity_fact_ids, req, identity, conn, now)
            if built is not None:
                sf, owned = built
                card_facts.append(sf)
                card_entity_ids.update(owned)
    except Exception as _card_exc:
        logger.warning("card fast-path error (falling through to raw facts): %s", _card_exc)
        return [], set()
    return card_facts, card_entity_ids


def _exclude_card_owned(
    card_entity_ids: set[str],
    all_facts_raw: dict[str, FactRecord],
    lex_scores: dict[str, float],
    sem_scores: dict[str, float],
    graph_hops: dict[str, int],
) -> tuple[dict[str, FactRecord], dict[str, float], dict[str, float], dict[str, int]]:
    """Drop any fact_id owned by a card-served entity from all four scoring inputs.

    No-op when ``card_entity_ids`` is empty.
    """
    if not card_entity_ids:
        return all_facts_raw, lex_scores, sem_scores, graph_hops
    return (
        {k: v for k, v in all_facts_raw.items() if k not in card_entity_ids},
        {k: v for k, v in lex_scores.items() if k not in card_entity_ids},
        {k: v for k, v in sem_scores.items() if k not in card_entity_ids},
        {k: v for k, v in graph_hops.items() if k not in card_entity_ids},
    )


def _set_recall_span_attrs(
    span: object,
    recall_id: str,
    total_scored: int,
    tokens_used: int,
    truncated: bool,
) -> None:
    """Best-effort: attach recall outcome attributes to the OTel span."""
    try:
        span.set_attribute("stigmem.recall_id", recall_id)  # type: ignore[attr-defined]
        span.set_attribute("stigmem.total_scored", total_scored)  # type: ignore[attr-defined]
        span.set_attribute("stigmem.tokens_used", tokens_used)  # type: ignore[attr-defined]
        span.set_attribute("stigmem.truncated", truncated)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001  # nosec B110 — span attrs best-effort
        logger.debug("recall span attribute set failed: %s", exc)


def _recall_impl(
    req: RecallRequest,
    identity: Identity,
    _span: object,
    *,
    session_id: str | None = None,
    verify_full: bool = False,
) -> RecallResponse:
    _validate_recall_request(req, identity)

    if req.as_of is not None:
        result = _handle_as_of_recall(req, identity, verify_full=verify_full)
        with db() as conn:
            record_read_scopes(
                conn,
                identity=identity,
                session_id=session_id,
                scopes={scored.fact.scope for scored in result.facts},
            )
        return result

    recall_id = str(uuid.uuid4())
    query_hash = hashlib.sha256(req.query.encode()).hexdigest()
    now = _now_iso()

    logger.info(
        "recall id=%s entity=%s query_hash=%s scope=%s budget=%d",
        recall_id,
        identity.entity_uri,
        query_hash[:12],
        req.scope,
        req.token_budget,
    )

    with db() as conn:
        lex_scores, sem_scores = _gather_direct_matches(conn, req, identity, now)
        direct_ids = set(lex_scores) | set(sem_scores)

        graph_hops = _expand_graph_neighbours(
            conn,
            req,
            identity,
            direct_ids,
            lex_scores,
            sem_scores,
            now,
        )
        # Direct matches have hop_distance=0 (mark in graph_hops)
        for fid in direct_ids:
            if fid not in graph_hops:
                graph_hops[fid] = 0

        # --- Fetch all candidate facts ---
        all_candidate_ids = list(direct_ids | set(graph_hops.keys()))[:_MAX_CANDIDATES]
        all_facts_raw = _fetch_facts_by_ids(conn, all_candidate_ids)

        # §23.3.2 r.3: exclude facts whose entity has an active tombstone (about_entity).
        # Uses in-process cache (§23.3.3 r.4) — no per-fact DB read required.
        pre_tombstone_count = len(all_facts_raw)
        all_facts_raw = {
            k: v
            for k, v in all_facts_raw.items()
            if not _is_tombstoned(v.entity, identity.tenant_id)
        }
        tombstone_filtered = len(all_facts_raw) < pre_tombstone_count

        # Garden ACL on the shared candidate set (audit M3): drop facts whose
        # garden the caller cannot see BEFORE the card fast-path and the ranker
        # consume them, so the per-record garden check (§17 ranker) is a
        # redundant backstop rather than the sole gate.
        all_facts_raw = _filter_visible_gardens(all_facts_raw, identity)

        # --- Card fast-path (§20) ---
        card_facts, card_entity_ids = _try_card_fast_path(
            all_facts_raw,
            req,
            identity,
            conn,
            now,
        )
        all_facts_raw, lex_scores, sem_scores, graph_hops = _exclude_card_owned(
            card_entity_ids,
            all_facts_raw,
            lex_scores,
            sem_scores,
            graph_hops,
        )

        # Apply §19 recall pipeline (source-trust multiplier + content sanitiser)
        all_facts = {r.id: r for r in apply_recall_pipeline(list(all_facts_raw.values()), identity)}

        # --- Score (timed for ranker histogram) ---
        with observe_duration(RECALL_RANKER_DURATION, {"tenant": identity.tenant_id}):
            candidates = _score_candidates(
                all_facts,
                lex_scores,
                sem_scores,
                graph_hops,
                req.weights,
                identity,
                req.depth,
            )
        candidates.extend(card_facts)
        total_scored = len(candidates)

        # --- Token-budget packing ---
        packed, tokens_used, truncated = _greedy_pack(candidates, req.token_budget)

        # --- Audit ---
        _write_recall_audit(
            conn,
            recall_id,
            identity,
            query_hash,
            req.scope,
            req.token_budget,
            len(packed),
            tokens_used,
            truncated,
        )
        record_read_scopes(
            conn,
            identity=identity,
            session_id=session_id,
            scopes={scored.fact.scope for scored in packed},
        )
        chain_proof = _chain_proof_or_409(conn, identity.tenant_id) if verify_full else None

    logger.info(
        "recall id=%s scored=%d packed=%d tokens=%d truncated=%s",
        recall_id,
        total_scored,
        len(packed),
        tokens_used,
        truncated,
    )

    _set_recall_span_attrs(_span, recall_id, total_scored, tokens_used, truncated)

    # §23.3.3 r.3: suppress total_scored when tombstone filtering was applied
    content, instructions = _split_interpretation_channels(packed)
    return RecallResponse(
        recall_id=recall_id,
        query_hash=query_hash,
        facts=packed,
        content=content,
        instructions=instructions,
        total_scored=None if tombstone_filtered else total_scored,
        token_budget=req.token_budget,
        tokens_used=tokens_used,
        truncated=truncated,
        chain_proof=chain_proof,
    )
