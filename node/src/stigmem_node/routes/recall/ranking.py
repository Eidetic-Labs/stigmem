"""Recall scoring and packing stages."""

from __future__ import annotations

from ...auth import Identity
from ...memory_garden_acl_gate import caller_visible_gardens, garden_acl_enforced
from ...models.facts import FactRecord
from ...models.recall import RecallWeights, ScoreBreakdown, ScoredFact
from ...plugins import get_registry
from .common import _estimate_tokens, _recency_score


def _filter_visible_gardens(
    facts: dict[str, FactRecord], identity: Identity
) -> dict[str, FactRecord]:
    """Drop facts whose garden the caller cannot see (audit M3, defense-in-depth).

    Applied to the candidate set of EVERY recall path (live and time-travel/as_of)
    so the per-record garden check is a redundant backstop rather than the sole
    gate. Uses the projected ``record.garden_id`` (consistent with the ranker) and
    a single batched membership lookup. No-op only when the boundary is not
    enforced (``garden_acl_enforced`` is fail-closed: it stays on once gardens
    exist, regardless of the operator flag).
    """
    if not garden_acl_enforced():
        return facts
    visible = caller_visible_gardens(identity)
    return {
        k: v
        for k, v in facts.items()
        if v.garden_id is None or v.garden_id in visible
    }


def _score_candidates(
    all_facts: dict[str, FactRecord],
    lex_scores: dict[str, float],
    sem_scores: dict[str, float],
    graph_hops: dict[str, int],
    weights: RecallWeights,
    identity: Identity,
    depth: int,
) -> list[ScoredFact]:
    """Compute composite score for each candidate fact."""
    w = weights
    total_weight = w.lexical + w.semantic + w.graph + w.recency
    if total_weight <= 0:
        total_weight = 1.0

    results: list[ScoredFact] = []

    # Garden ACL: resolve enforcement + the caller's visible gardens ONCE, then
    # filter in-memory per fact (batched, audit M3 secure-path). This is a
    # redundant backstop — the candidate set is pre-filtered by
    # _filter_visible_gardens — but it keeps the ranker self-defending.
    enforce_gardens = garden_acl_enforced()
    visible_gardens = caller_visible_gardens(identity) if enforce_gardens else frozenset()

    for fact_id, record in all_facts.items():
        # Skip quarantined / fully-redacted
        if record.quarantine_status == "pending":
            continue

        # Salience signal: contradiction-resolution status
        contradiction_factor = 0.1 if record.contradicted else 1.0

        # Salience signal: garden tier (quarantine garden = 0, normal = 1)
        garden_factor = 1.0
        if enforce_gardens and record.garden_id is not None:
            if record.garden_id not in visible_gardens:
                continue  # hidden by ACL
            # Penalise quarantine-tagged gardens (§17)
            garden_factor = 0.5

        # Source-trust rank contribution is plugin-owned. Default installs keep
        # this salience signal at 0 and can receive deltas from recall_rank.
        st_score = 0.0

        # Lexical signal
        lex = lex_scores.get(fact_id, 0.0)

        # Semantic signal
        sem = sem_scores.get(fact_id, 0.0)

        # Graph signal: inverse of hop distance (direct=0 → no graph bonus, 1 hop → 0.5, etc.)
        hops = graph_hops.get(fact_id)
        if hops is not None and hops > 0:
            graph_s = 1.0 / (1.0 + hops)
        else:
            graph_s = 0.0 if hops is None else 1.0

        # Salience signal: recency
        recency_s = _recency_score(record.timestamp)

        # Salience signal: decay proxy (confidence itself encodes decay)
        decay_factor = max(0.0, record.confidence)

        # Weighted sum (normalised by sum of non-zero weights)
        raw_total = (
            w.lexical * lex
            + w.semantic * sem
            + w.graph * graph_s
            + w.recency * recency_s
        ) / total_weight

        # Apply multiplicative adjustments
        final_score = raw_total * decay_factor * contradiction_factor * garden_factor

        breakdown = ScoreBreakdown(
            lexical=round(lex, 4),
            semantic=round(sem, 4),
            graph=round(graph_s, 4),
            source_trust=round(st_score, 4),
            recency=round(recency_s, 4),
            weighted_total=round(final_score, 6),
        )

        results.append(
            ScoredFact(
                fact=record,
                score=round(final_score, 6),
                score_breakdown=breakdown,
                hop_distance=hops if hops is not None else 0,
                token_estimate=_estimate_tokens(record),
            )
        )

    source_deltas = get_registry().fire_score_delta(
        "recall_rank",
        results,
        identity=identity,
        weights=weights,
        depth=depth,
    )
    if source_deltas:
        adjusted: list[ScoredFact] = []
        for scored in results:
            delta = source_deltas.get(scored.fact.id, 0.0)
            if delta == 0.0:
                adjusted.append(scored)
                continue
            next_score = round(max(0.0, scored.score + delta), 6)
            adjusted.append(
                scored.model_copy(
                    update={
                        "score": next_score,
                        "score_breakdown": scored.score_breakdown.model_copy(
                            update={"weighted_total": next_score}
                        ),
                    }
                )
            )
        results = adjusted

    return results


# ---------------------------------------------------------------------------
# Token-budget greedy packing
# ---------------------------------------------------------------------------


def _greedy_pack(
    candidates: list[ScoredFact],
    token_budget: int,
) -> tuple[list[ScoredFact], int, bool]:
    """Sort by score desc; include facts until budget exhausted.

    Returns (packed_facts, tokens_used, truncated).
    """
    candidates.sort(key=lambda c: c.score, reverse=True)
    packed: list[ScoredFact] = []
    tokens_used = 0
    truncated = False

    for candidate in candidates:
        if tokens_used + candidate.token_estimate > token_budget:
            truncated = True
            continue  # skip this fact (too large), keep trying smaller ones
        packed.append(candidate)
        tokens_used += candidate.token_estimate

    # Secondary sort within packed: preserve score order
    packed.sort(key=lambda c: c.score, reverse=True)
    return packed, tokens_used, truncated
