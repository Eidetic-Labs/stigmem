"""Fuzzy entity resolver — spec §2.6.6 (v0.8, Track F).

Three-layer resolution pipeline:

  Layer 1 — Canonical normalisation (entity_normalizer.py).
             Deterministic, idempotent. Collapses case/whitespace/hyphen variants.

  Layer 2 — Alias table lookup (entity_aliases, Migration 003).
             Explicit pre-registered mappings for known legacy URIs.

  Layer 3 — Token-fuzzy scoring over the live fact graph.
             For informal URIs (type:id) with the same type prefix, scores
             known entity candidates by token overlap and SequenceMatcher
             similarity on the id segment. Returns ranked candidates.
             Threshold: FUZZY_SCORE_THRESHOLD (default 0.5).

The full Kompl-style resolver (phonetic matching, NLP-based entity linking)
is deferred to Phase 7.  Layer 3 here covers the common cases:
  - Abbreviated names:  user:alice  ≡  user:a.smith  (partial token match)
  - Whitespace/hyphen:  user:alice-smith  ≡  user:alice_smith  (Layer 1)
  - Legacy aliases:     user:alice  →  user:a.smith  (Layer 2 explicit mapping)
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from ..utility.entity_normalizer import NormalizationError, normalize_entity_uri

_TOKEN_SPLIT_RE = re.compile(r"[.\-_/\s]+")
_FORMAL_PREFIX = "stigmem://"
FUZZY_SCORE_THRESHOLD = 0.5


@dataclass
class ResolveCandidate:
    uri: str
    score: float
    layer: int  # 1=canonical, 2=alias, 3=fuzzy
    match_note: str = ""


@dataclass
class ResolveResult:
    query: str
    canonical: str | None = None  # None if normalisation failed
    layer1_match: bool = False
    layer2_match: str | None = None  # alias target if found
    layer3_candidates: list[ResolveCandidate] = field(default_factory=list)

    @property
    def best(self) -> str | None:
        """Return the highest-confidence resolved URI, or None."""
        if self.layer2_match:
            return self.layer2_match
        if self.canonical and self.layer1_match:
            return self.canonical
        if self.layer3_candidates:
            return self.layer3_candidates[0].uri
        return self.canonical


def _tokenise(id_segment: str) -> list[str]:
    """Split an id segment into lowercase tokens."""
    return [t for t in _TOKEN_SPLIT_RE.split(id_segment.lower()) if t]


def _type_prefix(uri: str) -> str | None:
    """Extract 'type' from 'type:id' informal URIs. Returns None for formal or bare ids."""
    if uri.startswith(_FORMAL_PREFIX) or ":" not in uri:
        return None
    return uri.split(":", 1)[0]


def _id_segment(uri: str) -> str:
    """Extract the id part (after the type: prefix) for informal URIs."""
    if ":" in uri and not uri.startswith(_FORMAL_PREFIX):
        return uri.split(":", 1)[1]
    return uri


def _token_score(a_tokens: list[str], b_tokens: list[str]) -> float:
    """
    Similarity score [0, 1] between two token lists.

    Combines:
    - Jaccard overlap on full tokens
    - Initial/prefix match: token in a is a prefix of a token in b (covers a.smith ↔ alice)
    - Best SequenceMatcher ratio across all pair combinations
    """
    if not a_tokens or not b_tokens:
        return 0.0

    a_set = set(a_tokens)
    b_set = set(b_tokens)

    # Jaccard on exact tokens
    jaccard = len(a_set & b_set) / len(a_set | b_set)

    # Prefix/initial match: score +0.3 if any token in a is a prefix of any token in b
    prefix_bonus = 0.0
    for ta in a_tokens:
        for tb in b_tokens:
            if len(ta) >= 1 and tb.startswith(ta[0]):
                prefix_bonus = max(prefix_bonus, 0.3)
            if len(ta) > 1 and tb.startswith(ta[:2]):
                prefix_bonus = max(prefix_bonus, 0.5)

    # SequenceMatcher on concatenated id strings
    seq_score = SequenceMatcher(None, "".join(a_tokens), "".join(b_tokens)).ratio()

    return min(1.0, max(jaccard, prefix_bonus, seq_score))


def resolve_entity(
    raw: str,
    conn: sqlite3.Connection,
    *,
    tenant_id: str = "default",
    top_k: int = 5,
    threshold: float = FUZZY_SCORE_THRESHOLD,
) -> ResolveResult:
    """Resolve raw entity URI through 3 layers.

    Args:
        raw:       Raw entity URI string (may be non-canonical, aliased, or abbreviated).
        conn:      Open SQLite connection (read-only queries only).
        top_k:     Maximum Layer 3 candidates to return.
        threshold: Minimum fuzzy score to include in Layer 3 candidates.

    Returns:
        ResolveResult with layer-by-layer findings and a `.best` shorthand.
    """
    result = ResolveResult(query=raw)

    # -------------------------------------------------------------------
    # Layer 1 — canonical normalisation
    # -------------------------------------------------------------------
    try:
        canonical = normalize_entity_uri(raw)
    except NormalizationError:
        return result  # malformed input; no resolution possible

    result.canonical = canonical

    # Check if the canonical form itself appears in the fact graph.
    live_check = conn.execute(
        "SELECT 1 FROM facts WHERE entity = ? AND tenant_id = ? AND confidence > 0.0 LIMIT 1",
        (canonical, tenant_id),
    ).fetchone()
    if live_check:
        result.layer1_match = True
        return result  # exact hit; no further layers needed

    # -------------------------------------------------------------------
    # Layer 2 — alias table lookup
    # -------------------------------------------------------------------
    alias_row = conn.execute(
        "SELECT canonical_uri FROM entity_aliases WHERE raw_uri = ? AND tenant_id = ?",
        (canonical, tenant_id),
    ).fetchone()
    if alias_row is None:
        # Also try the raw input (pre-normalisation alias)
        alias_row = conn.execute(
            "SELECT canonical_uri FROM entity_aliases WHERE raw_uri = ? AND tenant_id = ?",
            (raw, tenant_id),
        ).fetchone()

    if alias_row:
        result.layer2_match = str(alias_row["canonical_uri"])
        return result  # explicit alias; authoritative

    # -------------------------------------------------------------------
    # Layer 3 — token-fuzzy scoring over same-type entities
    # -------------------------------------------------------------------
    type_prefix = _type_prefix(canonical)
    if type_prefix is None:
        # Formal or bare URIs: skip Layer 3 (no type-scoped candidates).
        return result

    id_seg = _id_segment(canonical)
    query_tokens = _tokenise(id_seg)
    if not query_tokens:
        return result

    # Fetch all distinct entity URIs with the same type prefix from the fact graph.
    # Escape LIKE metacharacters in the (caller-derived) type prefix so it cannot
    # inject wildcards into the scan (consistent with intents; audit F-2).
    safe_prefix = type_prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    prefix_pattern = f"{safe_prefix}:%"
    candidate_rows: list[Any] = conn.execute(
        """SELECT DISTINCT entity FROM facts
           WHERE entity LIKE ? ESCAPE '\\' AND tenant_id = ? AND confidence > 0.0
           LIMIT 2000""",
        (prefix_pattern, tenant_id),
    ).fetchall()

    scored: list[ResolveCandidate] = []
    for row in candidate_rows:
        candidate_uri: str = row["entity"]
        if candidate_uri == canonical:
            continue  # already checked in Layer 1

        cand_id_seg = _id_segment(candidate_uri)
        cand_tokens = _tokenise(cand_id_seg)
        score = _token_score(query_tokens, cand_tokens)

        if score >= threshold:
            scored.append(
                ResolveCandidate(
                    uri=candidate_uri,
                    score=score,
                    layer=3,
                    match_note=f"token_score={score:.2f} ({id_seg!r} ~ {cand_id_seg!r})",
                )
            )

    scored.sort(key=lambda c: c.score, reverse=True)
    result.layer3_candidates = scored[:top_k]
    return result
