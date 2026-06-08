"""Source ↔ identity attestation (P-INJ-1), graduated to core.

A fact's ``source`` is *attested* when it matches the principal writing it. By
default mismatches are flagged (``attested=False``) but allowed; with
``settings.source_attestation_enforce`` they are rejected at write. This closes
"any write key can forge any source" while making the attributable-memory claim
true: forged sources are always detectable, even when not blocked.

Delegated source entities (writing as a source other than yourself) are a
deferred surface (§18); ``authorized_source_entities`` already reads the
``allowed_source_entities`` identity field so the delegation hook lands cleanly.
"""

from __future__ import annotations

from typing import Any

from .entity_normalizer import NormalizationError, normalize_entity_uri


def _live_settings() -> Any:
    import sys

    return sys.modules["stigmem_node.settings"].settings


def _normalized_or_none(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    try:
        return normalize_entity_uri(raw)
    except NormalizationError:
        return None


def authorized_source_entities(identity: Any) -> set[str]:
    """Normalized set of source entities the principal may attest to."""
    raw = {getattr(identity, "entity_uri", None)}
    raw.update(getattr(identity, "allowed_source_entities", ()) or ())  # §18 delegation
    return {n for r in raw if (n := _normalized_or_none(r)) is not None}


def evaluate_source_attested(source: Any, identity: Any) -> bool | None:
    """Return whether *source* is attested to the writing *identity*.

    ``None`` when there is no authenticated principal (anonymous / auth-disabled
    mode) — attestation is meaningless without a real writer. Otherwise True when
    the normalized source matches the principal (or a delegated source), else False.
    """
    if not _live_settings().auth_required:
        return None
    normalized = _normalized_or_none(source)
    return normalized is not None and normalized in authorized_source_entities(identity)


def source_attestation_enforce_enabled() -> bool:
    """Return True when an unattested source must be rejected (default off)."""
    return bool(_live_settings().source_attestation_enforce)
