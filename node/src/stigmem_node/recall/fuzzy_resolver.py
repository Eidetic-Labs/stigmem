"""Fuzzy entity resolver — spec §2.6 Phase 6.

3-layer resolver:
  Layer 1: strict normalizer (entity_normalizer.py) — deterministic case + whitespace.
  Layer 2: explicit alias table lookup — user-defined semantic equivalences stored in
           entity_aliases (e.g. user:alice ≡ user:a.smith).
  Layer 3: passthrough — returns the Layer 1 result when no alias is registered.

The strict normalizer is stateless and import-time only; this module adds the
DB-backed Layer 2 on top and exposes helpers for alias registration / lookup.

Ingest contract: callers MUST apply normalize_entity_uri first, then call
resolve_entity with the already-normalized URI and an open connection. This
keeps the two concerns separable and avoids a second DB round-trip on the hot
normalization path when no alias table exists.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Any

from ..utility.entity_normalizer import NormalizationError, normalize_entity_uri


def resolve_entity(
    conn: sqlite3.Connection, normalized_uri: str, tenant_id: str = "default"
) -> str:
    """Layer 2 alias lookup. Input MUST already be Layer 1–normalized.

    Returns canonical_uri from the caller's tenant aliases if a registered alias
    exists, otherwise returns normalized_uri unchanged (Layer 3 passthrough).
    """
    row = conn.execute(
        "SELECT canonical_uri FROM entity_aliases WHERE raw_uri = ? AND tenant_id = ?",
        (normalized_uri, tenant_id),
    ).fetchone()
    return str(row["canonical_uri"]) if row else normalized_uri


def register_alias(
    conn: sqlite3.Connection,
    raw_uri: str,
    canonical_uri: str,
    *,
    kind: str = "user",
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Register or replace a semantic alias (raw_uri resolves to canonical_uri).

    Both URIs are Layer 1–normalized before storage so the caller need not
    pre-normalize them. The alias is scoped to ``tenant_id``. Raises ValueError
    on empty input or identical endpoints.

    Returns the stored alias record as a plain dict.
    """
    try:
        norm_raw = normalize_entity_uri(raw_uri)
        norm_canonical = normalize_entity_uri(canonical_uri)
    except NormalizationError as exc:
        raise ValueError(str(exc)) from exc

    if norm_raw == norm_canonical:
        raise ValueError(f"raw_uri and canonical_uri must differ after normalization: {norm_raw!r}")

    now = datetime.now(UTC).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO entity_aliases"
        " (raw_uri, canonical_uri, kind, created_at, tenant_id) VALUES (?, ?, ?, ?, ?)",
        (norm_raw, norm_canonical, kind, now, tenant_id),
    )
    return {
        "raw_uri": norm_raw,
        "canonical_uri": norm_canonical,
        "kind": kind,
        "created_at": now,
    }
