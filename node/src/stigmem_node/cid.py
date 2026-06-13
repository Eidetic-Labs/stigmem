"""Content-addressed fact IDs — spec §25 (CID v2).

CID = "sha256:" + hex_lowercase(SHA-256(canonical_fact_body))

Canonicalization is **sorted-key compact ``json.dumps``**, NOT full RFC 8785
(JCS). Concretely the canonical body is serialized with
``json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)``
and UTF-8 encoded. This gives deterministic key ordering and no insignificant
whitespace, but does NOT apply RFC 8785's number canonicalization or Unicode
normalization. Producers and verifiers MUST use this same serialization (see
``compute_cid``); the documented field set below is what makes it stable.

**CID v2 (breaking change, 2026-06-06).** The canonical body is a JSON object
with exactly 8 fields in lexicographic key order:
  confidence, entity, interpret_as, relation, scope, source, value_type, value_v

`interpret_as` is now bound (per ADR-003 / threat R-23): flipping a fact's
interpretation between `content` and `instruction` changes the CID, so it is
detected on the read path. **v1 CIDs (which omitted `interpret_as`) are NOT
accepted** — pre-v2 facts must be upgraded via the CID backfill migration;
until migrated they fail read-path verification (409 cid_mismatch).

Security-relevant excluded fields (§25.2.1 rev 15):
  valid_until, derived_from, attestation_chain, source_trust, signature, reason
  (these require independent validation; CID coverage alone is not sufficient)

fact_id and cid are also excluded (circular).
timestamp/created_at is excluded so the same assertion at different times shares one CID.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

_CID_PREFIX = "sha256:"
_CID_HEX_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def compute_cid(
    entity: str,
    relation: str,
    value_type: str,
    value_v: str,
    source: str,
    scope: str,
    confidence: float = 1.0,
    interpret_as: str = "content",
) -> str:
    """Return the CID v2 for a fact's canonical body (spec §25.2.1, §25.2.2).

    `interpret_as` is part of the canonical body (CID v2); a flip between
    `content` and `instruction` produces a different CID.
    """
    body: dict[str, Any] = {
        "confidence": confidence,
        "entity": entity,
        "interpret_as": interpret_as,
        "relation": relation,
        "scope": scope,
        "source": source,
        "value_type": value_type,
        "value_v": value_v,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    digest = hashlib.sha256(canonical).hexdigest()
    return f"{_CID_PREFIX}{digest}"


def compute_cid_from_row(row: Any) -> str:
    """Convenience wrapper: compute CID from a facts-table row."""
    return compute_cid(
        entity=row["entity"],
        relation=row["relation"],
        value_type=row["value_type"],
        value_v=row["value_v"] or "",
        source=row["source"],
        scope=row["scope"],
        confidence=float(row["confidence"]),
        interpret_as=(_optional_row_value(row, "interpret_as") or "content"),
    )


class CidMismatchError(ValueError):
    """Raised when a stored fact CID does not match its canonical body."""

    def __init__(self, *, fact_id: str, stored_cid: str, computed_cid: str) -> None:
        super().__init__(f"CID mismatch for fact {fact_id}")
        self.fact_id = fact_id
        self.stored_cid = stored_cid
        self.computed_cid = computed_cid


def _optional_row_value(row: Any, key: str) -> Any:
    try:
        keys = row.keys()
    except AttributeError:
        return row.get(key) if isinstance(row, dict) else None
    return row[key] if key in keys else None


def stored_cid_from_row(row: Any) -> str | None:
    """Return the stored/projected CID for a fact row, if one is present."""
    projected = _optional_row_value(row, "projected_cid")
    if projected is not None:
        return str(projected)
    stored = _optional_row_value(row, "cid")
    return None if stored is None else str(stored)


def verify_cid_from_row(row: Any) -> None:
    """Verify a fact row's stored CID, preserving legacy NULL-CID rows."""
    stored = stored_cid_from_row(row)
    if stored is None:
        return
    computed = compute_cid_from_row(row)
    if computed != stored:
        raise CidMismatchError(
            fact_id=str(row["id"]),
            stored_cid=stored,
            computed_cid=computed,
        )


def is_valid_cid(s: str) -> bool:
    """Return True if *s* looks like a well-formed sha256 CID (spec §25.2)."""
    return bool(_CID_HEX_RE.match(s))


def is_cid(s: str) -> bool:
    """Return True if *s* starts with the sha256: prefix (quick pre-filter)."""
    return s.startswith(_CID_PREFIX)
