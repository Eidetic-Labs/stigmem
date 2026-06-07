"""Fact value, request, response, and row conversion models."""

from __future__ import annotations

import sqlite3
from typing import Any

from pydantic import BaseModel, Field, field_validator

from .constants import VALID_SCOPES, VALID_VALUE_TYPES
from .tombstones import TombstoneNotice

VALID_WRITE_MODES = {"assert", "summarize_with_provenance"}
VALID_INTERPRET_AS = {"content", "instruction"}


class FactValue(BaseModel):
    type: str
    v: Any = None
    interpret_as: str = Field(
        "content",
        description="How the value may be interpreted by recall consumers.",
    )

    @field_validator("type")
    @classmethod
    def check_type(cls, t: str) -> str:
        if t not in VALID_VALUE_TYPES:
            raise ValueError(f"type must be one of {VALID_VALUE_TYPES}")
        return t

    @field_validator("interpret_as")
    @classmethod
    def check_interpret_as(cls, mode: str) -> str:
        if mode not in VALID_INTERPRET_AS:
            raise ValueError(f"interpret_as must be one of {sorted(VALID_INTERPRET_AS)}")
        return mode


class AttestationToken(BaseModel):
    """Ed25519 attestation proving the caller owns the registered agent key.

    The signature covers the canonical UTF-8 message:
        "{entity}\\n{relation}\\n{value.type}\\n{encoded_v}\\n{source}"
    where encoded_v is the same string the node derives via _encode_v().
    """

    key_id: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1, description="base64url-encoded Ed25519 signature")


class AssertRequest(BaseModel):
    entity: str = Field(..., min_length=1, max_length=2048)
    relation: str = Field(..., min_length=1, max_length=2048)
    value: FactValue
    source: str = Field(..., min_length=1, max_length=2048)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    scope: str = Field("local")
    valid_until: str | None = Field(None, description="ISO 8601 UTC expiry; null = non-expiring")
    attestation: AttestationToken | None = Field(
        None,
        description="Optional Ed25519 attestation; required when STIGMEM_ATTESTATION_REQUIRED=true",
    )
    garden_id: str | None = Field(
        None,
        description="URI of the garden this fact belongs to (Spec-02-Scopes-and-ACL)",
    )
    write_mode: str = Field(
        "assert",
        description="Write mode; summarize_with_provenance carries read-derived provenance.",
    )
    derived_from: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Source fact hashes/ids used for provenance-carrying summary writes.",
    )

    @field_validator("scope")
    @classmethod
    def check_scope(cls, s: str) -> str:
        if s not in VALID_SCOPES:
            raise ValueError(f"scope must be one of {VALID_SCOPES}")
        return s

    @field_validator("write_mode")
    @classmethod
    def check_write_mode(cls, mode: str) -> str:
        if mode not in VALID_WRITE_MODES:
            raise ValueError(f"write_mode must be one of {sorted(VALID_WRITE_MODES)}")
        return mode


class FactRecord(BaseModel):
    id: str
    entity: str
    relation: str
    value: FactValue
    source: str
    timestamp: str
    hlc: str | None = None  # v0.5: HLC timestamp; null for pre-migration facts
    received_from: str | None = None  # v0.5: originating node_id if federated
    valid_until: str | None = None
    confidence: float
    scope: str
    attested_key_id: str | None = None  # v1.0: agent key that attested this assertion
    origin_node_id: str | None = None  # v0.8: original assertor node_id (§6.8.1)
    origin_allowed_scopes: list[str] | None = None  # v0.8: scopes permitted at origin (§6.8.1)
    garden_id: str | None = None  # v0.9: garden URI; null = no garden
    attested: bool | None = None  # v0.9: source attestation result; null = not applicable
    contradicted: bool = False
    # write-time convention warnings (assert only)
    warnings: list[str] = Field(default_factory=list)
    # v1.1: source-trust snapshot (§19.4); recomputed live at recall — stored is audit only
    source_trust: float | None = None
    # v1.1: quarantine metadata (§19.5)
    quarantine_status: str | None = None
    quarantine_garden_id: str | None = None
    # v1.1: recall-time computed fields — not stored; populated by recall pipeline
    effective_confidence: float | None = None
    sanitizer_warnings: list[str] = Field(default_factory=list)
    sanitizer_redacted: bool = False
    # Phase 13: content-addressing (spec §25)
    cid: str | None = None
    # R-21: provenance for summary writes derived from recalled/read facts
    derived_from: list[dict[str, Any]] = Field(default_factory=list)


class QueryResponse(BaseModel):
    facts: list[FactRecord]
    total: int | None = None
    cursor: str | None
    tombstone_notices: list[TombstoneNotice] = Field(default_factory=list)

def _optional_col(row: sqlite3.Row, col: str, keys: Any) -> Any:
    """Return row[col] if column is in the result set, else None."""
    return row[col] if col in keys else None


def row_to_record(
    row: sqlite3.Row,
    contradicted: bool = False,
    warnings: list[str] | None = None,
    effective_confidence: float | None = None,
    sanitizer_warnings: list[str] | None = None,
    sanitizer_redacted: bool = False,
) -> FactRecord:
    import json as _json

    keys = row.keys()
    attested_raw = _optional_col(row, "attested", keys)
    attested: bool | None = None if attested_raw is None else bool(attested_raw)
    raw_scopes = _optional_col(row, "origin_allowed_scopes", keys)
    origin_allowed_scopes: list[str] | None = _json.loads(raw_scopes) if raw_scopes else None
    source_trust_raw = _optional_col(row, "source_trust", keys)
    source_trust: float | None = float(source_trust_raw) if source_trust_raw is not None else None
    valid_until = _optional_col(row, "projected_valid_until", keys)
    if valid_until is None:
        valid_until = row["valid_until"]
    confidence_raw = _optional_col(row, "projected_confidence", keys)
    confidence = row["confidence"] if confidence_raw is None else confidence_raw
    garden_id = _optional_col(row, "projected_garden_id", keys)
    if garden_id is None:
        garden_id = _optional_col(row, "garden_id", keys)
    quarantine_status = _optional_col(row, "projected_quarantine_status", keys)
    if quarantine_status is None:
        quarantine_status = _optional_col(row, "quarantine_status", keys)
    quarantine_garden_id = _optional_col(row, "projected_quarantine_garden_id", keys)
    if quarantine_garden_id is None:
        quarantine_garden_id = _optional_col(row, "quarantine_garden_id", keys)
    cid = _optional_col(row, "projected_cid", keys)
    if cid is None:
        cid = _optional_col(row, "cid", keys)
    return FactRecord(
        id=row["id"],
        entity=row["entity"],
        relation=row["relation"],
        value=FactValue(
            type=row["value_type"],
            v=_parse_v(row["value_type"], row["value_v"]),
            interpret_as=_optional_col(row, "interpret_as", keys) or "content",
        ),
        source=row["source"],
        timestamp=row["timestamp"],
        hlc=_optional_col(row, "hlc", keys),
        received_from=_optional_col(row, "received_from", keys),
        valid_until=valid_until,
        confidence=confidence,
        scope=row["scope"],
        attested_key_id=_optional_col(row, "attested_key_id", keys),
        origin_node_id=_optional_col(row, "origin_node_id", keys),
        origin_allowed_scopes=origin_allowed_scopes,
        garden_id=garden_id,
        attested=attested,
        contradicted=contradicted,
        warnings=warnings or [],
        source_trust=source_trust,
        quarantine_status=quarantine_status,
        quarantine_garden_id=quarantine_garden_id,
        effective_confidence=effective_confidence,
        sanitizer_warnings=sanitizer_warnings or [],
        sanitizer_redacted=sanitizer_redacted,
        cid=cid,
        derived_from=_json.loads(_optional_col(row, "derived_from", keys) or "[]"),
    )


def _parse_v(vtype: str, raw: str) -> Any:
    if vtype == "number":
        return float(raw)
    if vtype == "boolean":
        return raw == "true"
    if vtype == "null":
        return None
    return raw  # string, text, datetime, ref
