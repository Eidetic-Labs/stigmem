"""Federation and conflict-resolution models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from .constants import VALID_SCOPES
from .facts import FactRecord, FactValue
from .tombstones import TombstoneRecord, TombstoneRevocationRecord


class PeerRegisterRequest(BaseModel):
    node_url: str = Field(..., min_length=1)
    node_id: str = Field(..., min_length=1)
    federation_pubkey: str = Field(..., min_length=1)
    allowed_scopes: list[str]
    declaration_sig: str = Field(..., min_length=1)
    signed_at: str = Field(..., min_length=1)

    @field_validator("allowed_scopes")
    @classmethod
    def check_scopes(cls, scopes: list[str]) -> list[str]:
        invalid = set(scopes) - VALID_SCOPES
        if invalid:
            raise ValueError(f"invalid scopes: {invalid}")
        return scopes


class PeerRecord(BaseModel):
    peer_id: str
    node_id: str
    node_url: str
    status: str
    allowed_scopes: list[str]
    established_at: str | None


class PeerRegisterResponse(BaseModel):
    peer_id: str
    status: str
    verified_at: str | None


class PeerApprovalRequest(BaseModel):
    pubkey_fingerprint: str = Field(..., min_length=1)


class PeerApprovalResponse(BaseModel):
    peer_id: str
    node_id: str
    status: str
    approved_at: str


class OriginBlock(BaseModel):
    tenant: str
    node_id: str
    allowed_scopes: list[str]
    allowed_tenants: list[str]
    # Phase 2c W3.1: the origin's published entity_uri, bound INTO the signed origin
    # tuple (v2.1). A receiver fetches/verifies the origin's manifest by this uri, so a
    # relay cannot lie about which origin a relayed fact came from. Mandatory in v2.1.
    entity_uri: str


class FederationEnvelopeEntry(BaseModel):
    fact: FactRecord
    origin: OriginBlock
    origin_sig: str
    # Phase 2c W4.2: the carried, self-verifying origin manifest BODY the relay attaches
    # for RELAYED facts. It lets an UNREACHABLE downstream match the relayed origin's key
    # against its operator pin / stored binding (offline trust). It is NOT itself trusted
    # without a first-party anchor match — no proof/STH/Merkle fields, just the manifest
    # body. Absent (None) for self-originated facts and for direct (origin==sender) entries.
    origin_manifest: dict[str, Any] | None = None


class FederationFactsResponse(BaseModel):
    v: int = 2
    facts: list[FederationEnvelopeEntry]
    cursor: str | None
    has_more: bool


class AuditEntry(BaseModel):
    id: str
    peer_id: str
    event_type: str
    detail: str | None
    ts: str


class ConflictResolveRequest(BaseModel):
    """Request body for POST /v1/conflicts/:id/resolve (Spec-15-Fact-Semantics)."""

    winning_fact_id: str | None = None
    resolution_note: str = ""
    new_value: FactValue | None = None


# ---------------------------------------------------------------------------
# V2 tombstone envelope models (Phase 2c W6.4)
# Mirror FederationEnvelopeEntry / FederationFactsResponse for tombstones.
# TombstoneRecord + TombstoneRevocationRecord imported from tombstones.py.
# ---------------------------------------------------------------------------


class TombstoneEnvelopeEntry(BaseModel):
    """V2 per-tombstone envelope carrying origin attestation.

    Mirrors FederationEnvelopeEntry for facts; reuses OriginBlock unchanged.
    """

    tombstone: TombstoneRecord
    origin: OriginBlock
    origin_sig: str
    # Carried, self-verifying origin manifest body for RELAYED tombstones.
    # Absent (None) for self-originated tombstones and direct (origin==sender) entries.
    origin_manifest: dict[str, Any] | None = None


class FederationTombstonesResponseV2(BaseModel):
    """V2 federation tombstone poll response with per-tombstone origin envelopes.

    Mirrors FederationFactsResponse; revocations stay as TombstoneRevocationRecord
    for now (enveloped in a later task). Back-compat: FederationTombstonesResponse
    (v1) in tombstones.py is unchanged.
    """

    v: int = 2
    tombstones: list[TombstoneEnvelopeEntry]
    revocations: list[TombstoneRevocationRecord]
    cursor: str | None = None
    has_more: bool = False
