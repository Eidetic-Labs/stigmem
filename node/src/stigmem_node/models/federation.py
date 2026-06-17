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


class OriginKeyProof(BaseModel):
    """Phase 3 (Rev 6 §7) — the v2.2 envelope ``origin_key_proof`` transport copy.

    A relay MAY attach its last-resolved DNSSEC binding snapshot (fingerprint /
    epoch / host / outcome) for a RELAYED, DNSSEC-anchored origin. It is purely a
    *transport copy* / forward-compat hint.

    INVARIANT I7 — carried bytes are transport, NEVER trust. The receiver MUST
    ignore this carried snapshot as a trust input: it independently re-resolves and
    re-validates the origin key through the live ladder/recheck path
    (``resolve_origin_key_for_relay`` -> ``resolve_dnssec_binding``). A carried
    ``dnssec_binding`` with a fabricated ``fpr`` and no live validating record is
    rejected EXACTLY as if it were absent — trust comes only from live
    re-validation, never the carried bytes. The relay resolution entry point takes
    no ``origin_key_proof`` argument, so this snapshot can never be threaded into a
    trust decision; it exists for diagnostics / forward compatibility only.

    Additive + optional: ``proof_version`` lets the snapshot's shape evolve without
    breaking a v2.1 peer (which simply omits the whole field). ``dnssec_binding`` is
    a free-form dict (fpr/epoch/host/outcome) and may be ``None`` for a non-binding
    hint.
    """

    proof_version: int
    dnssec_binding: dict[str, Any] | None = None


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
    # Phase 3 (Rev 6 §7 v2.2): an OPTIONAL, additive per-origin DNSSEC binding snapshot a
    # relay MAY attach for a RELAYED, DNSSEC-anchored origin. Transport copy ONLY (I7): the
    # receiver re-resolves + re-validates and NEVER trusts these carried bytes (see
    # OriginKeyProof). Absent (None) for self-originated facts, direct entries, and any
    # non-DNSSEC origin. A v2.1 peer that omits the field still parses (backward-compatible).
    origin_key_proof: OriginKeyProof | None = None


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


class RevocationEnvelopeEntry(BaseModel):
    """V2 per-revocation envelope carrying origin attestation (Phase 2c Rev-2).

    Mirrors TombstoneEnvelopeEntry for tombstone REVOCATIONS; reuses OriginBlock
    unchanged. A revocation has no entity_uri/scope of its own — it references a
    tombstone by ``tombstone_id`` — so its origin attestation binds the revocation
    ``id`` + the referenced ``tombstone_id`` + the origin grant (Rev-1's
    ``canonical_revocation_origin_tuple``), and the egress gate is TENANT-only.
    """

    revocation: TombstoneRevocationRecord
    origin: OriginBlock
    origin_sig: str
    # Carried, self-verifying origin manifest body for RELAYED revocations.
    # Absent (None) for self-originated revocations and direct (origin==sender) entries.
    origin_manifest: dict[str, Any] | None = None


class FederationTombstonesResponseV2(BaseModel):
    """V2 federation tombstone poll response with per-tombstone origin envelopes.

    Mirrors FederationFactsResponse; revocations are now ALSO enveloped (Rev-2) so a
    relayed revocation carries its origin attestation on the wire. Back-compat:
    FederationTombstonesResponse (v1) in tombstones.py is unchanged.
    """

    v: int = 2
    tombstones: list[TombstoneEnvelopeEntry]
    revocations: list[RevocationEnvelopeEntry]
    cursor: str | None = None
    has_more: bool = False
