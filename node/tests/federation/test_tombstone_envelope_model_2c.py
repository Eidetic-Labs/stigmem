"""W6.4 — v2 tombstone envelope model tests.

Tests (a)–(d) as specified:
  (a) TombstoneEnvelopeEntry validates with TombstoneRecord + OriginBlock + origin_sig;
      origin_manifest defaults None and accepts a dict.
  (b) FederationTombstonesResponseV2 validates with v=2 default, a list of entries,
      optional cursor/has_more defaults.
  (c) Existing v1 FederationTombstonesResponse still validates (back-compat).
  (d) Round-trip: .model_dump() -> Model(**dump) for the v2 entry.
"""

from __future__ import annotations

import pytest

from stigmem_node.models.federation import (
    FederationTombstonesResponseV2,
    OriginBlock,
    TombstoneEnvelopeEntry,
)
from stigmem_node.models.tombstones import (
    FederationTombstonesResponse,
    TombstoneRecord,
    TombstoneRevocationRecord,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tombstone_record() -> TombstoneRecord:
    return TombstoneRecord(
        id="ts-001",
        entity_uri="stigmem://example.org/person/alice",
        scope="*",
        reason="RTBF request",
        signed_by="node-a",
        key_id="key-abc",
        signature="sig-xyz",
        created_at="2026-06-10T00:00:00Z",
        legal_hold=False,
    )


@pytest.fixture()
def origin_block() -> OriginBlock:
    return OriginBlock(
        tenant="tenant-a",
        node_id="node-a",
        allowed_scopes=["read"],
        allowed_tenants=["tenant-a"],
        entity_uri="stigmem://origin.example.org/node/node-a",
    )


@pytest.fixture()
def tombstone_envelope_entry(
    tombstone_record: TombstoneRecord,
    origin_block: OriginBlock,
) -> TombstoneEnvelopeEntry:
    return TombstoneEnvelopeEntry(
        tombstone=tombstone_record,
        origin=origin_block,
        origin_sig="sig-origin-abc123",
    )


# ---------------------------------------------------------------------------
# (a) TombstoneEnvelopeEntry
# ---------------------------------------------------------------------------


def test_tombstone_envelope_entry_validates(
    tombstone_record: TombstoneRecord,
    origin_block: OriginBlock,
) -> None:
    """(a) TombstoneEnvelopeEntry validates with required fields."""
    entry = TombstoneEnvelopeEntry(
        tombstone=tombstone_record,
        origin=origin_block,
        origin_sig="sig-origin-abc123",
    )
    assert entry.tombstone.id == "ts-001"
    assert entry.origin.tenant == "tenant-a"
    assert entry.origin_sig == "sig-origin-abc123"
    assert entry.origin_manifest is None


def test_tombstone_envelope_entry_origin_manifest_default_none(
    tombstone_record: TombstoneRecord,
    origin_block: OriginBlock,
) -> None:
    """(a) origin_manifest defaults to None."""
    entry = TombstoneEnvelopeEntry(
        tombstone=tombstone_record,
        origin=origin_block,
        origin_sig="sig-abc",
    )
    assert entry.origin_manifest is None


def test_tombstone_envelope_entry_origin_manifest_accepts_dict(
    tombstone_record: TombstoneRecord,
    origin_block: OriginBlock,
) -> None:
    """(a) origin_manifest accepts a dict when provided."""
    manifest = {"node_id": "node-a", "pubkey": "pk-xyz", "v": 2}
    entry = TombstoneEnvelopeEntry(
        tombstone=tombstone_record,
        origin=origin_block,
        origin_sig="sig-abc",
        origin_manifest=manifest,
    )
    assert entry.origin_manifest == manifest


# ---------------------------------------------------------------------------
# (b) FederationTombstonesResponseV2
# ---------------------------------------------------------------------------


def test_federation_tombstones_response_v2_default_v(
    tombstone_envelope_entry: TombstoneEnvelopeEntry,
) -> None:
    """(b) FederationTombstonesResponseV2 has v=2 by default."""
    resp = FederationTombstonesResponseV2(
        tombstones=[tombstone_envelope_entry],
        revocations=[],
    )
    assert resp.v == 2


def test_federation_tombstones_response_v2_cursor_defaults_none(
    tombstone_envelope_entry: TombstoneEnvelopeEntry,
) -> None:
    """(b) cursor defaults to None."""
    resp = FederationTombstonesResponseV2(
        tombstones=[tombstone_envelope_entry],
        revocations=[],
    )
    assert resp.cursor is None


def test_federation_tombstones_response_v2_has_more_defaults_false(
    tombstone_envelope_entry: TombstoneEnvelopeEntry,
) -> None:
    """(b) has_more defaults to False."""
    resp = FederationTombstonesResponseV2(
        tombstones=[tombstone_envelope_entry],
        revocations=[],
    )
    assert resp.has_more is False


def test_federation_tombstones_response_v2_with_all_fields(
    tombstone_envelope_entry: TombstoneEnvelopeEntry,
) -> None:
    """(b) FederationTombstonesResponseV2 accepts all optional fields."""
    revocation = TombstoneRevocationRecord(
        id="rev-001",
        tombstone_id="ts-001",
        reason="Revoked by admin",
        signed_by="node-a",
        key_id="key-abc",
        signature="sig-rev",
        created_at="2026-06-10T01:00:00Z",
    )
    resp = FederationTombstonesResponseV2(
        v=2,
        tombstones=[tombstone_envelope_entry],
        revocations=[revocation],
        cursor="2026-06-10T00:00:00Z",
        has_more=True,
    )
    assert resp.v == 2
    assert len(resp.tombstones) == 1
    assert len(resp.revocations) == 1
    assert resp.cursor == "2026-06-10T00:00:00Z"
    assert resp.has_more is True


# ---------------------------------------------------------------------------
# (c) Back-compat: existing v1 FederationTombstonesResponse still validates
# ---------------------------------------------------------------------------


def test_v1_federation_tombstones_response_back_compat(
    tombstone_record: TombstoneRecord,
) -> None:
    """(c) Existing v1 FederationTombstonesResponse still validates unchanged."""
    revocation = TombstoneRevocationRecord(
        id="rev-002",
        tombstone_id="ts-001",
        reason="Test revocation",
        signed_by="node-a",
        key_id="key-abc",
        signature="sig-rev-2",
        created_at="2026-06-10T02:00:00Z",
    )
    resp = FederationTombstonesResponse(
        tombstones=[tombstone_record],
        revocations=[revocation],
        cursor=None,
    )
    assert len(resp.tombstones) == 1
    assert len(resp.revocations) == 1
    assert resp.cursor is None


# ---------------------------------------------------------------------------
# (d) Round-trip: .model_dump() -> Model(**dump) for v2 entry
# ---------------------------------------------------------------------------


def test_tombstone_envelope_entry_round_trip(
    tombstone_record: TombstoneRecord,
    origin_block: OriginBlock,
) -> None:
    """(d) TombstoneEnvelopeEntry round-trips through model_dump / construction."""
    original = TombstoneEnvelopeEntry(
        tombstone=tombstone_record,
        origin=origin_block,
        origin_sig="sig-roundtrip-999",
        origin_manifest={"v": 2, "node_id": "node-a"},
    )
    dump = original.model_dump()
    reconstructed = TombstoneEnvelopeEntry(**dump)
    assert reconstructed.tombstone.id == original.tombstone.id
    assert reconstructed.origin.tenant == original.origin.tenant
    assert reconstructed.origin_sig == original.origin_sig
    assert reconstructed.origin_manifest == original.origin_manifest


def test_federation_tombstones_response_v2_round_trip(
    tombstone_envelope_entry: TombstoneEnvelopeEntry,
) -> None:
    """(d) FederationTombstonesResponseV2 round-trips through model_dump."""
    original = FederationTombstonesResponseV2(
        tombstones=[tombstone_envelope_entry],
        revocations=[],
        cursor="2026-06-10T00:00:00Z",
        has_more=False,
    )
    dump = original.model_dump()
    reconstructed = FederationTombstonesResponseV2(**dump)
    assert reconstructed.v == original.v
    assert len(reconstructed.tombstones) == 1
    assert reconstructed.cursor == original.cursor
