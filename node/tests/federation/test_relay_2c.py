"""Phase 2c relay — W2/W3 relay tests accumulate here.

W2.1: dormant foundation — relay enablement flag + peers.relay_trusted column
(both default off; no runtime behaviour change until W2.2+).

W2.2: at egress emit, distinguish self-originated (sign a FRESH origin block with
this node's identity — unchanged 2b behaviour) from relayed facts (received_from
not NULL — forward the STORED origin block + STORED origin_sig verbatim, no re-sign).
"""

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.db import db
from stigmem_node.federation.origin_signature import sign_origin
from stigmem_node.models.facts import FactRecord, FactValue
from stigmem_node.settings import Settings

# ---------------------------------------------------------------------------
# W2.1 — settings flag
# ---------------------------------------------------------------------------


def test_federation_relay_enabled_defaults_false() -> None:
    """Settings().federation_relay_enabled must default to False (relay is OFF)."""
    assert Settings().federation_relay_enabled is False


# ---------------------------------------------------------------------------
# W2.1 — migration 045: peers.relay_trusted column
# ---------------------------------------------------------------------------


def test_peers_has_relay_trusted_column(client) -> None:  # type: ignore[no-untyped-def]
    """Migration 045 adds relay_trusted to peers; PRAGMA table_info confirms it."""
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    assert "relay_trusted" in cols


def test_relay_trusted_defaults_to_zero(client) -> None:  # type: ignore[no-untyped-def]
    """A peer inserted without relay_trusted reads 0 (default off)."""
    with db() as conn:
        conn.execute(
            "INSERT INTO peers "
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, "
            "declaration_sig, signed_at) "
            "VALUES ('rt1', 'stigmem:node:rt1', 'http://x', 'PUB', '[]', 'active', "
            "'SIG', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT relay_trusted FROM peers WHERE id='rt1'"
        ).fetchone()
    assert row["relay_trusted"] == 0


# ---------------------------------------------------------------------------
# W2.2 — emit branch: self-originated (fresh sign) vs relayed (forward verbatim)
# ---------------------------------------------------------------------------

# This node's identity at emit time (the relay node). Distinct from the ORIGIN.
_OWN_NODE_ID = "stigmem:node:relay-self"
_PULL_TENANT = "default"

# The ORIGIN node (the upstream that first asserted the relayed fact).
_ORIGIN_NODE_ID = "stigmem:node:upstream-origin"
_ORIGIN_TENANT = "acme"


def _self_record() -> FactRecord:
    """A locally-originated, replication-eligible record (received_from is None)."""
    return FactRecord(
        id="11111111-1111-1111-1111-111111111111",
        entity="self:entity",
        relation="self:value",
        value=FactValue(type="string", v="local"),
        source="agent:test",
        timestamp="2026-06-10T00:00:00Z",
        hlc="1.000",
        received_from=None,
        confidence=1.0,
        scope="public",
        cid="bafyselfcid",
        origin_allowed_scopes=None,
    )


def _relayed_record() -> FactRecord:
    """A record received FROM a peer (received_from not None) — relay forwards it."""
    return FactRecord(
        id="22222222-2222-2222-2222-222222222222",
        entity="relayed:entity",
        relation="relayed:value",
        value=FactValue(type="string", v="from-upstream"),
        source=_ORIGIN_NODE_ID,
        timestamp="2026-06-10T00:00:00Z",
        hlc="2.000",
        received_from="stigmem:node:direct-peer",
        confidence=1.0,
        scope="public",
        cid="bafyrelayedcid",
        origin_node_id=_ORIGIN_NODE_ID,
        origin_allowed_scopes=["public"],
    )


def _stored_origin_row(
    record: FactRecord,
    *,
    origin_sig: str | None,
    origin_tenant: str | None = _ORIGIN_TENANT,
    origin_node_id: str | None = _ORIGIN_NODE_ID,
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
) -> dict[str, Any]:
    """A DB-row stand-in carrying the stored origin_* columns FactRecord omits."""
    return {
        "id": record.id,
        "origin_tenant": origin_tenant,
        "origin_node_id": origin_node_id,
        "origin_allowed_scopes": (
            json.dumps(origin_allowed_scopes) if origin_allowed_scopes is not None else None
        ),
        "origin_allowed_tenants": (
            json.dumps(origin_allowed_tenants) if origin_allowed_tenants is not None else None
        ),
        "origin_sig": origin_sig,
    }


def test_self_originated_emit_signs_fresh_with_own_identity() -> None:
    """Self-originated fact: emit a fresh OriginBlock for THIS node + a fresh sig."""
    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _self_record()
    row = _stored_origin_row(record, origin_sig=None, origin_node_id=None, origin_tenant=None)

    result = build_origin_entry(
        record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
    )
    assert result is not None
    origin, sig = result
    assert origin.node_id == _OWN_NODE_ID  # this node, not an upstream
    assert origin.tenant == _PULL_TENANT
    assert origin.allowed_tenants == [_PULL_TENANT]
    # the sig is freshly computed over THIS node's origin block
    assert record.cid is not None
    expected = sign_origin(
        priv,
        fact_id=record.id,
        cid=record.cid,
        origin=origin.model_dump(),
        valid_until=record.valid_until,
    )
    assert sig == expected


def test_relayed_emit_forwards_stored_origin_block_verbatim() -> None:
    """Relayed fact: emit the STORED origin block + STORED origin_sig, no re-sign."""
    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _relayed_record()
    stored_sig = "STORED-ORIGIN-SIGNATURE-FROM-UPSTREAM"
    row = _stored_origin_row(
        record,
        origin_sig=stored_sig,
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
    )

    result = build_origin_entry(
        record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
    )
    assert result is not None
    origin, sig = result
    # origin attribution is the UPSTREAM origin, NOT this relay node
    assert origin.node_id == _ORIGIN_NODE_ID
    assert origin.node_id != _OWN_NODE_ID
    assert origin.tenant == _ORIGIN_TENANT
    assert origin.allowed_scopes == ["public"]
    assert origin.allowed_tenants == ["acme"]
    # the stored sig is forwarded verbatim (NOT re-signed by this node)
    assert sig == stored_sig
    assert record.cid is not None
    fresh = sign_origin(
        priv,
        fact_id=record.id,
        cid=record.cid,
        origin=origin.model_dump(),
        valid_until=record.valid_until,
    )
    assert sig != fresh  # proves it was not re-signed locally


def test_relayed_emit_without_stored_sig_is_skipped(caplog) -> None:  # type: ignore[no-untyped-def]
    """A relayed fact missing its stored origin_sig is SKIPPED (None) + warned."""
    import logging  # noqa: PLC0415

    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _relayed_record()
    row = _stored_origin_row(record, origin_sig=None, origin_allowed_scopes=["public"])

    with caplog.at_level(logging.WARNING):
        result = build_origin_entry(
            record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
        )
    assert result is None
    assert any(record.id in r.getMessage() for r in caplog.records)
