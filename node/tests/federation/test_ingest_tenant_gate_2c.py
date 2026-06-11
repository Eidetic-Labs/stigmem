"""Phase 2c F-2c-MED-1 — INGEST-side origin tenant gate (ingest/egress symmetry).

The relay INGEST path gates the artifact's SCOPE against the origin's signed
``origin.allowed_scopes`` but did NOT check that ``origin.tenant`` is itself inside
the origin's signed ``origin.allowed_tenants``. The egress side enforces tenant
overlap; ingest was asymmetrically weaker — a misconfigured/narrowed-grant origin
could assert a tenant OUTSIDE its own grant and get mapped through the RELAY's
tenant_map.

Both ``origin.tenant`` and ``origin.allowed_tenants`` are bound in the signed origin
tuple (so a relay cannot forge them), but the receiver never enforced the signed
invariant. This module asserts the new fail-closed gate at EVERY relay ingest site:

  * fact PUSH  (``_verify_origin_and_resolve_tenant``)
  * fact PULL  (``pull_from_peer_once`` loop)
  * tombstone PULL (``ingest_tombstone_entry``)
  * revocation PULL (``ingest_revocation_entry``)

Each negative case builds an origin with ``tenant="acme"`` but
``allowed_tenants=["default"]`` (signed consistently so the origin signature still
verifies — the failure is on the NEW gate, ``tenant_not_in_origin_grant``, not the
signature). Each has a positive control (tenant IN grant → applied/ingested).
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import FedNode, make_peer_token
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.origin_signature import (
    sign_revocation_origin,
    sign_tombstone_origin,
)
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.lifecycle.tombstone_signing import (
    _revocation_signing_body,
    _signing_body,
)
from stigmem_node.models.tombstones import TombstoneRecord, TombstoneRevocationRecord

from .helpers import generate_ed25519_b64, make_bound_peer, make_v2_envelope

_TENANT = "default"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _set_relay_enabled(value: bool) -> None:
    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    _settings_mod.settings.federation_relay_enabled = value


# ---------------------------------------------------------------------------
# Shared relay sender + origin bound-peers (origin != sender).
# The sender peer pins ingest_tenant so any wire-carried origin tenant that the
# gate ALLOWS still resolves to a local tenant (default-deny resolver). The gate
# under test fires BEFORE the resolver, so a mismatched origin.tenant is refused
# even though the resolver would otherwise have mapped it.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _FakeClient:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body

    async def get(self, *_a: Any, **_k: Any) -> _FakeResponse:
        return _FakeResponse(self._body)


@pytest.fixture()
def relay_nodes(
    fed_node: FedNode,
) -> tuple[FedNode, str, str, Ed25519PrivateKey, str, str, str, Ed25519PrivateKey, str]:
    """fed_node + a relay SENDER bound-peer + a separate ORIGIN bound-peer (origin != sender).

    Returns (fed_node, sender_node_id, sender_entity_uri, sender_priv, sender_key_id,
             origin_node_id, origin_entity_uri, origin_priv, origin_key_id).
    The sender peer is relay_trusted and pins ingest_tenant='default' so an ALLOWED
    origin tenant of 'default' resolves to a local tenant.
    """
    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"
    sender_key_id = generate_key_id(sender_priv.public_key())

    origin_pub, origin_priv_b64 = generate_ed25519_b64()
    origin_priv = _priv_from_b64(origin_priv_b64)
    origin_node_id = f"stigmem://origin-{uuid.uuid4()}"
    origin_entity_uri = f"https://origin-{uuid.uuid4()}.example"
    origin_key_id = generate_key_id(origin_priv.public_key())

    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        # relay_trusted + ingest_tenant pin so an allowed origin tenant resolves.
        conn.execute(
            "UPDATE peers SET relay_trusted = 1, ingest_tenant = ? WHERE node_id = ?",
            (_TENANT, sender_node_id),
        )
        conn.commit()
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=origin_node_id,
            entity_uri=origin_entity_uri,
            pub_b64=origin_pub,
            priv=origin_priv,
        )
        conn.commit()
    return (
        fed_node,
        sender_node_id,
        sender_entity_uri,
        sender_priv,
        sender_key_id,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    )


def _peer_dict(node_id: str, *, relay_trusted: int = 1) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": node_id,
        "node_url": "http://peer",
        "allowed_scopes": json.dumps(["public", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": relay_trusted,
    }


# ===========================================================================
# FACT — push path (_verify_origin_and_resolve_tenant)
# ===========================================================================


def _relayed_fact_body(
    origin_priv: Ed25519PrivateKey,
    *,
    origin_node_id: str,
    origin_entity_uri: str,
    tenant: str,
    allowed_tenants: list[str],
    scope: str = "public",
    allowed_scopes: list[str] | None = None,
) -> dict[str, Any]:
    """A v2 push envelope for a RELAYED fact (origin.node_id != sender), origin-signed.

    ``source`` is the ORIGIN node_id (relayed facts carry the origin as source).
    """
    fact = {
        "id": str(uuid.uuid4()),
        "entity": f"stigmem://t/{uuid.uuid4()}",
        "relation": "r",
        "value": {"type": "string", "v": "x"},
        "source": origin_node_id,
        "scope": scope,
        "timestamp": "2026-06-01T00:00:00Z",
        "confidence": 1.0,
        "valid_until": None,
    }
    origin = {
        "tenant": tenant,
        "node_id": origin_node_id,
        "allowed_scopes": allowed_scopes if allowed_scopes is not None else [scope],
        "allowed_tenants": allowed_tenants,
        "entity_uri": origin_entity_uri,
    }
    return make_v2_envelope(origin_priv, facts=[fact], origin=origin)


def _push(fed_node: FedNode, sender_node_id: str, sender_priv: Ed25519PrivateKey, body):  # type: ignore[no-untyped-def]
    sender_priv_b64 = (
        base64.urlsafe_b64encode(
            sender_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    token = make_peer_token(sender_priv_b64, sender_node_id, fed_node.node_id, ["public"])
    return fed_node.client.post(
        "/v1/federation/facts/push",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_fact_push_tenant_not_in_origin_grant_rejected(relay_nodes, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """PUSH: a relayed fact whose origin.tenant ∉ origin.allowed_tenants is REJECTED with
    tenant_not_in_origin_grant — even though the origin signature verifies."""
    import stigmem_node.settings as _smod  # noqa: PLC0415

    (
        fed_node,
        sender_node_id,
        _su,
        sender_priv,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        _ok,
    ) = relay_nodes
    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    # origin.tenant='default' WOULD resolve (resolver falls back to the peer's pinned
    # ingest_tenant='default'); the failure isolates the NEW gate: 'default' ∉ ['other'].
    body = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",  # tenant the origin asserts (resolvable)
        allowed_tenants=["other"],  # but NOT in its own signed grant
    )
    r = _push(fed_node, sender_node_id, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 0, r.json()
    assert any(e["error"] == "tenant_not_in_origin_grant" for e in r.json()["errors"]), r.json()


def test_fact_push_tenant_in_origin_grant_ingested(relay_nodes, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """PUSH positive control: a relayed fact whose origin.tenant ∈ origin.allowed_tenants
    still ingests."""
    import stigmem_node.settings as _smod  # noqa: PLC0415

    (
        fed_node,
        sender_node_id,
        _su,
        sender_priv,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        _ok,
    ) = relay_nodes
    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    body = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["default"],  # tenant IS in grant
    )
    r = _push(fed_node, sender_node_id, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1, r.json()


# ===========================================================================
# FACT — pull path (pull_from_peer_once loop)
# ===========================================================================


def test_fact_pull_tenant_not_in_origin_grant_skipped(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """PULL: a relayed fact whose origin.tenant ∉ origin.allowed_tenants is SKIPPED, not
    ingested."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once  # noqa: PLC0415

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        _ok,
    ) = relay_nodes
    _set_relay_enabled(True)

    # origin.tenant='default' resolves; isolates the NEW gate: 'default' ∉ ['other'].
    body = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["other"],
    )
    body["cursor"] = "fpc-bad"
    fact_id = body["facts"][0]["fact"]["id"]

    asyncio.run(
        pull_from_peer_once(_peer_dict(sender_node_id), _FakeClient(body), None)
    )
    with _db_ctx() as conn:
        row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
    assert row is None


def test_fact_pull_tenant_in_origin_grant_ingested(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """PULL positive control: a relayed fact whose origin.tenant ∈ origin.allowed_tenants
    ingests."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once  # noqa: PLC0415

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        _ok,
    ) = relay_nodes
    _set_relay_enabled(True)

    body = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["default"],
    )
    body["cursor"] = "fpc-ok"
    fact_id = body["facts"][0]["fact"]["id"]

    asyncio.run(
        pull_from_peer_once(_peer_dict(sender_node_id), _FakeClient(body), None)
    )
    with _db_ctx() as conn:
        row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
    assert row is not None


# ===========================================================================
# TOMBSTONE — pull path (ingest_tombstone_entry)
# ===========================================================================


def _issuer_signed_tombstone(
    issuer_priv: Ed25519PrivateKey, *, entity_uri: str, scope: str, signed_by: str, key_id: str
) -> TombstoneRecord:
    rec = TombstoneRecord(
        id=f"tomb_{uuid.uuid4()}",
        entity_uri=entity_uri,
        scope=scope,
        reason=None,
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    sig = base64.urlsafe_b64encode(issuer_priv.sign(_signing_body(rec))).decode().rstrip("=")
    return rec.model_copy(update={"signature": sig})


def _tombstone_entry(
    origin_priv: Ed25519PrivateKey,
    *,
    tombstone: TombstoneRecord,
    origin_node_id: str,
    origin_entity_uri: str,
    tenant: str,
    allowed_tenants: list[str],
    allowed_scopes: list[str],
) -> dict[str, Any]:
    origin = {
        "tenant": tenant,
        "node_id": origin_node_id,
        "allowed_scopes": allowed_scopes,
        "allowed_tenants": allowed_tenants,
        "entity_uri": origin_entity_uri,
    }
    origin_sig = sign_tombstone_origin(
        origin_priv,
        tombstone_id=tombstone.id,
        entity_uri=tombstone.entity_uri,
        scope=tombstone.scope,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
    )
    return {"tombstone": tombstone.model_dump(), "origin": origin, "origin_sig": origin_sig}


def _tomb_page(entries: list[dict[str, Any]], cursor: str | None = None) -> dict[str, Any]:
    return {"v": 2, "tombstones": entries, "revocations": [], "cursor": cursor}


def _tombstone_row(entity_uri: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstones WHERE entity_uri = ?", (entity_uri,)
        ).fetchone()
    return dict(row) if row is not None else None


def test_tombstone_pull_tenant_not_in_origin_grant_skipped(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """TOMBSTONE PULL: a relayed tombstone whose origin.tenant ∉ origin.allowed_tenants is
    SKIPPED — not applied."""
    from stigmem_node.federation.federation_pull import (  # noqa: PLC0415
        pull_tombstones_from_peer_once,
    )

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri=f"user:tg-bad-{uuid.uuid4()}",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    # origin.tenant='default' resolves; isolates the NEW gate: 'default' ∉ ['other'].
    entry = _tombstone_entry(
        origin_priv,
        tombstone=rec,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["other"],
        allowed_scopes=["public"],
    )
    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id), _FakeClient(_tomb_page([entry], cursor="tg1")), None
        )
    )
    assert _tombstone_row(rec.entity_uri) is None


def test_tombstone_pull_tenant_in_origin_grant_applied(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """TOMBSTONE PULL positive control: origin.tenant ∈ origin.allowed_tenants → applied."""
    from stigmem_node.federation.federation_pull import (  # noqa: PLC0415
        pull_tombstones_from_peer_once,
    )

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri=f"user:tg-ok-{uuid.uuid4()}",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    entry = _tombstone_entry(
        origin_priv,
        tombstone=rec,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["default"],
        allowed_scopes=["public"],
    )
    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id), _FakeClient(_tomb_page([entry], cursor="tg2")), None
        )
    )
    assert _tombstone_row(rec.entity_uri) is not None


# ===========================================================================
# REVOCATION — pull path (ingest_revocation_entry)
# ===========================================================================


def _issuer_signed_revocation(
    issuer_priv: Ed25519PrivateKey, *, tombstone_id: str, signed_by: str, key_id: str
) -> TombstoneRevocationRecord:
    rec = TombstoneRevocationRecord(
        id=f"tombrevoke_{uuid.uuid4()}",
        tombstone_id=tombstone_id,
        reason="",
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
    )
    sig = (
        base64.urlsafe_b64encode(issuer_priv.sign(_revocation_signing_body(rec)))
        .decode()
        .rstrip("=")
    )
    return rec.model_copy(update={"signature": sig})


def _insert_tombstone(db_path: str, *, tombstone_id: str, entity_uri: str) -> None:
    import sqlite3  # noqa: PLC0415

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tombstone_id,
                entity_uri,
                "*",
                None,
                "stigmem://local/issuer",
                "key-1",
                "issuer-sig",
                "2026-06-10T00:00:00Z",
                0,
                _TENANT,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _revocation_entry(
    origin_priv: Ed25519PrivateKey,
    *,
    revocation: TombstoneRevocationRecord,
    origin_node_id: str,
    origin_entity_uri: str,
    tenant: str,
    allowed_tenants: list[str],
) -> dict[str, Any]:
    origin = {
        "tenant": tenant,
        "node_id": origin_node_id,
        "allowed_scopes": [],
        "allowed_tenants": allowed_tenants,
        "entity_uri": origin_entity_uri,
    }
    origin_sig = sign_revocation_origin(
        origin_priv,
        revocation_id=revocation.id,
        tombstone_id=revocation.tombstone_id,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
    )
    return {"revocation": revocation.model_dump(), "origin": origin, "origin_sig": origin_sig}


def _rev_page(revocations: list[dict[str, Any]], cursor: str | None = None) -> dict[str, Any]:
    return {"v": 2, "tombstones": [], "revocations": revocations, "cursor": cursor}


def _revocation_row(rev_id: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstone_revocations WHERE id = ?", (rev_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def test_revocation_pull_tenant_not_in_origin_grant_skipped(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """REVOCATION PULL: a relayed revocation whose origin.tenant ∉ origin.allowed_tenants is
    SKIPPED — not applied (revocations carry origin.tenant + allowed_tenants but no scope)."""
    from stigmem_node.federation.federation_pull import (  # noqa: PLC0415
        pull_tombstones_from_peer_once,
    )

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri=f"user:rg-bad-{tomb_id}")
    rev = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    # origin.tenant='default' resolves; isolates the NEW gate: 'default' ∉ ['other'].
    entry = _revocation_entry(
        origin_priv,
        revocation=rev,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["other"],
    )
    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id), _FakeClient(_rev_page([entry], cursor="rg1")), None
        )
    )
    assert _revocation_row(rev.id) is None


def test_revocation_pull_tenant_in_origin_grant_applied(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """REVOCATION PULL positive control: origin.tenant ∈ origin.allowed_tenants → applied."""
    from stigmem_node.federation.federation_pull import (  # noqa: PLC0415
        pull_tombstones_from_peer_once,
    )

    (
        fed_node,
        sender_node_id,
        _su,
        _sp,
        _sk,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri=f"user:rg-ok-{tomb_id}")
    rev = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    entry = _revocation_entry(
        origin_priv,
        revocation=rev,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        tenant="default",
        allowed_tenants=["default"],
    )
    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id), _FakeClient(_rev_page([entry], cursor="rg2")), None
        )
    )
    assert _revocation_row(rev.id) is not None
