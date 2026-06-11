"""Phase 2c F-2c-MED-2 — validate inbound fact.scope against VALID_SCOPES on ingest.

``fact.scope`` was checked only for membership in the ORIGIN-signed
``origin.allowed_scopes``, then written straight to ``facts.scope`` with NO enum
validation. A malicious origin can self-consistently sign ``scope="a_b"`` +
``allowed_scopes=["a_b"]`` and persist a non-enum/wildcard scope — a data-integrity
gap (and the enabler the egress LIKE-escaping fix defends against).

Fix: on the fact relay ingest path (push ``_verify_origin_and_resolve_tenant`` + the
pull loop) validate ``fact_scope in VALID_SCOPES`` BEFORE ingest; reject ``invalid_scope``
if not. Facts only (the finding is about facts).

Tests:
  * a relayed fact with ``scope="a_b"`` (non-enum), signed consistently with
    ``allowed_scopes=["a_b"]``, is REJECTED (``invalid_scope``), not stored — push + pull.
  * positive control: a valid enum scope still ingests — push + pull.
"""

from __future__ import annotations

import base64
import json
import uuid
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

from .helpers import generate_ed25519_b64, make_bound_peer, make_v2_envelope

_TENANT = "default"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _priv_to_b64(priv: Ed25519PrivateKey) -> str:
    return (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )


def _set_relay_enabled(value: bool) -> None:
    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    _settings_mod.settings.federation_relay_enabled = value


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
) -> tuple[FedNode, str, Ed25519PrivateKey, str, str, Ed25519PrivateKey]:
    """fed_node + relay SENDER bound-peer + separate ORIGIN bound-peer (origin != sender).

    The sender peer's allowed_scopes includes the non-enum 'a_b' so the peer-token
    scope-permission gate on the PUSH path does NOT pre-empt the new enum check — the
    failure isolates ``invalid_scope`` (not ``scope_not_permitted``). relay_trusted + a
    'default' ingest_tenant pin so an allowed origin tenant resolves.

    Returns (fed_node, sender_node_id, sender_priv, origin_node_id, origin_entity_uri,
             origin_priv).
    """
    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"

    origin_pub, origin_priv_b64 = generate_ed25519_b64()
    origin_priv = _priv_from_b64(origin_priv_b64)
    origin_node_id = f"stigmem://origin-{uuid.uuid4()}"
    origin_entity_uri = f"https://origin-{uuid.uuid4()}.example"

    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        conn.execute(
            "UPDATE peers SET relay_trusted = 1, ingest_tenant = ?, allowed_scopes = ? "
            "WHERE node_id = ?",
            (_TENANT, json.dumps(["public", "a_b"]), sender_node_id),
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
    return (fed_node, sender_node_id, sender_priv, origin_node_id, origin_entity_uri, origin_priv)


def _peer_dict(node_id: str, *, relay_trusted: int = 1) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": node_id,
        "node_url": "http://peer",
        "allowed_scopes": json.dumps(["public", "a_b"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": relay_trusted,
    }


def _relayed_fact_body(
    origin_priv: Ed25519PrivateKey,
    *,
    origin_node_id: str,
    origin_entity_uri: str,
    scope: str,
) -> tuple[dict[str, Any], str]:
    """A v2 push envelope for a RELAYED fact with origin.allowed_scopes == [scope] (so the
    origin-grant scope check passes self-consistently — only the enum check can catch it).

    Returns (body, fact_id).
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
        "tenant": _TENANT,
        "node_id": origin_node_id,
        "allowed_scopes": [scope],
        "allowed_tenants": [_TENANT],
        "entity_uri": origin_entity_uri,
    }
    return make_v2_envelope(origin_priv, facts=[fact], origin=origin), fact["id"]


def _push(fed_node: FedNode, sender_node_id: str, sender_priv: Ed25519PrivateKey, body):  # type: ignore[no-untyped-def]
    token = make_peer_token(
        _priv_to_b64(sender_priv), sender_node_id, fed_node.node_id, ["public", "a_b"]
    )
    return fed_node.client.post(
        "/v1/federation/facts/push",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )


# ===========================================================================
# PUSH path (_verify_origin_and_resolve_tenant)
# ===========================================================================


def test_fact_push_non_enum_scope_rejected(relay_nodes, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """PUSH: a relayed fact with scope='a_b' (non-enum), self-consistently signed with
    allowed_scopes=['a_b'], is REJECTED (invalid_scope) and never stored."""
    import stigmem_node.settings as _smod  # noqa: PLC0415

    fed_node, sender_node_id, sender_priv, origin_node_id, origin_entity_uri, origin_priv = (
        relay_nodes
    )
    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    body, fact_id = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        scope="a_b",
    )
    r = _push(fed_node, sender_node_id, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 0, r.json()
    assert any(e["error"] == "invalid_scope" for e in r.json()["errors"]), r.json()
    with _db_ctx() as conn:
        assert conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone() is None


def test_fact_push_valid_scope_ingested(relay_nodes, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """PUSH positive control: a relayed fact with a valid enum scope ('public') still
    ingests."""
    import stigmem_node.settings as _smod  # noqa: PLC0415

    fed_node, sender_node_id, sender_priv, origin_node_id, origin_entity_uri, origin_priv = (
        relay_nodes
    )
    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    body, fact_id = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        scope="public",
    )
    r = _push(fed_node, sender_node_id, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1, r.json()
    with _db_ctx() as conn:
        assert conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone() is not None


# ===========================================================================
# PULL path (pull_from_peer_once loop)
# ===========================================================================


def test_fact_pull_non_enum_scope_skipped(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """PULL: a relayed fact with scope='a_b' (non-enum) is SKIPPED (invalid_scope), not
    stored."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once  # noqa: PLC0415

    fed_node, sender_node_id, _sp, origin_node_id, origin_entity_uri, origin_priv = relay_nodes
    _set_relay_enabled(True)

    body, fact_id = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        scope="a_b",
    )
    body["cursor"] = "sc-bad"

    import asyncio  # noqa: PLC0415

    asyncio.run(pull_from_peer_once(_peer_dict(sender_node_id), _FakeClient(body), None))
    with _db_ctx() as conn:
        assert conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone() is None


def test_fact_pull_valid_scope_ingested(relay_nodes) -> None:  # type: ignore[no-untyped-def]
    """PULL positive control: a relayed fact with a valid enum scope ('public') ingests."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once  # noqa: PLC0415

    fed_node, sender_node_id, _sp, origin_node_id, origin_entity_uri, origin_priv = relay_nodes
    _set_relay_enabled(True)

    body, fact_id = _relayed_fact_body(
        origin_priv,
        origin_node_id=origin_node_id,
        origin_entity_uri=origin_entity_uri,
        scope="public",
    )
    body["cursor"] = "sc-ok"

    import asyncio  # noqa: PLC0415

    asyncio.run(pull_from_peer_once(_peer_dict(sender_node_id), _FakeClient(body), None))
    with _db_ctx() as conn:
        assert conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone() is not None
