from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from stigmem_node.db import db
from stigmem_node.plugins import Allow, Deny, PluginContext, PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins
from stigmem_node.routes import federation

# tests/federation/ is a package but tests/plugins/ is not, so a relative import
# is unavailable; add the federation test dir to the path to reuse its v2 helpers.
_FED_TEST_DIR = Path(__file__).resolve().parents[1] / "federation"
if str(_FED_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_FED_TEST_DIR))
from helpers import make_bound_peer, make_v2_entry  # noqa: E402


def _gen_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return priv, pub


def _bound_v2_fact(
    *, node_id: str, scope: str, entity: str = "stigmem://t/a", relation: str = "memory:role"
) -> tuple[dict, dict, str]:
    """Create a bound peer + a signed v2 entry whose source == the peer node_id.

    Returns (fact, origin, origin_sig) destructured from a ``make_v2_entry`` envelope
    so the per-fact origin verification (resolve_origin_key + verify_origin_signature)
    succeeds and execution reaches the federation_inbound_* plugin hooks.
    """
    priv, pub = _gen_keypair()
    with db() as conn:
        make_bound_peer(
            conn,
            node_id=node_id,
            entity_uri=f"https://{node_id.split(':')[-1]}.example",
            pub_b64=pub,
            priv=priv,
        )
        conn.commit()
    fact = {
        "id": "11111111-1111-1111-1111-111111111111",
        "entity": entity,
        "relation": relation,
        "value": {"type": "string", "v": "writer"},
        "source": node_id,
        "timestamp": "2026-06-01T00:00:00Z",
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }
    origin = {
        "tenant": "default",
        "node_id": node_id,
        "allowed_scopes": [scope],
        "allowed_tenants": ["default"],
    }
    entry = make_v2_entry(priv, fact=fact, origin=origin)
    return entry["fact"], entry["origin"], entry["origin_sig"]


def test_federation_inbound_validate_deny_blocks_peer_push(client: TestClient) -> None:
    calls: list[str] = []
    node_id = "stigmem:node:peerdeny"
    fact, origin, origin_sig = _bound_v2_fact(node_id=node_id, scope="company")
    peer = {"id": "peer-id", "node_id": node_id, "allowed_scopes": '["company"]'}
    token_payload = {"scopes": ["company"]}

    def validate(_ctx: PluginContext, **_: object) -> Deny:
        calls.append("validate")
        return Deny("plugin_rejected")

    def filter_fact(
        _ctx: PluginContext, value: dict[str, object], **_: object
    ) -> dict[str, object]:
        calls.append("filter")
        return value

    manifest = PluginManifest(
        name="federation-deny",
        version="1.0.0",
        hooks={
            "federation_inbound_validate": validate,
            "federation_inbound_filter": filter_fact,
        },
    )

    with stigmem_plugins([manifest]):
        ok, err = federation._push_fact_with_peer_token(
            fact, "company", origin, origin_sig, peer, token_payload
        )

    assert ok is False
    assert err == {"fact_id": fact["id"], "error": "plugin_rejected"}
    assert calls == ["validate"]


def test_federation_inbound_filter_transforms_cap_token_fact(
    client: TestClient,
    monkeypatch: object,
) -> None:
    ingested: list[dict[str, object]] = []
    node_id = "stigmem:node:peerfilter"
    fact, origin, origin_sig = _bound_v2_fact(node_id=node_id, scope="team")
    cap_token = {"subject": node_id, "object": "stigmem://facts/scope:team"}

    def fake_ingest(fact_payload: dict[str, object], *_args: object, **_kwargs: object) -> None:
        ingested.append(fact_payload)

    monkeypatch.setattr(federation, "ingest_fact", fake_ingest)  # type: ignore[attr-defined]

    def validate(_ctx: PluginContext, **_: object) -> Allow:
        return Allow()

    def filter_fact(
        _ctx: PluginContext, value: dict[str, object], **_: object
    ) -> dict[str, object]:
        return {**value, "relation": "memory:filtered"}

    manifest = PluginManifest(
        name="federation-filter",
        version="1.0.0",
        hooks={
            "federation_inbound_validate": validate,
            "federation_inbound_filter": filter_fact,
        },
    )

    with stigmem_plugins([manifest]):
        ok, err = federation._push_fact_with_cap_token(
            fact, "team", origin, origin_sig, cap_token
        )

    assert ok is True
    assert err is None
    assert ingested == [{**fact, "relation": "memory:filtered"}]


def test_federation_outbound_filter_and_sign_chain() -> None:
    registry_calls: list[str] = []

    def filter_records(_ctx: PluginContext, value: list[str], **_: object) -> list[str]:
        registry_calls.append("filter")
        return value + ["filtered"]

    def sign_records(_ctx: PluginContext, value: list[str], **_: object) -> list[str]:
        registry_calls.append("sign")
        return value + ["signed"]

    manifest = PluginManifest(
        name="federation-outbound",
        version="1.0.0",
        hooks={
            "federation_outbound_filter": filter_records,
            "federation_outbound_sign": sign_records,
        },
    )

    with stigmem_plugins([manifest]) as registry:
        records = registry.fire_filter_chain("federation_outbound_filter", ["original"])
        records = registry.fire_filter_chain("federation_outbound_sign", records)

    assert records == ["original", "filtered", "signed"]
    assert registry_calls == ["filter", "sign"]
