from __future__ import annotations

from stigmem_node.plugins import Allow, Deny, PluginContext, PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins
from stigmem_node.routes import federation


def test_federation_inbound_validate_deny_blocks_peer_push() -> None:
    calls: list[str] = []
    fact = {"id": "fact-1", "scope": "company", "source": "peer-a"}
    peer = {"id": "peer-id", "node_id": "peer-a", "allowed_scopes": '["company"]'}
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
            fact, "company", peer, token_payload, "default"
        )

    assert ok is False
    assert err == {"fact_id": "fact-1", "error": "plugin_rejected"}
    assert calls == ["validate"]


def test_federation_inbound_filter_transforms_cap_token_fact(
    monkeypatch: object,
) -> None:
    ingested: list[dict[str, object]] = []
    fact = {"id": "fact-1", "scope": "team", "source": "peer-a"}
    cap_token = {"subject": "peer-a", "object": "stigmem://facts/scope:team"}

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
        ok, err = federation._push_fact_with_cap_token(fact, "team", cap_token, "default")

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
