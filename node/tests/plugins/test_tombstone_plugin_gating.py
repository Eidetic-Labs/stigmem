from __future__ import annotations

import importlib
import sys
import urllib.parse
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from conftest import _make_enc_settings, _patch_settings, _restore_settings
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.plugins.discovery import DiscoveredPlugin
from stigmem_node.plugins.testing import stigmem_plugins

_FEATURE_DIR = Path(__file__).resolve().parents[3] / "experimental" / "tombstones"
_SRC_DIR = _FEATURE_DIR / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

_PLUGIN = importlib.import_module("stigmem_plugin_tombstones")
PLUGIN_NAME = _PLUGIN.PLUGIN_NAME
plugin_manifest = _PLUGIN.plugin_manifest


def _insert_fact(client: TestClient, entity: str) -> dict[str, Any]:
    response = client.post(
        "/v1/facts",
        json={
            "entity": entity,
            "relation": "test:name",
            "value": {"type": "string", "v": "visible"},
            "source": entity,
            "confidence": 1.0,
            "scope": "local",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _insert_tombstone(entity: str) -> None:
    with db_mod.db() as conn:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?, ?, '*', 'test', 'agent:admin', 'sig',
                       ?, 0, 'default')""",
            (f"tomb_{uuid.uuid4().hex}", entity, datetime.now(UTC).isoformat()),
        )


@pytest.fixture()
def tombstone_plugin_client(
    tmp_db: str,
    backend: str,
    encrypt: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient, None, None]:
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db,
        backend,
        encrypt,
        auth_required=False,
        node_url="http://testnode",
    )
    extra = _patch_settings(test_settings)
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER", "true")

    manifest = plugin_manifest()
    discovered = DiscoveredPlugin(
        manifest=manifest,
        entry_point_name="tombstones",
        entry_point_value="stigmem_plugin_tombstones:plugin_manifest",
        distribution=PLUGIN_NAME,
    )
    app = create_app()
    _include_plugin_routers(app, (discovered,))
    admin_key = auth_mod.create_api_key(
        "stigmem://testnode/agent/admin",
        ["read", "write", "federate", "admin"],
    )

    try:
        with stigmem_plugins([manifest]), TestClient(app, raise_server_exceptions=True) as client:
            client.headers.update({"Authorization": f"Bearer {admin_key}"})
            yield client
    finally:
        _restore_settings(original, extra)


@pytest.fixture()
def tombstone_plugin_no_filter_client(
    tmp_db: str,
    backend: str,
    encrypt: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[TestClient, None, None]:
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db,
        backend,
        encrypt,
        auth_required=False,
        node_url="http://testnode",
    )
    extra = _patch_settings(test_settings)
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES", "true")
    monkeypatch.delenv("STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER", raising=False)

    manifest = plugin_manifest()
    discovered = DiscoveredPlugin(
        manifest=manifest,
        entry_point_name="tombstones",
        entry_point_value="stigmem_plugin_tombstones:plugin_manifest",
        distribution=PLUGIN_NAME,
    )
    app = create_app()
    _include_plugin_routers(app, (discovered,))
    admin_key = auth_mod.create_api_key(
        "stigmem://testnode/agent/admin",
        ["read", "write", "federate", "admin"],
    )

    try:
        with stigmem_plugins([manifest]), TestClient(app, raise_server_exceptions=True) as client:
            client.headers.update({"Authorization": f"Bearer {admin_key}"})
            yield client
    finally:
        _restore_settings(original, extra)


def test_default_install_keeps_tombstone_routes_access_gated(client: TestClient) -> None:
    assert client.get("/v1/tombstones/user%3Aalice").status_code == 403
    assert client.get("/v1/federation/tombstones").status_code == 401
    assert client.post("/v1/federation/tombstones/ingest", json={}).status_code == 401

    openapi_paths = client.get("/openapi.json").json()["paths"]
    assert "/v1/tombstones/{entity_uri_encoded}" in openapi_paths
    assert "/v1/federation/tombstones" in openapi_paths
    assert "/v1/federation/tombstones/ingest" in openapi_paths


def test_default_install_does_not_apply_legacy_tombstone_filter(client: TestClient) -> None:
    entity = "stigmem://test/tombstone-gated/default"
    fact = _insert_fact(client, entity)
    _insert_tombstone(entity)

    response = client.get("/v1/facts", params={"entity": entity})

    assert response.status_code == 200, response.text
    assert [row["id"] for row in response.json()["facts"]] == [fact["id"]]


def test_plugin_loaded_restores_routes_and_tombstone_filter(
    tombstone_plugin_client: TestClient,
) -> None:
    entity = "user:tombstone-gated-plugin"
    _insert_fact(tombstone_plugin_client, entity)
    _insert_tombstone(entity)

    encoded_entity = urllib.parse.quote(entity, safe="")
    status_response = tombstone_plugin_client.get(f"/v1/tombstones/{encoded_entity}")
    fact_response = tombstone_plugin_client.get("/v1/facts", params={"entity": entity})

    assert status_response.status_code == 200, status_response.text
    assert status_response.json()["tombstoned"] is True
    assert fact_response.status_code == 200, fact_response.text
    assert fact_response.json()["facts"] == []


def test_plugin_loaded_without_filter_gate_keeps_facts_visible(
    tombstone_plugin_no_filter_client: TestClient,
) -> None:
    entity = "user:tombstone-no-filter-gate"
    fact = _insert_fact(tombstone_plugin_no_filter_client, entity)
    _insert_tombstone(entity)

    encoded_entity = urllib.parse.quote(entity, safe="")
    status_response = tombstone_plugin_no_filter_client.get(f"/v1/tombstones/{encoded_entity}")
    fact_response = tombstone_plugin_no_filter_client.get("/v1/facts", params={"entity": entity})

    assert status_response.status_code == 200, status_response.text
    assert status_response.json()["tombstoned"] is True
    assert fact_response.status_code == 200, fact_response.text
    assert [row["id"] for row in fact_response.json()["facts"]] == [fact["id"]]
