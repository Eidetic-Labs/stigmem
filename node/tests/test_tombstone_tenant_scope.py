"""Tenant-scoping of RTBF tombstone suppression (read path) and issuance (write path).

R-3 / F-SBOLA3 (HIGH cross-tenant): tombstone read-path suppression and write-path
issuance ignored tenant. A tenant-B tombstone suppressed tenant-A's facts (and
admin-issued tombstones all landed in tenant "default"). Suppression reads and
issuance must be scoped to the caller's own tenant — no cross-tenant path.

These tests combine the multi-tenant plugin fixture (so identities resolve to their
own tenant) with the RTBF tombstone plugin + recall-filter env gate (so the
suppression path is live), and set tombstone/fact ``tenant_id`` via SQL as needed.
"""

from __future__ import annotations

import base64
import importlib
import os
import sqlite3
import sys
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.lifecycle.tombstones as tombstones_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.plugins.discovery import DiscoveredPlugin
from stigmem_node.plugins.testing import stigmem_plugins

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings

# ---------------------------------------------------------------------------
# Plugin sources: multi-tenant (identity → own tenant) + tombstones (RTBF filter)
# ---------------------------------------------------------------------------

_MT_PLUGIN_SRC = Path(__file__).resolve().parents[2] / "experimental" / "multi-tenant" / "src"
_TOMB_PLUGIN_SRC = Path(__file__).resolve().parents[2] / "experimental" / "tombstones" / "src"
for _p in (_MT_PLUGIN_SRC, _TOMB_PLUGIN_SRC):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

_mt_plugin = importlib.import_module("stigmem_plugin_multi_tenant")
_tomb_plugin = importlib.import_module("stigmem_plugin_tombstones")

_TOMBSTONE_ENV = {
    "STIGMEM_TOMBSTONES_ENABLED": "true",
    "STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER": "true",
}


@contextmanager
def _tombstone_env() -> Generator[None, None, None]:
    original = {name: os.environ.get(name) for name in _TOMBSTONE_ENV}
    try:
        for name, value in _TOMBSTONE_ENV.items():
            os.environ[name] = value
        yield
    finally:
        for name, value in original.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _gen_priv_b64() -> str:
    priv = Ed25519PrivateKey.generate()
    return (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )


@pytest.fixture()
def tenant_tombstone_app(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str, str], None, None]:
    """Two tenants (a/b) + admin key, with both plugins active and the RTBF filter on.

    Yields ``(client, key_a, key_b, db_file)``. ``key_a`` resolves to tenant-a,
    ``key_b`` to tenant-b. Both keys carry admin so they can issue tombstones.
    """
    db_file = str(tmp_path) + "/tomb-tenant.db"
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        trust_mode="off",
        node_private_key=_gen_priv_b64(),
    )
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings

    key_a = create_api_key("agent:alice", ["read", "write", "admin"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write", "admin"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    mt_manifest = _mt_plugin.plugin_manifest()
    tomb_manifest = _tomb_plugin.plugin_manifest()

    with _tombstone_env(), stigmem_plugins([mt_manifest, tomb_manifest]):
        app = create_app()
        discovered = DiscoveredPlugin(
            manifest=tomb_manifest,
            entry_point_name="tombstones",
            entry_point_value="stigmem_plugin_tombstones:plugin_manifest",
            distribution=tomb_manifest.name,
        )
        _include_plugin_routers(app, (discovered,))
        with TestClient(app, raise_server_exceptions=True) as c:
            tombstones_mod.invalidate_tombstone_cache()
            yield c, key_a, key_b, db_file

    tombstones_mod.invalidate_tombstone_cache()
    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


def _assert_fact(client: TestClient, key: str, entity: str, value: str) -> str:
    resp = client.post(
        "/v1/facts",
        json={
            "entity": entity,
            "relation": "test:color",
            "value": {"type": "string", "v": value},
            "source": "agent:test",
        },
        headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _insert_tombstone(db_file: str, entity_uri: str, tenant_id: str) -> str:
    """Insert an active tombstone row for *entity_uri* in *tenant_id* directly via SQL."""
    tomb_id = "tomb_" + str(uuid.uuid4())
    conn = sqlite3.connect(db_file)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tomb_id,
                entity_uri,
                "*",
                None,
                "agent:issuer",
                "key-1",
                "sig",
                "2026-06-10T00:00:00Z",
                0,
                tenant_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    tombstones_mod.invalidate_tombstone_cache()
    return tomb_id


def _query_entities(client: TestClient, key: str, entity: str) -> set[str]:
    resp = client.get(
        "/v1/facts",
        params={"entity": entity},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert resp.status_code == 200, resp.text
    return {f["entity"] for f in resp.json()["facts"]}


# ---------------------------------------------------------------------------
# 1. Read-path (the TA-7 test): a tenant-B tombstone must NOT hide tenant-A facts
# ---------------------------------------------------------------------------


def test_cross_tenant_tombstone_does_not_suppress(
    tenant_tombstone_app: tuple[TestClient, str, str, str],
) -> None:
    client, key_a, _key_b, db_file = tenant_tombstone_app
    entity = "stigmem://test/shared-entity-x"

    _assert_fact(client, key_a, entity, "alice-value")

    # A tombstone owned by tenant-b for the same entity.
    _insert_tombstone(db_file, entity, tenant_id="tenant-b")

    # Tenant-a's fact about X must still be visible — the tenant-b tombstone is not
    # in tenant-a's partition and must not suppress it.
    visible = _query_entities(client, key_a, entity)
    assert entity in visible, "tenant-b tombstone wrongly suppressed tenant-a's fact"


# ---------------------------------------------------------------------------
# 2. Write-path: a tenant-B caller's issued tombstone is stored with tenant_id=tenant-b
# ---------------------------------------------------------------------------


def test_issued_tombstone_stamped_with_caller_tenant(
    tenant_tombstone_app: tuple[TestClient, str, str, str],
) -> None:
    client, _key_a, key_b, db_file = tenant_tombstone_app
    entity = "stigmem://test/bob-rtbf-entity"

    resp = client.post(
        "/v1/tombstones",
        json={"entity_uri": entity, "scope": "local"},
        headers={"Authorization": f"Bearer {key_b}"},
    )
    assert resp.status_code == 201, resp.text
    tomb_id = resp.json()["id"]

    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM tombstones WHERE id = ?", (tomb_id,)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == "tenant-b", f"expected tenant-b, got {row[0]!r} (defaulted to 'default'?)"


# ---------------------------------------------------------------------------
# 3. Same-tenant still works: a tenant-B tombstone DOES suppress tenant-B's facts
# ---------------------------------------------------------------------------


def test_same_tenant_tombstone_suppresses(
    tenant_tombstone_app: tuple[TestClient, str, str, str],
) -> None:
    client, _key_a, key_b, db_file = tenant_tombstone_app
    entity = "stigmem://test/bob-suppressed-entity"

    _assert_fact(client, key_b, entity, "bob-value")

    _insert_tombstone(db_file, entity, tenant_id="tenant-b")

    visible = _query_entities(client, key_b, entity)
    assert entity not in visible, "tenant-b tombstone failed to suppress tenant-b's own fact"
