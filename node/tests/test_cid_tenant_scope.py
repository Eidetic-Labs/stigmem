"""Fact CID-alias tenant-scoping regression tests (F-SBOLA4).

The fact_cid_aliases table had a GLOBAL unique index on ``cid`` and
``_existing_record_for_cid`` ignored the tenant_id it was passed, so identical
content asserted by two tenants collided: tenant B's alias row was silently
dropped (content unaddressable + an existence oracle for tenant A's content).
After the fix the uniqueness and the dedup pre-check are scoped to the tenant,
so each tenant gets its own fact_id and its own alias row.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from conftest import _patch_settings, _restore_settings  # type: ignore[import-not-found]
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app
from stigmem_node.plugins.testing import stigmem_plugins

_PLUGIN_SRC = Path(__file__).resolve().parents[2] / "experimental" / "multi-tenant" / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

_PLUGIN = importlib.import_module("stigmem_plugin_multi_tenant")

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings
plugin_manifest = _PLUGIN.plugin_manifest

# Identical content asserted by both tenants — same computed CID.
FACT = {
    "entity": "stigmem://test/user/alice",
    "relation": "test:role",
    "value": {"type": "string", "v": "admin"},
    "source": "stigmem://test/source/hr",
    "confidence": 0.9,
    "scope": "local",
}


@pytest.fixture()
def two_tenants_cid(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str, str], None, None]:
    """Two tenant keys + multi-tenant plugin; yields (client, key_a, key_b, db_path)."""
    db_file = str(tmp_path) + "/mt-cid.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    extra = _patch_settings(test_settings)

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    try:
        with stigmem_plugins([plugin_manifest()]):
            app = create_app()
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c, key_a, key_b, db_file
    finally:
        _restore_settings(original, extra)


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def test_identical_content_not_deduped_across_tenants(
    two_tenants_cid: tuple[TestClient, str, str, str],
) -> None:
    client, key_a, key_b, db_path = two_tenants_cid

    ra = client.post("/v1/facts", json=FACT, headers=_auth(key_a))
    assert ra.status_code == 201, ra.text
    fact_id_a = ra.json()["id"]

    # Tenant B asserts the SAME content: must get its OWN fact, not dedup to A's.
    rb = client.post("/v1/facts", json=FACT, headers=_auth(key_b))
    assert rb.status_code == 201, rb.text
    fact_id_b = rb.json()["id"]

    assert fact_id_a != fact_id_b, "tenant B was deduped to tenant A's fact (cross-tenant dedup)"

    # Both alias rows exist, each tagged with its own tenant_id, sharing the same CID.
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT fact_id, tenant_id, cid FROM fact_cid_aliases ORDER BY tenant_id"
        ).fetchall()
    finally:
        conn.close()

    by_fact = {r[0]: (r[1], r[2]) for r in rows}
    assert fact_id_a in by_fact, "tenant A alias row missing"
    assert fact_id_b in by_fact, "tenant B alias row missing (collided on global unique cid)"
    assert by_fact[fact_id_a][0] == "tenant-a"
    assert by_fact[fact_id_b][0] == "tenant-b"
    # Same content → same CID, now distinguished only by tenant_id.
    assert by_fact[fact_id_a][1] == by_fact[fact_id_b][1]
