"""Quarantine tenant-scoping regression tests (R-2 / F-SBOLA5).

The quarantine list + moderation surface must only expose facts belonging to
the caller's tenant. Before the fix the list endpoint treated a per-NODE admin
as cross-tenant ("Node admins see all quarantined facts across all gardens"),
and the admit/reject helper looked up a fact by id without a tenant predicate —
so a tenant-B admin could read AND admit/reject another tenant's quarantined
facts. Everything is now scoped to `identity.tenant_id`; a tenant-B admin must
not see or touch tenant-A quarantine.

These tests exercise the real HTTP path with the multi-tenant plugin active so
the tenant-B key resolves to its own tenant (without the plugin the node
collapses every key to the default tenant, which would defeat the test).
"""

from __future__ import annotations

import importlib
import sys
import uuid
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app
from stigmem_node.models.constants import QUARANTINE_PENDING
from stigmem_node.plugins.testing import stigmem_plugins

_PLUGIN_SRC = Path(__file__).resolve().parents[2] / "experimental" / "multi-tenant" / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

_PLUGIN = importlib.import_module("stigmem_plugin_multi_tenant")
plugin_manifest = _PLUGIN.plugin_manifest

# The owning tenant (creates the garden + the quarantined fact) and the
# attacking tenant (a different tenant's admin attempting cross-tenant access).
OWNER_TENANT = "default"
ATTACKER_TENANT = "tenant-b"


@pytest.fixture()
def node(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> Generator[tuple[TestClient, str, str, str], None, None]:
    """Node with the multi-tenant plugin active: an owner admin + an attacker admin."""
    db_file = str(tmp_path) + "/q_tenant.db"  # type: ignore[operator]
    db_mod.apply_migrations(db_path=db_file)

    original = settings_module.settings
    ts = settings_module.Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://qnode",
        trust_mode="relaxed",
        sanitizer_mode="warn",
    )
    settings_module.settings = ts
    auth_mod.settings = ts
    db_mod.settings = ts

    owner_admin_key = auth_mod.create_api_key(
        "stigmem://qnode/agent/admin", ["read", "write"], tenant_id=OWNER_TENANT
    )
    attacker_admin_key = auth_mod.create_api_key(
        "stigmem://qnode/agent/admin-b", ["read", "write"], tenant_id=ATTACKER_TENANT
    )

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    with stigmem_plugins([plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client, owner_admin_key, attacker_admin_key, db_file

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


def _ah(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _inject_quarantined_fact(garden_uuid: str, *, tenant_id: str) -> str:
    """Insert one pending quarantined fact for the given tenant via direct SQL."""
    fact_id = str(uuid.uuid4())
    with db_mod.db() as conn:
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, quarantine_garden_id,
                quarantine_status, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                "e:1",
                "r:1",
                "string",
                "v1",
                "src:1",
                "2026-01-01T00:00:00",
                None,
                0.9,
                "local",
                "0",
                garden_uuid,
                QUARANTINE_PENDING,
                tenant_id,
            ),
        )
    return fact_id


def _create_owner_quarantine_garden(client: TestClient, owner_admin_key: str) -> str:
    """Create a quarantine garden owned by the owner tenant's admin."""
    r = client.post(
        "/v1/gardens",
        json={"slug": "q-owner", "name": "Q Owner", "scope": "local", "quarantine": True},
        headers=_ah(owner_admin_key),
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_list_excludes_other_tenants_quarantined_fact(node):
    """An attacker-tenant admin must not see (or count) the owner tenant's fact."""
    client, owner_admin_key, attacker_admin_key, _db_file = node
    garden_uuid = _create_owner_quarantine_garden(client, owner_admin_key)
    fid = _inject_quarantined_fact(garden_uuid, tenant_id=OWNER_TENANT)

    # Sanity: the owning tenant admin DOES see it.
    r_owner = client.get("/v1/quarantine", headers=_ah(owner_admin_key))
    assert r_owner.status_code == 200, r_owner.text
    assert fid in [i["fact_id"] for i in r_owner.json()["items"]]

    # The attacker tenant admin must NOT see it, and total must exclude it.
    r_attacker = client.get("/v1/quarantine", headers=_ah(attacker_admin_key))
    assert r_attacker.status_code == 200, r_attacker.text
    body = r_attacker.json()
    assert fid not in [i["fact_id"] for i in body["items"]]
    assert body["total"] == 0


def test_admit_other_tenants_fact_returns_404(node):
    """An attacker-tenant admin admitting the owner tenant's fact gets 404."""
    client, owner_admin_key, attacker_admin_key, _db_file = node
    garden_uuid = _create_owner_quarantine_garden(client, owner_admin_key)
    fid = _inject_quarantined_fact(garden_uuid, tenant_id=OWNER_TENANT)

    r = client.post(f"/v1/quarantine/{fid}/admit", headers=_ah(attacker_admin_key))
    assert r.status_code == 404, r.text


def test_reject_other_tenants_fact_returns_404(node):
    """An attacker-tenant admin rejecting the owner tenant's fact gets 404."""
    client, owner_admin_key, attacker_admin_key, _db_file = node
    garden_uuid = _create_owner_quarantine_garden(client, owner_admin_key)
    fid = _inject_quarantined_fact(garden_uuid, tenant_id=OWNER_TENANT)

    r = client.post(f"/v1/quarantine/{fid}/reject", headers=_ah(attacker_admin_key))
    assert r.status_code == 404, r.text
