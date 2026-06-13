"""Async-job tenant-scoping regression tests (F-SBOLA2).

The async ``jobs`` table backs lint/decay job-status polling. Before the fix the
table had no ``tenant_id`` and ``get_job(job_id, job_type)`` selected by id+type
only, so any caller who learned a job UUID could read it cross-tenant. These
tests drive the public HTTP surface: a tenant-B caller polling a job created
under another tenant must get a 404 (not found), never the other tenant's job
record.
"""

from __future__ import annotations

import importlib
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

FACT = {
    "entity": "stigmem://test/user/alice",
    "relation": "test:role",
    "value": {"type": "string", "v": "admin"},
    "source": "stigmem://test/source/hr",
    "confidence": 0.9,
    "scope": "local",
}


@pytest.fixture()
def two_tenants_async(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str], None, None]:
    """Two tenant keys + multi-tenant plugin, with async_job_threshold=0 so any
    non-empty scope takes the async (202 + job_id) path and creates a job row."""
    db_file = str(tmp_path) + "/mt-jobs.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        async_job_threshold=0,
    )
    extra = _patch_settings(test_settings)

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    try:
        with stigmem_plugins([plugin_manifest()]):
            app = create_app()
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c, key_a, key_b
    finally:
        _restore_settings(original, extra)


def _auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def test_decay_job_not_readable_cross_tenant(
    two_tenants_async: tuple[TestClient, str, str],
) -> None:
    client, key_a, key_b = two_tenants_async

    # Tenant A seeds a fact and triggers an async decay job (threshold=0).
    assert client.post("/v1/facts", json=FACT, headers=_auth(key_a)).status_code == 201
    r = client.post("/v1/decay/sweep?ttl_seconds=0", headers=_auth(key_a))
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    # Tenant A can read its own job.
    own = client.get(f"/v1/decay/jobs/{job_id}", headers=_auth(key_a))
    assert own.status_code == 200, own.text

    # Tenant B knows the UUID but must not be able to read it.
    leaked = client.get(f"/v1/decay/jobs/{job_id}", headers=_auth(key_b))
    assert leaked.status_code == 404, leaked.text


def test_lint_job_not_readable_cross_tenant(
    two_tenants_async: tuple[TestClient, str, str],
) -> None:
    client, key_a, key_b = two_tenants_async

    assert client.post("/v1/facts", json=FACT, headers=_auth(key_a)).status_code == 201
    r = client.post("/v1/lint", json={"scope": "local"}, headers=_auth(key_a))
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]

    own = client.get(f"/v1/lint/jobs/{job_id}", headers=_auth(key_a))
    assert own.status_code == 200, own.text

    leaked = client.get(f"/v1/lint/jobs/{job_id}", headers=_auth(key_b))
    assert leaked.status_code == 404, leaked.text
