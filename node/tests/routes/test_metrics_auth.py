"""M11 / F-AVAIL-1: /metrics requires admin auth by default.

Tests (a-e):
(a) metrics_require_auth=True, no auth      → 401 + WWW-Authenticate: Bearer
(b) metrics_require_auth=True, admin cred   → 200 + Prometheus text body
(c) metrics_require_auth=True, non-admin    → 403
(d) metrics_require_auth=False, no auth     → 200 (private-scrape-interface path)
(e) regression: /metrics with admin key still returns 200 (formerly unauthenticated 200)
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.main as main_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings


# ---------------------------------------------------------------------------
# Fixture helpers (mirrors conftest._patch_settings / _restore_settings)
# ---------------------------------------------------------------------------


def _make_test_settings(tmp_db: str, **overrides: object) -> Settings:
    base: dict[str, object] = {
        "db_path": tmp_db,
        "storage_backend": "sqlite",
        "subscription_delivery_sweep_s": 86400,
        "node_url": "http://testnode",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


_PATCH_TARGETS = (settings_module, auth_mod, db_mod, wk_mod, main_mod)


def _patch(s: Settings) -> dict[object, Settings]:
    # Snapshot each module's *own* current ``settings`` and restore them
    # independently. Capturing a single ``settings_module.settings`` and writing
    # it back to every module (including ``main``) is unsafe: the suite shares
    # one process and an upstream test can leave ``settings_module.settings``
    # pointing at unrelated federation test settings (``node_url`` not loopback).
    # ``main`` is the only module whose ``settings`` the federation transport
    # check reads at app startup, so propagating a polluted value into it makes
    # every subsequent app-startup raise. Per-module snapshots keep each
    # reference at the value it genuinely held before this fixture ran.
    originals: dict[object, Settings] = {mod: mod.settings for mod in _PATCH_TARGETS}
    for mod in _PATCH_TARGETS:
        mod.settings = s  # type: ignore[attr-defined]
    return originals


def _restore(originals: dict[object, Settings]) -> None:
    for mod, original in originals.items():
        mod.settings = original  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Fixture: auth=True, metrics_require_auth=True → (client, admin_key, reader_key)
# ---------------------------------------------------------------------------


@pytest.fixture()
def metrics_authed(
    tmp_db: str,
) -> Generator[tuple[TestClient, str, str], None, None]:
    """TestClient with auth=True + metrics_require_auth=True (default).

    Yields (client, admin_key, reader_key).
    """
    test_settings = _make_test_settings(
        tmp_db, auth_required=True, metrics_require_auth=True
    )
    originals = _patch(test_settings)

    admin_key = create_api_key("agent:admin-scraper", ["admin"])
    reader_key = create_api_key("agent:reader", ["read", "write"])

    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c, admin_key, reader_key
    finally:
        _restore(originals)


# ---------------------------------------------------------------------------
# Fixture: auth=False, metrics_require_auth=False → client (opt-out path)
# ---------------------------------------------------------------------------


@pytest.fixture()
def metrics_opt_out(
    tmp_db: str,
) -> Generator[TestClient, None, None]:
    """TestClient with metrics_require_auth=False (operator-controlled private scrape)."""
    test_settings = _make_test_settings(
        tmp_db,
        auth_required=False,
        metrics_require_auth=False,
        node_url="http://localhost:8765",
    )
    originals = _patch(test_settings)

    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
    finally:
        _restore(originals)


# ---------------------------------------------------------------------------
# (a) No auth → 401 + WWW-Authenticate: Bearer
# ---------------------------------------------------------------------------


def test_metrics_no_auth_returns_401(
    metrics_authed: tuple[TestClient, str, str],
) -> None:
    """(a) GET /metrics without credentials must return 401 with WWW-Authenticate: Bearer."""
    client, _admin_key, _reader_key = metrics_authed
    resp = client.get("/metrics")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
    assert "bearer" in resp.headers.get("www-authenticate", "").lower(), (
        f"Expected WWW-Authenticate: Bearer header; got: {resp.headers}"
    )


# ---------------------------------------------------------------------------
# (b) Valid admin credential → 200 + text body
# ---------------------------------------------------------------------------


def test_metrics_admin_returns_200(
    metrics_authed: tuple[TestClient, str, str],
) -> None:
    """(b) GET /metrics with admin credential must return 200."""
    client, admin_key, _reader_key = metrics_authed
    resp = client.get("/metrics", headers={"Authorization": f"Bearer {admin_key}"})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.headers["content-type"].startswith("text/"), (
        f"Expected text/* content-type, got {resp.headers['content-type']}"
    )


# ---------------------------------------------------------------------------
# (c) Valid non-admin credential → 403
# ---------------------------------------------------------------------------


def test_metrics_non_admin_returns_403(
    metrics_authed: tuple[TestClient, str, str],
) -> None:
    """(c) GET /metrics with valid non-admin credential must return 403."""
    client, _admin_key, reader_key = metrics_authed
    resp = client.get("/metrics", headers={"Authorization": f"Bearer {reader_key}"})
    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# (d) metrics_require_auth=False → 200 with no credentials
# ---------------------------------------------------------------------------


def test_metrics_opt_out_serves_unauthenticated(
    metrics_opt_out: TestClient,
) -> None:
    """(d) metrics_require_auth=False must serve /metrics without any credentials."""
    resp = metrics_opt_out.get("/metrics")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.headers["content-type"].startswith("text/"), (
        f"Expected text/* content-type, got {resp.headers['content-type']}"
    )


# ---------------------------------------------------------------------------
# (e) Regression: /metrics with admin key returns 200 (replaces old unauthenticated check)
# ---------------------------------------------------------------------------


def test_metrics_admin_key_regression(
    metrics_authed: tuple[TestClient, str, str],
) -> None:
    """(e) Regression guard: /metrics with admin auth returns 200 + text body."""
    client, admin_key, _reader_key = metrics_authed
    resp = client.get("/metrics", headers={"Authorization": f"Bearer {admin_key}"})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/")
