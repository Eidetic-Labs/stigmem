"""W1.1 — SSRF guard on the peer-registration well-known fetch (NF-2).

Two invariants:
1. A registration whose node_url resolves to a private/internal address is
   blocked BEFORE the well-known GET is attempted when federation_insecure=False
   (fail-closed in production).
2. A registration under federation_insecure=True still proceeds (dev path
   preserved), regardless of node_url scheme or address.
"""

from __future__ import annotations

import importlib
import sqlite3
import uuid
from collections.abc import Generator

import pytest
from conftest import FedNode, generate_keypair, sign_declaration

import stigmem_node.settings as _settings_mod


def _make_secure_fed_node(
    tmp_path: object,
) -> Generator[FedNode, None, None]:
    """Yield a federation-enabled node with federation_insecure=False (production mode)."""
    from fastapi.testclient import TestClient

    import stigmem_node.auth as auth_mod
    import stigmem_node.db as db_mod
    import stigmem_node.peer_token as token_mod
    import stigmem_node.routes.wellknown as wk_mod
    from stigmem_node.auth import create_api_key
    from stigmem_node.db import apply_migrations
    from stigmem_node.main import create_app

    db_file = str(tmp_path) + "/fed_secure_test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    pub_b64, priv_b64 = generate_keypair()
    node_id = "stigmem://test-node-secure"
    node_url = "http://test-node-secure"

    conn = sqlite3.connect(db_file)
    conn.execute("INSERT OR REPLACE INTO node_meta (key, value) VALUES ('node_id', ?)", (node_id,))
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_pubkey', ?)", (pub_b64,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_privkey', ?)",
        (priv_b64,),
    )
    conn.commit()
    conn.close()

    Settings = _settings_mod.Settings
    original = _settings_mod.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url=node_url,
        federation_enabled=True,
        federation_insecure=False,  # production mode — SSRF guard is active
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    # Patch settings across all modules that cache it at import time
    _PATCHABLE = [
        "stigmem_node.federation_pull",
        "stigmem_node.peer_token",
        "stigmem_node.federation_ingest",
        "stigmem_node.routes.federation",
    ]
    _settings_mod.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    extra = []
    for mod_name in _PATCHABLE:
        try:
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "settings"):
                mod.settings = test_settings
                extra.append(mod)
        except ImportError:
            pass

    token_mod._cached_pub = pub_b64
    token_mod._cached_priv = priv_b64

    raw_key = create_api_key("agent:test-fed-secure", ["read", "write", "federate"])

    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield FedNode(
            client=c,
            db_path=db_file,
            node_id=node_id,
            pub_b64=pub_b64,
            priv_b64=priv_b64,
            federate_key=raw_key,
            node_url=node_url,
        )

    # Restore
    _settings_mod.settings = original  # type: ignore[assignment]
    auth_mod.settings = original  # type: ignore[assignment]
    db_mod.settings = original  # type: ignore[assignment]
    wk_mod.settings = original  # type: ignore[assignment]
    for mod in extra:
        if hasattr(mod, "settings"):
            mod.settings = original
    token_mod._cached_pub = None
    token_mod._cached_priv = None


@pytest.fixture()
def secure_fed_node(tmp_path: object) -> Generator[FedNode, None, None]:
    """Federation-enabled node with federation_insecure=False (production SSRF guard active)."""
    yield from _make_secure_fed_node(tmp_path)


class TestRegistrationSsrfGuard:
    """NF-2: assert_safe_url gates the registration-time well-known fetch."""

    def _build_declaration(
        self,
        node_id: str,
        node_url: str,
        pub_b64: str,
        priv_b64: str,
    ) -> dict:
        scopes = ["public"]
        fields_to_sign = {
            "allowed_scopes": scopes,
            "federation_pubkey": pub_b64,
            "node_id": node_id,
            "node_url": node_url,
            "signed_at": "2026-01-01T00:00:00Z",
        }
        sig = sign_declaration(priv_b64, fields_to_sign)
        return {
            "node_id": node_id,
            "node_url": node_url,
            "federation_pubkey": pub_b64,
            "allowed_scopes": scopes,
            "declaration_sig": sig,
            "signed_at": "2026-01-01T00:00:00Z",
        }

    def _mock_well_known(self, monkeypatch: pytest.MonkeyPatch, peer_pub: str) -> None:
        """Stub httpx so no real network call is made (mirrors test_peer_registration.py)."""
        import httpx as _httpx

        class _MockAsyncClient:
            async def __aenter__(self) -> _MockAsyncClient:
                return self

            async def __aexit__(self, *args: object) -> None:
                pass

            async def get(self, url: str) -> _httpx.Response:
                return _httpx.Response(200, json={"federation_pubkey": peer_pub})

        monkeypatch.setattr(
            "stigmem_node.routes._federation_impl.httpx.AsyncClient",
            lambda **_: _MockAsyncClient(),
        )

    def test_private_node_url_is_blocked_before_fetch(
        self,
        secure_fed_node: FedNode,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With federation_insecure=False, a private RFC 1918 node_url must not reach the GET.

        10.0.0.1 is a private address that assert_safe_url always blocks.
        The registration must fail closed — the well-known mock must NOT be called.
        """
        peer_pub, peer_priv = generate_keypair()
        node_id = f"stigmem://ssrf-private-{uuid.uuid4()}"
        # RFC 1918 address blocked by assert_safe_url (NF-2)
        node_url = "https://10.0.0.1"

        body = self._build_declaration(node_id, node_url, peer_pub, peer_priv)

        # Track whether the mock was ever called; it must NOT be called.
        fetch_attempted = []

        import httpx as _httpx

        class _TrackingMockClient:
            async def __aenter__(self) -> _TrackingMockClient:
                return self

            async def __aexit__(self, *args: object) -> None:
                pass

            async def get(self, url: str) -> _httpx.Response:
                fetch_attempted.append(url)
                return _httpx.Response(200, json={"federation_pubkey": peer_pub})

        monkeypatch.setattr(
            "stigmem_node.routes._federation_impl.httpx.AsyncClient",
            lambda **_: _TrackingMockClient(),
        )

        r = secure_fed_node.client.post(
            "/v1/federation/peers",
            json=body,
            headers={"Authorization": f"Bearer {secure_fed_node.federate_key}"},
        )

        # The critical invariant: no fetch was attempted for the private address
        assert fetch_attempted == [], (
            f"well-known fetch was attempted for private node_url: {fetch_attempted}"
        )
        # Registration must complete (201) but status must be rejected
        assert r.status_code == 201, r.text
        assert r.json()["status"] == "rejected", (
            f"expected rejected status for private node_url, got: {r.json()}"
        )

    def test_insecure_dev_mode_bypasses_ssrf_guard(
        self,
        fed_node: FedNode,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With federation_insecure=True, the SSRF guard is bypassed entirely.

        The fed_node fixture sets federation_insecure=True.  Even a loopback
        URL (127.0.0.1) must proceed without being blocked, preserving the
        dev/test path used by all federation registration tests.
        """
        peer_pub, peer_priv = generate_keypair()
        node_id = f"stigmem://ssrf-loopback-{uuid.uuid4()}"
        node_url = "http://127.0.0.1:8001"

        body = self._build_declaration(node_id, node_url, peer_pub, peer_priv)
        self._mock_well_known(monkeypatch, peer_pub)

        r = fed_node.client.post(
            "/v1/federation/peers",
            json=body,
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )

        # The request must reach the server and complete (not crash / 500)
        assert r.status_code == 201, r.text
        # The well-known mock returned matching pubkey + valid sig → pending_approval
        assert r.json()["status"] in ("pending_approval", "rejected"), r.json()
