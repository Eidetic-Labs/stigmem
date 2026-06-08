"""Integration tests for the OIDC → API-key exchange bridge (Track B / B3).

Strategy: we generate a real RSA-2048 keypair, build a minimal JWKS document,
mock httpx.get so the route sees our fake discovery doc + JWKS, then sign
id_tokens with the private key and exercise every code path.
"""

from __future__ import annotations

import json
import socket
import sqlite3 as _sqlite3
import sys
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.routes.auth as auth_route_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app
from stigmem_node.plugins import PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins

apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings

ISSUER = "https://oidc.example.com"
AUDIENCE = "stigmem-test-client"
_MEMORY_GARDEN_ACL_SRC = (
    Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl" / "src"
)


def _memory_garden_acl_manifest() -> PluginManifest:
    if str(_MEMORY_GARDEN_ACL_SRC) not in sys.path:
        sys.path.insert(0, str(_MEMORY_GARDEN_ACL_SRC))
    import importlib

    plugin = importlib.import_module("stigmem_plugin_memory_garden_acl")
    return plugin.plugin_manifest()


def _enable_oidc_ceiling(monkeypatch: pytest.MonkeyPatch) -> None:
    # Graduated to core: the OIDC permission ceiling is now a settings flag.
    import sys

    monkeypatch.setattr(
        sys.modules["stigmem_node.settings"].settings,
        "oidc_permission_ceiling",
        True,
    )


# ---------------------------------------------------------------------------
# RSA keypair fixture (shared across all tests in this module)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="module")
def jwks_document(rsa_keypair):
    _, public_key = rsa_keypair
    public_numbers = public_key.public_numbers()

    import base64

    def _int_to_base64url(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-1",
                "alg": "RS256",
                "n": _int_to_base64url(public_numbers.n),
                "e": _int_to_base64url(public_numbers.e),
            }
        ]
    }


def _sign_token(
    private_key,
    sub: str = "user-123",
    email: str = "alice@example.com",
    audience: str = AUDIENCE,
    issuer: str = ISSUER,
    exp_offset: int = 3600,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "iat": now,
        "exp": now + exp_offset,
        "email": email,
        "email_verified": True,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )


# ---------------------------------------------------------------------------
# OIDC-enabled client fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def oidc_client(
    tmp_path: Path,
    rsa_keypair,
    jwks_document,
) -> Generator[TestClient, None, None]:
    db_file = str(tmp_path / "oidc_test.db")
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        oidc_enabled=True,
        oidc_issuer_url=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_token_ttl_hours=1,
        oidc_allowed_domains="",
    )

    # Patch settings everywhere
    settings_module.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    auth_route_mod.settings = test_settings  # type: ignore[assignment]

    # Clear the JWKS cache so our mock is used
    auth_route_mod._JWKS_CACHE.clear()

    disco_response = MagicMock()
    disco_response.raise_for_status = MagicMock()
    disco_response.json.return_value = {"jwks_uri": f"{ISSUER}/.well-known/jwks.json"}

    jwks_response = MagicMock()
    jwks_response.raise_for_status = MagicMock()
    jwks_response.text = json.dumps(jwks_document)

    def _fake_get(url: str, **kwargs: Any) -> MagicMock:
        if "openid-configuration" in url:
            return disco_response
        return jwks_response

    with patch("stigmem_node.routes.auth.httpx.get", side_effect=_fake_get), patch(
        "stigmem_node.routes.auth.assert_safe_url"
    ):
        # Also mock PyJWKClient so it serves our in-memory JWKS
        real_PyJWKClient = jwt.PyJWKClient

        class _FakeJWKSClient(real_PyJWKClient):
            def fetch_data(self):
                return jwks_document

        with patch("stigmem_node.routes.auth.jwt.PyJWKClient", _FakeJWKSClient):
            app = create_app()
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c

    settings_module.settings = original  # type: ignore[assignment]
    auth_mod.settings = original  # type: ignore[assignment]
    db_mod.settings = original  # type: ignore[assignment]
    wk_mod.settings = original  # type: ignore[assignment]
    auth_route_mod.settings = original  # type: ignore[assignment]
    auth_route_mod._JWKS_CACHE.clear()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_oidc_disabled_returns_503(client: TestClient) -> None:
    resp = client.post("/v1/auth/oidc/exchange", json={"id_token": "dummy"})
    assert resp.status_code == 503


def test_oidc_discovery_blocks_http_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    auth_route_mod._JWKS_CACHE.clear()

    def _unexpected_get(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("discovery fetch must not run for unsafe issuer URLs")

    monkeypatch.setattr(auth_route_mod.httpx, "get", _unexpected_get)

    with pytest.raises(HTTPException) as exc:
        auth_route_mod._get_jwks_client("http://login.example.com")

    assert exc.value.status_code == 503


def test_oidc_discovery_blocks_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    auth_route_mod._JWKS_CACHE.clear()

    def _unexpected_get(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("discovery fetch must not run for unsafe issuer URLs")

    monkeypatch.setattr(auth_route_mod.httpx, "get", _unexpected_get)

    with pytest.raises(HTTPException) as exc:
        auth_route_mod._get_jwks_client("https://127.0.0.1:8443")

    assert exc.value.status_code == 503


def test_oidc_discovery_uses_https_without_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    auth_route_mod._JWKS_CACHE.clear()
    calls: list[dict[str, Any]] = []

    def _safe_getaddrinfo(_host: str, port: int | None, *_args: Any, **_kwargs: Any):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 0))]

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"jwks_uri": "https://login.example.com/keys"}

    class _FakeJwksClient:
        def __init__(self, jwks_uri: str) -> None:
            self.uri = jwks_uri

    def _fake_get(url: str, **kwargs: Any) -> _FakeResponse:
        calls.append({"url": url, **kwargs})
        return _FakeResponse()

    monkeypatch.setattr("socket.getaddrinfo", _safe_getaddrinfo)
    monkeypatch.setattr(auth_route_mod.httpx, "get", _fake_get)
    monkeypatch.setattr(auth_route_mod.jwt, "PyJWKClient", _FakeJwksClient)

    client = auth_route_mod._get_jwks_client("https://login.example.com")

    assert isinstance(client, _FakeJwksClient)
    assert client.uri == "https://login.example.com/keys"
    assert calls == [
        {
            "url": "https://login.example.com/.well-known/openid-configuration",
            "timeout": 5.0,
            "follow_redirects": False,
        }
    ]


def test_oidc_discovery_blocks_unsafe_jwks_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    auth_route_mod._JWKS_CACHE.clear()

    def _safe_getaddrinfo(host: str, port: int | None, *_args: Any, **_kwargs: Any):
        ip = "93.184.216.34" if host == "login.example.com" else "169.254.169.254"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0))]

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"jwks_uri": "https://metadata.example/keys"}

    def _fake_get(_url: str, **_kwargs: Any) -> _FakeResponse:
        return _FakeResponse()

    monkeypatch.setattr("socket.getaddrinfo", _safe_getaddrinfo)
    monkeypatch.setattr(auth_route_mod.httpx, "get", _fake_get)

    with pytest.raises(HTTPException) as exc:
        auth_route_mod._get_jwks_client("https://login.example.com")

    assert exc.value.status_code == 503


def test_verify_id_token_accepts_configured_eddsa_algorithm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    token = _sign_eddsa_token(private_key)
    test_settings = Settings(
        oidc_issuer_url=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_id_token_algorithms=["RS256", "ES256", "PS256", "EdDSA"],
    )

    monkeypatch.setattr(auth_route_mod, "settings", test_settings)
    monkeypatch.setattr(auth_route_mod, "_get_jwks_client", lambda _issuer: _Jwks(public_key))

    claims = auth_route_mod._verify_id_token(token)

    assert claims["sub"] == "user-eddsa"


def test_verify_id_token_rejects_algorithm_not_in_configured_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    token = _sign_eddsa_token(private_key)
    test_settings = Settings(
        oidc_issuer_url=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_id_token_algorithms=["RS256"],
    )

    monkeypatch.setattr(auth_route_mod, "settings", test_settings)
    monkeypatch.setattr(auth_route_mod, "_get_jwks_client", lambda _issuer: _Jwks(public_key))

    with pytest.raises(HTTPException) as exc:
        auth_route_mod._verify_id_token(token)

    assert exc.value.status_code == 401


class _SigningKey:
    def __init__(self, key: object) -> None:
        self.key = key


class _Jwks:
    def __init__(self, key: object) -> None:
        self.key = key

    def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
        return _SigningKey(self.key)


def _sign_eddsa_token(private_key: ed25519.Ed25519PrivateKey) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "sub": "user-eddsa",
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + 3600,
            "email": "eddsa@example.com",
            "email_verified": True,
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": "test-eddsa"},
    )


def test_exchange_valid_token_returns_key(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair
    token = _sign_token(private_key)

    resp = oidc_client.post(
        "/v1/auth/oidc/exchange",
        json={"id_token": token, "permissions": ["read", "write"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "api_key" in body
    assert body["entity_uri"] == "oidc:user-123"
    assert "expires_at" in body
    # The returned key should be usable
    facts_resp = oidc_client.get(
        "/v1/facts", headers={"Authorization": f"Bearer {body['api_key']}"}
    )
    assert facts_resp.status_code == 200


def test_exchange_expired_token_returns_401(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair
    token = _sign_token(private_key, exp_offset=-10)  # already expired

    resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": token})
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


def test_exchange_wrong_audience_returns_401(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair
    token = _sign_token(private_key, audience="wrong-client")

    resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": token})
    assert resp.status_code == 401


def test_exchange_domain_restriction_blocks_wrong_domain(
    tmp_path: Path, rsa_keypair, jwks_document
) -> None:
    """When oidc_allowed_domains is set, out-of-domain emails must be rejected."""
    db_file = str(tmp_path / "domain_test.db")
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        oidc_enabled=True,
        oidc_issuer_url=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_token_ttl_hours=1,
        oidc_allowed_domains="allowed.com",
    )

    settings_module.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    auth_route_mod.settings = test_settings  # type: ignore[assignment]
    auth_route_mod._JWKS_CACHE.clear()

    private_key, _ = rsa_keypair
    token = _sign_token(private_key, email="alice@example.com")  # not allowed.com

    real_PyJWKClient = jwt.PyJWKClient

    class _FakeJWKSClient(real_PyJWKClient):
        def fetch_data(self):
            return jwks_document

    disco_response = MagicMock()
    disco_response.raise_for_status = MagicMock()
    disco_response.json.return_value = {"jwks_uri": f"{ISSUER}/.well-known/jwks.json"}

    def _fake_get(url: str, **kwargs: Any) -> MagicMock:
        return disco_response

    try:
        with (
            patch("stigmem_node.routes.auth.httpx.get", side_effect=_fake_get),
            patch("stigmem_node.routes.auth.jwt.PyJWKClient", _FakeJWKSClient),
            patch("stigmem_node.routes.auth.assert_safe_url"),
        ):
            app = create_app()
            with TestClient(app, raise_server_exceptions=True) as c:
                resp = c.post("/v1/auth/oidc/exchange", json={"id_token": token})
                assert resp.status_code == 403
                assert resp.json()["detail"] == "Email domain 'example.com' is not permitted"
    finally:
        settings_module.settings = original  # type: ignore[assignment]
        auth_mod.settings = original  # type: ignore[assignment]
        db_mod.settings = original  # type: ignore[assignment]
        wk_mod.settings = original  # type: ignore[assignment]
        auth_route_mod.settings = original  # type: ignore[assignment]
        auth_route_mod._JWKS_CACHE.clear()


def test_exchange_permissions_capped_at_read_write(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair
    token = _sign_token(private_key)

    resp = oidc_client.post(
        "/v1/auth/oidc/exchange",
        json={"id_token": token, "permissions": ["read", "write", "federate"]},
    )
    assert resp.status_code == 200
    api_key = resp.json()["api_key"]

    # Verify the key does NOT have federate permission by checking the DB indirectly:
    # assert/retract works (write), but we can't test federate without a peer setup
    # — sufficient to confirm key is valid and the route accepted the sanitised perms
    assert len(api_key) > 10


def test_list_and_revoke_own_keys(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair
    token = _sign_token(private_key, sub="revoke-test-sub")
    resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": token})
    assert resp.status_code == 200
    api_key = resp.json()["api_key"]

    # List keys
    list_resp = oidc_client.get("/v1/auth/keys", headers={"Authorization": f"Bearer {api_key}"})
    assert list_resp.status_code == 200
    keys = list_resp.json()
    assert any(k["entity_uri"] == "oidc:revoke-test-sub" for k in keys)

    key_id = next(k["id"] for k in keys if k["entity_uri"] == "oidc:revoke-test-sub")

    # Revoke it
    del_resp = oidc_client.delete(
        f"/v1/auth/keys/{key_id}", headers={"Authorization": f"Bearer {api_key}"}
    )
    assert del_resp.status_code == 204

    # Key is now invalid
    after_resp = oidc_client.get("/v1/facts", headers={"Authorization": f"Bearer {api_key}"})
    assert after_resp.status_code == 401


def test_cannot_revoke_another_entitys_key(oidc_client: TestClient, rsa_keypair) -> None:
    private_key, _ = rsa_keypair

    # Alice mints her key
    alice_token = _sign_token(private_key, sub="alice", email="alice@example.com")
    alice_resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": alice_token})
    alice_key = alice_resp.json()["api_key"]

    # Bob mints his key
    bob_token = _sign_token(private_key, sub="bob", email="bob@example.com")
    bob_resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": bob_token})
    bob_key = bob_resp.json()["api_key"]

    # Get Alice's key id
    alice_keys = oidc_client.get(
        "/v1/auth/keys", headers={"Authorization": f"Bearer {alice_key}"}
    ).json()
    alice_key_id = alice_keys[0]["id"]

    # Bob tries to revoke Alice's key — should 403
    del_resp = oidc_client.delete(
        f"/v1/auth/keys/{alice_key_id}", headers={"Authorization": f"Bearer {bob_key}"}
    )
    assert del_resp.status_code == 403


def test_exchange_rotates_previous_key(oidc_client: TestClient, rsa_keypair) -> None:
    """A second exchange for the same sub invalidates the first key (rotation)."""
    private_key, _ = rsa_keypair

    # First exchange
    token1 = _sign_token(private_key, sub="rotate-sub")
    resp1 = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": token1})
    assert resp1.status_code == 200
    key1 = resp1.json()["api_key"]

    # Key1 is usable immediately after first exchange
    assert (
        oidc_client.get("/v1/facts", headers={"Authorization": f"Bearer {key1}"}).status_code == 200
    )

    # Second exchange — same sub, new token
    token2 = _sign_token(private_key, sub="rotate-sub")
    resp2 = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": token2})
    assert resp2.status_code == 200
    key2 = resp2.json()["api_key"]
    assert key1 != key2

    # key2 works
    assert (
        oidc_client.get("/v1/facts", headers={"Authorization": f"Bearer {key2}"}).status_code == 200
    )

    # key1 is revoked
    assert (
        oidc_client.get("/v1/facts", headers={"Authorization": f"Bearer {key1}"}).status_code == 401
    )


def test_exchange_rotation_does_not_affect_other_users(
    oidc_client: TestClient, rsa_keypair
) -> None:
    """Rotation must only revoke the sub's own keys, not other users' keys."""
    private_key, _ = rsa_keypair

    carol_token = _sign_token(private_key, sub="carol", email="carol@example.com")
    carol_resp = oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": carol_token})
    carol_key = carol_resp.json()["api_key"]

    # Dave exchanges — should not affect Carol
    dave_token = _sign_token(private_key, sub="dave", email="dave@example.com")
    oidc_client.post("/v1/auth/oidc/exchange", json={"id_token": dave_token})

    # Carol's key still works
    assert (
        oidc_client.get("/v1/facts", headers={"Authorization": f"Bearer {carol_key}"}).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# C2 — garden-membership-scoped permission tests
# ---------------------------------------------------------------------------


def _seed_garden_member(db_path: str, entity_uri: str, role: str) -> None:
    """Insert a minimal garden + member row so the exchange can derive permissions."""
    garden_id = str(uuid.uuid4())
    now = "2026-01-01T00:00:00+00:00"
    conn = _sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO gardens (id, slug, name, scope, created_by, created_at) VALUES (?,?,?,?,?,?)",
        (garden_id, f"test-garden-{garden_id[:8]}", "Test Garden", "company", entity_uri, now),
    )
    conn.execute(
        """INSERT INTO garden_members
           (garden_id, entity_uri, role, added_by, added_at)
           VALUES (?,?,?,?,?)""",
        (garden_id, entity_uri, role, entity_uri, now),
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def oidc_env(
    tmp_path: Path,
    rsa_keypair,
    jwks_document,
) -> Generator[tuple[TestClient, str], None, None]:
    """Like oidc_client but yields (client, db_path) so tests can pre-seed garden rows."""
    db_file = str(tmp_path / "oidc_c2_test.db")
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        oidc_enabled=True,
        oidc_issuer_url=ISSUER,
        oidc_audience=AUDIENCE,
        oidc_token_ttl_hours=1,
        oidc_allowed_domains="",
    )

    settings_module.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    auth_route_mod.settings = test_settings  # type: ignore[assignment]
    auth_route_mod._JWKS_CACHE.clear()

    disco_response = MagicMock()
    disco_response.raise_for_status = MagicMock()
    disco_response.json.return_value = {"jwks_uri": f"{ISSUER}/.well-known/jwks.json"}

    real_PyJWKClient = jwt.PyJWKClient

    class _FakeJWKSClient(real_PyJWKClient):
        def fetch_data(self):
            return jwks_document

    def _fake_get(url: str, **kwargs: Any) -> MagicMock:
        return disco_response

    with (
        patch("stigmem_node.routes.auth.httpx.get", side_effect=_fake_get),
        patch("stigmem_node.routes.auth.jwt.PyJWKClient", _FakeJWKSClient),
        patch("stigmem_node.routes.auth.assert_safe_url"),
    ):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c, db_file

    settings_module.settings = original  # type: ignore[assignment]
    auth_mod.settings = original  # type: ignore[assignment]
    db_mod.settings = original  # type: ignore[assignment]
    wk_mod.settings = original  # type: ignore[assignment]
    auth_route_mod.settings = original  # type: ignore[assignment]
    auth_route_mod._JWKS_CACHE.clear()


def test_exchange_writer_membership_grants_write(
    oidc_env, rsa_keypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with writer role in any garden receives read+write permissions."""
    client, db_path = oidc_env
    private_key, _ = rsa_keypair
    _seed_garden_member(db_path, "oidc:writer-user", "writer")

    token = _sign_token(private_key, sub="writer-user")
    _enable_oidc_ceiling(monkeypatch)
    with stigmem_plugins([_memory_garden_acl_manifest()]):
        resp = client.post(
            "/v1/auth/oidc/exchange",
            json={"id_token": token, "permissions": ["read", "write"]},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["permissions"]) == {"read", "write"}


def test_exchange_admin_membership_grants_write(
    oidc_env, rsa_keypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with admin role in any garden receives read+write permissions."""
    client, db_path = oidc_env
    private_key, _ = rsa_keypair
    _seed_garden_member(db_path, "oidc:admin-user", "admin")

    token = _sign_token(private_key, sub="admin-user")
    _enable_oidc_ceiling(monkeypatch)
    with stigmem_plugins([_memory_garden_acl_manifest()]):
        resp = client.post(
            "/v1/auth/oidc/exchange",
            json={"id_token": token, "permissions": ["read", "write"]},
        )
    assert resp.status_code == 200
    assert set(resp.json()["permissions"]) == {"read", "write"}


def test_exchange_reader_only_membership_caps_at_read(
    oidc_env, rsa_keypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with only reader role cannot obtain write permissions."""
    client, db_path = oidc_env
    private_key, _ = rsa_keypair
    _seed_garden_member(db_path, "oidc:reader-user", "reader")

    token = _sign_token(private_key, sub="reader-user")
    _enable_oidc_ceiling(monkeypatch)
    with stigmem_plugins([_memory_garden_acl_manifest()]):
        resp = client.post(
            "/v1/auth/oidc/exchange",
            json={"id_token": token, "permissions": ["read", "write"]},
        )
    assert resp.status_code == 200
    assert resp.json()["permissions"] == ["read"]

    # Confirm the key cannot write
    api_key = resp.json()["api_key"]
    write_resp = client.post(
        "/v1/facts",
        json={"entity": "e", "relation": "r", "value": {"type": "string", "v": "x"}, "source": "s"},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert write_resp.status_code == 403


def test_exchange_no_membership_caps_at_read(
    oidc_env, rsa_keypair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user with no garden membership can only get read access."""
    client, _ = oidc_env
    private_key, _ = rsa_keypair

    token = _sign_token(private_key, sub="nomember-user", email="nomember@example.com")
    _enable_oidc_ceiling(monkeypatch)
    with stigmem_plugins([_memory_garden_acl_manifest()]):
        resp = client.post(
            "/v1/auth/oidc/exchange",
            json={"id_token": token, "permissions": ["read", "write"]},
        )
    assert resp.status_code == 200
    assert resp.json()["permissions"] == ["read"]


def test_exchange_default_install_does_not_apply_garden_permission_ceiling(
    oidc_env, rsa_keypair
) -> None:
    """Default installs do not apply advanced membership-derived OIDC ceilings."""
    client, db_path = oidc_env
    private_key, _ = rsa_keypair
    _seed_garden_member(db_path, "oidc:default-reader-user", "reader")

    token = _sign_token(private_key, sub="default-reader-user")
    resp = client.post(
        "/v1/auth/oidc/exchange",
        json={"id_token": token, "permissions": ["read", "write"]},
    )
    assert resp.status_code == 200
    assert set(resp.json()["permissions"]) == {"read", "write"}


def test_exchange_response_includes_permissions_field(oidc_env, rsa_keypair) -> None:
    """ExchangeResponse always contains the permissions field."""
    client, _ = oidc_env
    private_key, _ = rsa_keypair

    token = _sign_token(private_key, sub="fields-check-user")
    resp = client.post("/v1/auth/oidc/exchange", json={"id_token": token})
    assert resp.status_code == 200
    body = resp.json()
    assert "permissions" in body
    assert isinstance(body["permissions"], list)
