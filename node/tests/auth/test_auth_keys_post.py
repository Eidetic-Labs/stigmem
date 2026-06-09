"""Tests for ``POST /v1/auth/keys`` — issue #135.

Covers the four acceptance criteria from the issue:
1. Endpoint exists and is documented.
2. Caller-generated-key posture preserved (raw_key in request, NOT in response).
3. Endpoint requires admin authorization; raw key material is not leaked.
4. Tests cover successful creation AND unauthorized attempts.

The endpoint wraps ``register_api_key`` and emits an ``admin_action`` audit
event with detail ``action=api_key_register``.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

import stigmem_node.db as db_mod
from stigmem_node.auth import _verify_key_hash, create_api_key


def _mint_admin_key() -> str:
    """Return a fresh raw API key with admin scope (uses create_api_key for test
    convenience; production callers use ``register_api_key`` via this endpoint).
    """
    return create_api_key("agent:admin", ["admin", "read", "write"])


def _mint_federation_admin_key() -> str:
    """Admin key that also holds admin:federation (cross-tenant minting authority, M2)."""
    return create_api_key("agent:fedadmin", ["admin", "admin:federation", "read", "write"])


def _new_raw_key() -> str:
    """64-hex-char key value, matching `openssl rand -hex 32`."""
    return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


class TestRegisterStaticKey:
    def test_admin_cannot_mint_key_in_foreign_tenant(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        """A tenant-scoped admin (no admin:federation) cannot mint in another tenant (M2)."""
        client, _ = authed_client
        admin_key = _mint_admin_key()  # tenant "default", no admin:federation
        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:cross-tenant",
                "permissions": ["read"],
                "tenant_id": "tenant-b",
            },
        )
        assert resp.status_code == 403, resp.text

    def test_admin_can_mint_key_in_own_tenant(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()  # tenant "default"
        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:same-tenant",
                "permissions": ["read"],
                "tenant_id": "default",
            },
        )
        assert resp.status_code == 201, resp.text

    def test_admin_can_register_static_key(self, authed_client: tuple[TestClient, str]) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        new_raw = _new_raw_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": new_raw,
                "entity_uri": "agent:service-account",
                "permissions": ["read", "write"],
                "description": "CI bot",
            },
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()

        # AC #2: raw_key is NEVER echoed.
        assert "raw_key" not in body
        assert "api_key" not in body
        assert new_raw not in resp.text

        # Response shape.
        assert body["entity_uri"] == "agent:service-account"
        assert body["permissions"] == ["read", "write"]
        assert body["description"] == "CI bot"
        assert body["expires_at"] is not None
        assert body["tenant_id"] == "default"
        assert body["id"]  # non-empty UUID

        # Persisted as an Argon2id hash of new_raw.
        with db_mod.db() as conn:
            row = conn.execute(
                "SELECT key_hash, entity_uri, permissions FROM api_keys WHERE id = ?",
                (body["id"],),
            ).fetchone()
        assert row is not None
        assert row["key_hash"].startswith("$argon2id$")
        assert _verify_key_hash(new_raw, row["key_hash"])
        assert row["entity_uri"] == "agent:service-account"
        assert sorted(json.loads(row["permissions"])) == ["read", "write"]

    def test_response_does_not_leak_raw_key(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        """Direct regression on the caller-generated-key invariant (AC #2)."""
        client, _ = authed_client
        admin_key = _mint_admin_key()
        unique_raw = "abc" + secrets.token_hex(31)  # easy to grep

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": unique_raw,
                "entity_uri": "agent:service-account",
                "permissions": ["read"],
            },
        )
        assert resp.status_code == 201, resp.text
        assert unique_raw not in resp.text, (
            "raw_key must not appear anywhere in the response body"
        )

    def test_admin_register_normalizes_tenant_id(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        # cross-tenant minting requires admin:federation (M2)
        admin_key = _mint_federation_admin_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:tenant-service",
                "permissions": ["read"],
                "tenant_id": " Customer-A ",
            },
        )

        assert resp.status_code == 201, resp.text
        assert resp.json()["tenant_id"] == "customer-a"

    def test_admin_register_rejects_invalid_tenant_id(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        # cross-tenant authority (M2); an invalid tenant id is still rejected with 400
        admin_key = _mint_federation_admin_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:tenant-service",
                "permissions": ["read"],
                "tenant_id": "contains spaces",
            },
        )

        assert resp.status_code == 400, resp.text
        assert "tenant_id_invalid" in resp.json()["detail"]

    def test_admin_can_register_with_explicit_expiry(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        expires = (datetime.now(UTC) + timedelta(days=30)).isoformat()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:cron-bot",
                "permissions": ["read"],
                "expires_at": expires,
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["expires_at"] == expires

    def test_registration_applies_default_static_key_max_age(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()

        before = datetime.now(UTC)
        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:max-age-default",
                "permissions": ["read"],
            },
        )
        after = datetime.now(UTC)

        assert resp.status_code == 201, resp.text
        expires_at = datetime.fromisoformat(resp.json()["expires_at"])
        assert before + timedelta(days=90) - timedelta(seconds=1) <= expires_at
        assert expires_at <= after + timedelta(days=90) + timedelta(seconds=1)

    def test_registration_rejects_expiry_beyond_static_key_max_age(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        expires = (datetime.now(UTC) + timedelta(days=91)).isoformat()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:max-age-too-long",
                "permissions": ["read"],
                "expires_at": expires,
            },
        )

        assert resp.status_code == 400, resp.text
        assert "max age" in resp.json()["detail"]

    def test_audit_event_emitted_on_register(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        new_raw = _new_raw_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": new_raw,
                "entity_uri": "agent:service-account",
                "permissions": ["read", "write"],
            },
        )
        assert resp.status_code == 201, resp.text
        new_key_id = resp.json()["id"]

        # An admin_action audit row whose detail captures the new key id and
        # the actor (the admin key holder) MUST be present.
        with db_mod.db() as conn:
            rows = conn.execute(
                "SELECT entity_uri, detail FROM fact_audit_log"
                " WHERE event_type = 'admin_action'"
                " ORDER BY ts DESC"
            ).fetchall()
        match = next(
            (r for r in rows
             if r["detail"] and "api_key_register" in r["detail"]
             and new_key_id in r["detail"]),
            None,
        )
        assert match is not None, (
            f"expected admin_action audit row for new_key_id={new_key_id};"
            f" rows={[dict(r) for r in rows]}"
        )
        detail = json.loads(match["detail"])
        assert detail["action"] == "api_key_register"
        assert detail["new_key_id"] == new_key_id
        assert detail["target_entity_uri"] == "agent:service-account"


class TestExpiringSoonKeys:
    def test_admin_can_list_expiring_keys(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        soon_expiry = (datetime.now(UTC) + timedelta(days=7)).isoformat()
        later_expiry = (datetime.now(UTC) + timedelta(days=60)).isoformat()

        soon = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:expiring-soon",
                "permissions": ["read"],
                "expires_at": soon_expiry,
            },
        )
        assert soon.status_code == 201, soon.text
        later = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:expiring-later",
                "permissions": ["read"],
                "expires_at": later_expiry,
            },
        )
        assert later.status_code == 201, later.text

        resp = client.get(
            "/v1/auth/keys/expiring-soon?within_days=30",
            headers={"Authorization": f"Bearer {admin_key}"},
        )

        assert resp.status_code == 200, resp.text
        entities = {row["entity_uri"] for row in resp.json()}
        assert "agent:expiring-soon" in entities
        assert "agent:expiring-later" not in entities
        row = next(row for row in resp.json() if row["entity_uri"] == "agent:expiring-soon")
        assert 0 < row["days_remaining"] <= 8
        assert row["tenant_id"] == "default"

    def test_non_admin_cannot_list_expiring_keys(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, agent_key = authed_client

        resp = client.get(
            "/v1/auth/keys/expiring-soon",
            headers={"Authorization": f"Bearer {agent_key}"},
        )

        assert resp.status_code == 403, resp.text


# ---------------------------------------------------------------------------
# Authorization failures
# ---------------------------------------------------------------------------


class TestRegisterStaticKeyAuthz:
    def test_non_admin_caller_gets_403(self, authed_client: tuple[TestClient, str]) -> None:
        """The default authed_client fixture has only ['read','write'] — no admin."""
        client, agent_key = authed_client

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {agent_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:should-not-be-created",
                "permissions": ["read"],
            },
        )
        assert resp.status_code == 403, resp.text
        assert "admin" in resp.json()["detail"].lower()

        # No row inserted.
        with db_mod.db() as conn:
            row = conn.execute(
                "SELECT id FROM api_keys WHERE entity_uri = ?",
                ("agent:should-not-be-created",),
            ).fetchone()
        assert row is None

    def test_unauthenticated_caller_gets_401(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client

        resp = client.post(
            "/v1/auth/keys",
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:noauth",
                "permissions": ["read"],
            },
        )
        # No Authorization header → 401 from resolve_identity.
        assert resp.status_code == 401, resp.text


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------


class TestRegisterStaticKeyValidation:
    def test_short_raw_key_rejected(self, authed_client: tuple[TestClient, str]) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": "tooshort",
                "entity_uri": "agent:x",
                "permissions": ["read"],
            },
        )
        # FastAPI/Pydantic returns 422 for min_length validation failures.
        assert resp.status_code == 422, resp.text

    def test_unknown_permission_rejected(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:typo",
                "permissions": ["writes"],  # typo
            },
        )
        assert resp.status_code == 400, resp.text
        assert "writes" in resp.json()["detail"]

    def test_empty_permissions_rejected(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()

        resp = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": _new_raw_key(),
                "entity_uri": "agent:noperm",
                "permissions": [],
            },
        )
        assert resp.status_code == 400, resp.text

    def test_duplicate_raw_key_returns_409(
        self, authed_client: tuple[TestClient, str]
    ) -> None:
        client, _ = authed_client
        admin_key = _mint_admin_key()
        raw = _new_raw_key()

        first = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": raw,
                "entity_uri": "agent:first",
                "permissions": ["read"],
            },
        )
        assert first.status_code == 201, first.text

        second = client.post(
            "/v1/auth/keys",
            headers={"Authorization": f"Bearer {admin_key}"},
            json={
                "raw_key": raw,
                "entity_uri": "agent:second",
                "permissions": ["read"],
            },
        )
        assert second.status_code == 409, second.text
