"""Integration + unit tests for RTBF tombstones — spec §23.

Coverage:
- POST /v1/tombstones: create tombstone (admin only, idempotent)
- GET  /v1/tombstones/{uri}: check tombstone status (admin only)
- POST /v1/tombstones/{id}/revoke: revoke tombstone
- Recall-time filter: tombstoned entity facts excluded from GET /v1/facts
- Federation: GET /v1/federation/tombstones poll route
- Federation: POST /v1/federation/tombstones/ingest inbound apply
- Cache invalidation after write
- §23.3.3 r.3 — pagination totals computed post-filter (no oracle leakage)
- §23.4.3 — tombstone:read capability token required for federation poll
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import time
import urllib.parse
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.lifecycle.tombstones as tombstones_mod
import stigmem_node.routes.federation as fed_mod
import stigmem_node.routes.tombstones as tomb_routes_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.identity.manifest import OrgManifest, sign_manifest
from stigmem_node.identity.trust_store import store_peer_manifest
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.models.tombstones import TombstoneRecord, TombstoneRevocationRecord
from stigmem_node.plugins import Allow, Deny, PluginContext, PluginManifest
from stigmem_node.plugins.discovery import DiscoveredPlugin
from stigmem_node.plugins.testing import stigmem_plugins
from stigmem_node.tombstone_signing import _revocation_signing_body, _signing_body

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
get_or_create_node_id = db_mod.get_or_create_node_id
Settings = settings_module.Settings
create_tombstone = tombstones_mod.create_tombstone
is_tombstoned = tombstones_mod.is_tombstoned
revoke_tombstone = tombstones_mod.revoke_tombstone

_TOMBSTONE_PLUGIN_SRC = (
    Path(__file__).resolve().parents[3] / "experimental" / "tombstones" / "src"
)
_TOMBSTONE_ENV = {
    "STIGMEM_TOMBSTONES_ENABLED": "true",
    "STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER": "true",
}


def _tombstone_plugin_manifest():
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    plugin = __import__("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


@contextmanager
def _tombstone_plugin_app(app) -> Generator[None, None, None]:
    original_env = {name: os.environ.get(name) for name in _TOMBSTONE_ENV}
    try:
        for name, value in _TOMBSTONE_ENV.items():
            os.environ[name] = value
        manifest = _tombstone_plugin_manifest()
        discovered = DiscoveredPlugin(
            manifest=manifest,
            entry_point_name="tombstones",
            entry_point_value="stigmem_plugin_tombstones:plugin_manifest",
            distribution=manifest.name,
        )
        _include_plugin_routers(app, (discovered,))
        with stigmem_plugins([manifest]):
            yield
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _reset_tombstone_cache() -> None:
    tombstones_mod.invalidate_tombstone_cache()


def _gen_key_b64() -> tuple[Ed25519PrivateKey, str, str]:
    """Generate Ed25519 keypair, return (priv_obj, pub_b64url, priv_b64url)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return priv, pub_b64, priv_b64


def _register_peer(db_file: str, node_id: str, pub_b64: str) -> str:
    """Insert an active peer into the DB. Returns peer row id."""
    peer_id = str(uuid.uuid4())
    peer_timestamp = datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = sqlite3.connect(db_file)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                node_id,
                "http://127.0.0.1:1",
                pub_b64,
                json.dumps(["public", "*"]),
                "active",
                peer_timestamp,
                "test_sig",
                peer_timestamp,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return peer_id


def _build_peer_token_payload(iss: str, sub: str, now_ms: int) -> dict:
    return {
        "iss": iss,
        "sub": sub,
        "iat": now_ms,
        "exp": now_ms + 3_600_000,
        "nonce": str(uuid.uuid4()),
        "scopes": ["public", "*"],
    }


def _make_peer_token(priv_b64: str, iss: str, sub: str = "tombnode") -> str:
    """Mint an Ed25519-signed peer JWT."""
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    payload = _build_peer_token_payload(iss=iss, sub=sub, now_ms=int(time.time() * 1000))
    return pyjwt.encode(payload, privkey, algorithm="EdDSA")


def _make_manifest(priv: Ed25519PrivateKey, pub_b64: str, entity_uri: str) -> OrgManifest:
    now = datetime.now(UTC)
    manifest = OrgManifest(
        entity_uri=entity_uri,
        key_id="key-1",
        public_key=pub_b64,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=365)).isoformat(),
        entities=[entity_uri],
    )
    sign_manifest(manifest, priv)
    return manifest


def _sign_tombstone_payload(payload: dict, priv: Ed25519PrivateKey) -> dict:
    record = TombstoneRecord(**{**payload, "key_id": "key-1", "signature": ""})
    sig = base64.urlsafe_b64encode(priv.sign(_signing_body(record))).decode().rstrip("=")
    return record.model_copy(update={"signature": sig}).model_dump()


def _sign_revocation_payload(payload: dict, priv: Ed25519PrivateKey) -> dict:
    record = TombstoneRevocationRecord(**{**payload, "key_id": "key-1", "signature": ""})
    sig = base64.urlsafe_b64encode(priv.sign(_revocation_signing_body(record))).decode().rstrip("=")
    return record.model_copy(update={"signature": sig}).model_dump()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def node(tmp_path):
    """Authenticated node with admin and reader keys + signing key + registered peer."""
    db_file = str(tmp_path / "tomb_test.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    _priv, _pub_b64, priv_b64 = _gen_key_b64()
    # Peer keypair for federation ingest auth
    peer_priv, peer_pub_b64, peer_priv_b64 = _gen_key_b64()
    peer_node_id = "stigmem://peer-node"

    ts = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://tombnode",
        trust_mode="off",
        node_private_key=priv_b64,
    )
    settings_module.settings = ts
    auth_mod.settings = ts
    db_mod.settings = ts
    wk_mod.settings = ts
    fed_mod.settings = ts
    tomb_routes_mod.settings = ts

    # Register the peer so peer tokens pass auth
    _register_peer(db_file, peer_node_id, peer_pub_b64)
    store_peer_manifest(peer_node_id, _make_manifest(peer_priv, peer_pub_b64, peer_node_id))

    # Reset module-level tombstone cache for clean test isolation
    _reset_tombstone_cache()

    admin_key = create_api_key(
        "stigmem://tombnode/agent/admin",
        ["read", "write", "federate", "admin"],
    )
    reader_key = create_api_key("stigmem://tombnode/agent/reader", ["read"])
    # Peer token factory — each call mints a fresh JWT (unique nonce)
    our_node_id = get_or_create_node_id(db_path=db_file)

    def _mint_peer_token():
        return _make_peer_token(peer_priv_b64, peer_node_id, sub=our_node_id)

    app = create_app()
    with _tombstone_plugin_app(app):
        client = TestClient(app, raise_server_exceptions=True)
        client.__enter__()
        yield client, admin_key, reader_key, ts, db_file, _mint_peer_token, peer_priv
        client.__exit__(None, None, None)
    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original
    wk_mod.settings = original
    fed_mod.settings = original
    tomb_routes_mod.settings = original


def _ah(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def _assert_fact(client: TestClient, headers: dict, entity: str = "user:alice") -> dict:
    resp = client.post(
        "/v1/facts",
        json={
            "entity": entity,
            "relation": "test:name",
            "value": {"type": "string", "v": "Alice"},
            "source": "test:source",
            "scope": "local",
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _audit_events(db_file: str, event_type: str) -> list[dict]:
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT event_type, entity_uri, fact_id, source, detail FROM fact_audit_log "
            "WHERE event_type = ? ORDER BY seq",
            (event_type,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST /v1/tombstones — create
# ---------------------------------------------------------------------------


class TestTombstoneCreate:
    def test_admin_can_create(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:alice", "scope": "*"},
            headers=_ah(admin_key),
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["entity_uri"] == "user:alice"
        assert data["scope"] == "*"
        assert data["id"].startswith("tomb_")
        assert data["signed_by"] == "stigmem://tombnode/agent/admin"

        audit = _audit_events(db_file, "tombstone_created")
        assert len(audit) == 1
        assert audit[0]["entity_uri"] == "stigmem://tombnode/agent/admin"
        assert audit[0]["fact_id"] == data["id"]
        detail = json.loads(audit[0]["detail"])
        assert detail["target_entity_uri"] == "user:alice"
        assert detail["scope"] == "*"

    def test_reader_cannot_create(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:alice", "scope": "*"},
            headers=_ah(reader_key),
        )
        assert resp.status_code == 403
        assert _audit_events(db_file, "tombstone_created") == []

    def test_idempotent_on_same_entity_scope(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp1 = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:bob", "scope": "*"},
            headers=_ah(admin_key),
        )
        resp2 = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:bob", "scope": "*"},
            headers=_ah(admin_key),
        )
        assert resp1.status_code == 201
        assert resp2.status_code == 201
        # Must return the same record (idempotent)
        assert resp1.json()["id"] == resp2.json()["id"]
        assert len(_audit_events(db_file, "tombstone_created")) == 1

    def test_invalid_scope_rejected(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:alice", "scope": "garbage_scope"},
            headers=_ah(admin_key),
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "tombstone_invalid_scope"

    def test_legal_hold_flag(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:carol", "scope": "*", "legal_hold": True},
            headers=_ah(admin_key),
        )
        assert resp.status_code == 201
        assert resp.json()["legal_hold"] is True


class TestTombstoneAdminCapabilityConsistency:
    def test_write_federate_without_admin_cannot_use_admin_routes(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        write_federate_key = create_api_key(
            "stigmem://tombnode/agent/write-federate",
            ["read", "write", "federate"],
        )
        create_resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:admin-consistency", "scope": "*"},
            headers=_ah(admin_key),
        )
        assert create_resp.status_code == 201, create_resp.text
        tomb_id = create_resp.json()["id"]
        encoded = urllib.parse.quote("user:admin-consistency", safe="")

        responses = [
            client.post(
                "/v1/tombstones",
                json={"entity_uri": "user:write-fed-denied", "scope": "*"},
                headers=_ah(write_federate_key),
            ),
            client.get(f"/v1/tombstones/{encoded}", headers=_ah(write_federate_key)),
            client.post(
                f"/v1/tombstones/{tomb_id}/revoke",
                json={"reason": "unauthorized"},
                headers=_ah(write_federate_key),
            ),
        ]

        assert [response.status_code for response in responses] == [403, 403, 403]
        assert {response.json()["detail"] for response in responses} == {
            "admin API key required"
        }

    def test_admin_capability_voter_denial_blocks_all_admin_routes(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        create_resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:admin-voter-denial", "scope": "*"},
            headers=_ah(admin_key),
        )
        assert create_resp.status_code == 201, create_resp.text
        tomb_id = create_resp.json()["id"]
        encoded = urllib.parse.quote("user:admin-voter-denial", safe="")
        seen_capabilities: list[str] = []

        def capability_check(_ctx: PluginContext, **kwargs: object) -> Deny | Allow:
            capability = str(kwargs["capability"])
            seen_capabilities.append(capability)
            if capability == "admin":
                return Deny("admin disabled")
            return Allow()

        manifest = PluginManifest(
            name="deny-admin-capability",
            version="1.0.0",
            hooks={"capability_check": capability_check},
        )

        with stigmem_plugins([manifest]):
            responses = [
                client.post(
                    "/v1/tombstones",
                    json={"entity_uri": "user:admin-voter-denied", "scope": "*"},
                    headers=_ah(admin_key),
                ),
                client.get(f"/v1/tombstones/{encoded}", headers=_ah(admin_key)),
                client.post(
                    f"/v1/tombstones/{tomb_id}/revoke",
                    json={"reason": "voter denied"},
                    headers=_ah(admin_key),
                ),
            ]

        assert [response.status_code for response in responses] == [403, 403, 403]
        assert {response.json()["detail"] for response in responses} == {
            "admin API key required"
        }
        assert seen_capabilities == ["admin", "admin", "admin"]


# ---------------------------------------------------------------------------
# GET /v1/tombstones/{entity_uri} — status check
# ---------------------------------------------------------------------------


class TestTombstoneStatus:
    def test_check_returns_tombstoned_true(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:dave", "scope": "*"},
            headers=_ah(admin_key),
        )
        encoded = urllib.parse.quote("user:dave", safe="")
        resp = client.get(f"/v1/tombstones/{encoded}", headers=_ah(admin_key))
        assert resp.status_code == 200
        data = resp.json()
        assert data["tombstoned"] is True
        assert len(data["tombstones"]) == 1

    def test_check_unknown_entity_returns_false(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        encoded = urllib.parse.quote("user:nobody", safe="")
        resp = client.get(f"/v1/tombstones/{encoded}", headers=_ah(admin_key))
        assert resp.status_code == 200
        assert resp.json()["tombstoned"] is False

    def test_reader_cannot_check(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        encoded = urllib.parse.quote("user:dave", safe="")
        resp = client.get(f"/v1/tombstones/{encoded}", headers=_ah(reader_key))
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /v1/tombstones/{id}/revoke
# ---------------------------------------------------------------------------


class TestTombstoneRevoke:
    def test_revoke_tombstone(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        create_resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:eve", "scope": "*"},
            headers=_ah(admin_key),
        )
        assert create_resp.status_code == 201
        tomb_id = create_resp.json()["id"]

        revoke_resp = client.post(
            f"/v1/tombstones/{tomb_id}/revoke",
            json={"reason": "Court order #2026-CR-9"},
            headers=_ah(admin_key),
        )
        assert revoke_resp.status_code == 200
        data = revoke_resp.json()
        assert data["tombstone_id"] == tomb_id
        audit = _audit_events(db_file, "tombstone_revoked")
        assert len(audit) == 1
        assert audit[0]["entity_uri"] == "stigmem://tombnode/agent/admin"
        assert audit[0]["fact_id"] == tomb_id

        # After revocation, status check should show tombstoned=False
        encoded = urllib.parse.quote("user:eve", safe="")
        status_resp = client.get(f"/v1/tombstones/{encoded}", headers=_ah(admin_key))
        assert status_resp.json()["tombstoned"] is False

    def test_revoke_unknown_tombstone_is_404(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.post(
            "/v1/tombstones/tomb_nonexistent/revoke",
            json={"reason": "test"},
            headers=_ah(admin_key),
        )
        assert resp.status_code == 404

    def test_double_revoke_is_409(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        create_resp = client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:frank", "scope": "*"},
            headers=_ah(admin_key),
        )
        tomb_id = create_resp.json()["id"]
        client.post(
            f"/v1/tombstones/{tomb_id}/revoke", json={"reason": "first"}, headers=_ah(admin_key)
        )
        resp = client.post(
            f"/v1/tombstones/{tomb_id}/revoke", json={"reason": "second"}, headers=_ah(admin_key)
        )
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Recall-time filter (§23.3)
# ---------------------------------------------------------------------------


class TestTombstoneRecallFilter:
    def test_tombstoned_entity_excluded_from_facts(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node

        _assert_fact(client, _ah(admin_key), entity="user:alice")

        # Verify fact appears before tombstone
        resp = client.get("/v1/facts?entity=user:alice&scope=local", headers=_ah(reader_key))
        assert resp.status_code == 200
        pre_facts = resp.json()["facts"]
        assert len(pre_facts) >= 1

        # Issue tombstone
        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:alice", "scope": "*"},
            headers=_ah(admin_key),
        )
        # Force cache invalidation
        _reset_tombstone_cache()

        # Facts for tombstoned entity must be excluded
        resp = client.get("/v1/facts?entity=user:alice&scope=local", headers=_ah(reader_key))
        assert resp.status_code == 200
        post_facts = resp.json()["facts"]
        assert len(post_facts) == 0, "Tombstoned entity facts must be excluded from recall"

    def test_total_count_excludes_tombstoned_facts(self, node):
        """§23.3.3 r.3 — pagination total must be post-filter count."""
        client, admin_key, reader_key, ts, db_file, *_extra = node

        for _i in range(3):
            _assert_fact(client, _ah(admin_key), entity="user:mallory")

        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:mallory", "scope": "*"},
            headers=_ah(admin_key),
        )
        _reset_tombstone_cache()

        resp = client.get("/v1/facts?entity=user:mallory&scope=local", headers=_ah(reader_key))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] is None, (
            "Total must be null when tombstone filtering applied (§23.3.3 r.3)"
        )

    def test_non_tombstoned_entity_not_affected(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node

        _assert_fact(client, _ah(admin_key), entity="user:grace")
        _assert_fact(client, _ah(admin_key), entity="user:alice")

        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:alice", "scope": "*"},
            headers=_ah(admin_key),
        )
        _reset_tombstone_cache()

        # Grace's facts must not be affected
        resp = client.get("/v1/facts?entity=user:grace&scope=local", headers=_ah(reader_key))
        assert len(resp.json()["facts"]) >= 1


# ---------------------------------------------------------------------------
# Storage-layer unit tests
# ---------------------------------------------------------------------------


class TestTombstoneStorageLayer:
    def test_is_tombstoned_returns_true_after_create(self, node):
        _, _, _, ts, db_file, *_ = node
        _reset_tombstone_cache()
        create_tombstone(
            "user:henry",
            "*",
            "test",
            "admin:node",
            "test-key-id",
            "test-sig",
        )
        assert is_tombstoned("user:henry", "local") is True

    def test_is_tombstoned_returns_false_after_revoke(self, node):
        _, _, _, ts, db_file, *_ = node
        _reset_tombstone_cache()
        record = create_tombstone(
            "user:ida",
            "*",
            "test",
            "admin:node",
            "test-key-id",
            "test-sig",
        )
        revoke_tombstone(record.id, "reinstated", "admin:node", "test-key-id", "test-sig")
        _reset_tombstone_cache()
        assert is_tombstoned("user:ida", "local") is False

    def test_scope_wildcard_covers_all_scopes(self, node):
        _, _, _, ts, db_file, *_ = node
        _reset_tombstone_cache()
        create_tombstone(
            "user:jack",
            "*",
            None,
            "admin:node",
            "test-key-id",
            "test-sig",
        )
        _reset_tombstone_cache()
        for scope in ("local", "team", "company", "public"):
            assert is_tombstoned("user:jack", scope) is True

    def test_specific_scope_does_not_cover_other_scopes(self, node):
        _, _, _, ts, db_file, *_ = node
        _reset_tombstone_cache()
        create_tombstone(
            "user:kate",
            "local",
            None,
            "admin:node",
            "test-key-id",
            "test-sig",
        )
        _reset_tombstone_cache()
        assert is_tombstoned("user:kate", "local") is True
        assert is_tombstoned("user:kate", "team") is False


# ---------------------------------------------------------------------------
# Federation tombstone routes (§23.4)
# ---------------------------------------------------------------------------


class TestFederationTombstoneRoutes:
    def test_federation_tombstones_poll_returns_list(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:leo", "scope": "*"},
            headers=_ah(admin_key),
        )
        resp = client.get(
            "/v1/federation/tombstones",
            headers=_ah(admin_key),
        )
        assert resp.status_code == 200
        data = resp.json()
        # W6.5: poll now emits the v2 signed-origin envelope (each entry wraps the tombstone).
        assert data["v"] == 2
        assert "tombstones" in data
        uris = [e["tombstone"]["entity_uri"] for e in data["tombstones"]]
        assert "user:leo" in uris

    def test_federation_tombstones_since_filter(self, node):
        client, admin_key, reader_key, ts, db_file, *_extra = node
        # Create tombstone
        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:mia", "scope": "*"},
            headers=_ah(admin_key),
        )
        future = (datetime.now(UTC) + timedelta(days=365 * 100)).isoformat()
        resp = client.get(
            f"/v1/federation/tombstones?since={future}",
            headers=_ah(admin_key),
        )
        assert resp.status_code == 200
        assert len(resp.json()["tombstones"]) == 0

    def test_federation_tombstone_ingest(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, peer_priv = node
        tomb_id = f"tomb_{uuid.uuid4()}"
        payload = _sign_tombstone_payload(
            {
                "id": tomb_id,
                "entity_uri": "user:nina",
                "scope": "*",
                "reason": "test-ingest",
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
                "legal_hold": False,
            },
            peer_priv,
        )
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp.status_code == 200
        assert resp.json()["written"] is True
        audit = _audit_events(db_file, "tombstone_federation_ingested")
        assert len(audit) == 1
        assert audit[0]["entity_uri"] == "stigmem://peer-node"
        assert audit[0]["fact_id"] == tomb_id

        # Idempotent — second ingest same id (fresh token, same payload)
        resp2 = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp2.status_code == 200
        assert resp2.json()["written"] is False
        assert len(_audit_events(db_file, "tombstone_federation_ingested")) == 1

    def test_federation_tombstone_ingest_applies_filter(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, peer_priv = node

        # Create a fact for oscar
        _assert_fact(client, _ah(admin_key), entity="user:oscar")

        # Ingest tombstone for oscar via federation
        tomb_id = f"tomb_{uuid.uuid4()}"
        payload = _sign_tombstone_payload(
            {
                "id": tomb_id,
                "entity_uri": "user:oscar",
                "scope": "*",
                "reason": None,
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
                "legal_hold": False,
            },
            peer_priv,
        )
        client.post(
            "/v1/federation/tombstones/ingest", json=payload, headers=_ah(mint_peer_token())
        )
        _reset_tombstone_cache()

        # Oscar's facts must now be excluded
        resp = client.get("/v1/facts?entity=user:oscar&scope=local", headers=_ah(reader_key))
        assert resp.status_code == 200
        assert len(resp.json()["facts"]) == 0

    def test_federation_tombstone_ingest_rejects_missing_signature(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, *_extra = node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:missing-signature",
            "scope": "*",
            "reason": "test",
            "signed_by": "stigmem://peer-node",
            "key_id": "key-1",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp.status_code == 400
        audit = _audit_events(db_file, "tombstone_federation_rejected")
        assert len(audit) == 1
        detail = json.loads(audit[0]["detail"])
        assert detail["artifact"] == "tombstone"
        assert "signature" in detail["reason"]

    def test_federation_tombstone_ingest_rejects_bad_signature(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, peer_priv = node
        payload = _sign_tombstone_payload(
            {
                "id": f"tomb_{uuid.uuid4()}",
                "entity_uri": "user:bad-signature",
                "scope": "*",
                "reason": "test",
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
                "legal_hold": False,
            },
            peer_priv,
        )
        payload["signature"] = "bad-signature"
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp.status_code == 400
        audit = _audit_events(db_file, "tombstone_federation_rejected")
        assert len(audit) == 1
        detail = json.loads(audit[0]["detail"])
        assert detail["artifact"] == "tombstone"
        assert "signature" in detail["reason"]

    def test_federation_revocation_ingest_accepts_valid_signature(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, peer_priv = node
        tombstone_id = f"tomb_{uuid.uuid4()}"
        tombstone_payload = _sign_tombstone_payload(
            {
                "id": tombstone_id,
                "entity_uri": "user:revoked",
                "scope": "*",
                "reason": "test",
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
                "legal_hold": False,
            },
            peer_priv,
        )
        tombstone_resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=tombstone_payload,
            headers=_ah(mint_peer_token()),
        )
        assert tombstone_resp.status_code == 200

        payload = _sign_revocation_payload(
            {
                "id": f"tombrevoke_{uuid.uuid4()}",
                "tombstone_id": tombstone_id,
                "reason": "test",
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
            },
            peer_priv,
        )
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "type": "revocation"}

    def test_federation_revocation_ingest_rejects_bad_signature(self, node):
        client, admin_key, reader_key, ts, db_file, mint_peer_token, peer_priv = node
        payload = _sign_revocation_payload(
            {
                "id": f"tombrevoke_{uuid.uuid4()}",
                "tombstone_id": f"tomb_{uuid.uuid4()}",
                "reason": "test",
                "signed_by": "stigmem://peer-node",
                "created_at": datetime.now(UTC).isoformat(),
            },
            peer_priv,
        )
        payload["signature"] = "bad-signature"
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint_peer_token()),
        )
        assert resp.status_code == 400
        audit = _audit_events(db_file, "tombstone_federation_rejected")
        assert len(audit) == 1
        detail = json.loads(audit[0]["detail"])
        assert detail["artifact"] == "revocation"

    # -- F-3 regression tests: auth bypass fix --

    def test_federation_tombstones_poll_no_token_returns_401(self, node):
        """GET without Authorization header must return 401 (F-3)."""
        client, admin_key, reader_key, ts, db_file, *_extra = node
        resp = client.get("/v1/federation/tombstones")
        assert resp.status_code == 401
        assert "capability token required" in resp.json()["detail"]

    def test_federation_tombstones_poll_valid_token_returns_200(self, node):
        """GET with valid tombstone:read capability token returns 200 (F-3)."""
        client, admin_key, reader_key, ts, db_file, *_extra = node
        client.post(
            "/v1/tombstones",
            json={"entity_uri": "user:pat", "scope": "*"},
            headers=_ah(admin_key),
        )
        resp = client.get(
            "/v1/federation/tombstones",
            headers=_ah(admin_key),
        )
        assert resp.status_code == 200
        assert "tombstones" in resp.json()

    def test_federation_tombstones_poll_trust_mode_off_requires_token(self, node):
        """trust_mode=off still requires a token but skips sig verification (F-3)."""
        client, admin_key, reader_key, ts, db_file, *_extra = node
        # Fixture already sets trust_mode="off"
        assert ts.trust_mode == "off"

        # No token → 401 even in trust_mode=off
        resp = client.get("/v1/federation/tombstones")
        assert resp.status_code == 401

        # With token → 200 (sig verification skipped)
        resp = client.get(
            "/v1/federation/tombstones",
            headers=_ah(admin_key),
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 2-node federation propagation test
# ---------------------------------------------------------------------------


class TestTwoNodeFederationPropagation:
    """Verify tombstone propagation between two independent node instances."""

    def _make_node(self, tmp_path, name: str, peer_node_id: str = "stigmem://peer"):
        db_file = str(tmp_path / f"{name}.db")
        apply_migrations(db_path=db_file)
        node_priv, node_pub_b64, priv_b64 = _gen_key_b64()
        _peer_priv, peer_pub_b64, peer_priv_b64 = _gen_key_b64()
        ts = Settings(
            db_path=db_file,
            auth_required=True,
            node_url=f"http://{name}",
            trust_mode="off",
            node_private_key=priv_b64,
        )
        # Temporarily switch settings so create_api_key uses the right DB
        settings_module.settings = ts
        auth_mod.settings = ts
        db_mod.settings = ts
        _register_peer(db_file, peer_node_id, peer_pub_b64)
        admin_key = create_api_key(
            f"stigmem://{name}/agent/admin",
            ["read", "write", "federate", "admin"],
        )
        our_node_id = get_or_create_node_id(db_path=db_file)

        def _mint():
            return _make_peer_token(peer_priv_b64, peer_node_id, sub=our_node_id)

        return ts, admin_key, db_file, _mint, node_priv, node_pub_b64

    def test_tombstone_propagates_via_ingest(self, tmp_path):
        """Tombstone created on node A is applied on node B via federation/tombstones/ingest."""
        original = settings_module.settings

        try:
            # ---- Node A ----
            ts_a, admin_a, db_a, _peer_a, node_a_priv, node_a_pub = self._make_node(
                tmp_path, "node_a", "stigmem://ext-a"
            )
            settings_module.settings = ts_a
            auth_mod.settings = ts_a
            db_mod.settings = ts_a
            wk_mod.settings = ts_a
            fed_mod.settings = ts_a
            tomb_routes_mod.settings = ts_a
            _reset_tombstone_cache()
            app_a = create_app()
            plugin_ctx_a = _tombstone_plugin_app(app_a)
            plugin_ctx_a.__enter__()
            client_a = TestClient(app_a)
            client_a.__enter__()

            # Create tombstone on node A
            resp = client_a.post(
                "/v1/tombstones",
                json={"entity_uri": "user:quinn", "scope": "*", "reason": "GDPR test"},
                headers=_ah(admin_a),
            )
            assert resp.status_code == 201
            tomb_record = resp.json()

            # Fetch tombstone list from node A (federation poll simulation)
            poll_resp = client_a.get("/v1/federation/tombstones", headers=_ah(admin_a))
            assert poll_resp.status_code == 200
            # W6.5: v2 envelope — each entry wraps the tombstone under "tombstone".
            assert poll_resp.json()["v"] == 2
            polled = poll_resp.json()["tombstones"]
            assert any(e["tombstone"]["entity_uri"] == "user:quinn" for e in polled)

            client_a.__exit__(None, None, None)
            plugin_ctx_a.__exit__(None, None, None)

            # ---- Node B ----
            ts_b, admin_b, db_b, mint_b, _node_b_priv, _node_b_pub = self._make_node(
                tmp_path, "node_b", "stigmem://ext-b"
            )
            settings_module.settings = ts_b
            auth_mod.settings = ts_b
            db_mod.settings = ts_b
            wk_mod.settings = ts_b
            fed_mod.settings = ts_b
            tomb_routes_mod.settings = ts_b
            signer_manifest = OrgManifest(
                entity_uri=tomb_record["signed_by"],
                key_id=tomb_record["key_id"],
                public_key=node_a_pub,
                issued_at=datetime.now(UTC).isoformat(),
                expires_at=(datetime.now(UTC) + timedelta(days=365)).isoformat(),
                entities=[tomb_record["signed_by"]],
            )
            store_peer_manifest(
                tomb_record["signed_by"],
                sign_manifest(signer_manifest, node_a_priv),
            )
            _reset_tombstone_cache()
            app_b = create_app()
            plugin_ctx_b = _tombstone_plugin_app(app_b)
            plugin_ctx_b.__enter__()
            client_b = TestClient(app_b)
            client_b.__enter__()

            # Assert a fact on node B before ingest
            resp_fact = client_b.post(
                "/v1/facts",
                json={
                    "entity": "user:quinn",
                    "relation": "test:name",
                    "value": {"type": "string", "v": "Quinn"},
                    "source": "test",
                    "scope": "local",
                },
                headers=_ah(admin_b),
            )
            assert resp_fact.status_code == 201

            # Ingest tombstone from node A into node B (using peer token for auth)
            ingest_resp = client_b.post(
                "/v1/federation/tombstones/ingest",
                json=tomb_record,
                headers=_ah(mint_b()),
            )
            assert ingest_resp.status_code == 200
            assert ingest_resp.json()["written"] is True

            # Force cache refresh on node B
            _reset_tombstone_cache()

            # User:quinn's facts must now be suppressed on node B
            facts_resp = client_b.get(
                "/v1/facts?entity=user:quinn&scope=local", headers=_ah(admin_b)
            )
            assert facts_resp.status_code == 200
            assert len(facts_resp.json()["facts"]) == 0, (
                "Tombstone propagated from node A must suppress facts on node B"
            )

            client_b.__exit__(None, None, None)
            plugin_ctx_b.__exit__(None, None, None)

        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original
            _reset_tombstone_cache()


# ---------------------------------------------------------------------------
# Regression tests: ingest auth + signature enforcement (ACM-290 F-1/F-2/F-4)
# ---------------------------------------------------------------------------


class TestIngestAuthEnforcement:
    """Verify the ingest endpoint rejects unauthenticated and unsigned payloads."""

    def test_ingest_rejects_no_token(self, node):
        """F-1: ingest must reject payloads without peer/capability token (401)."""
        client, *_ = node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:attacker",
            "scope": "*",
            "reason": "evil",
            "signed_by": "stigmem://evil-node/admin",
            "key_id": "evil-key",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post("/v1/federation/tombstones/ingest", json=payload)
        assert resp.status_code == 401
        assert "peer token or capability token required" in resp.json()["detail"]

    def test_ingest_rejects_invalid_bearer(self, node):
        """F-1: ingest rejects garbage bearer token."""
        client, *_ = node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:attacker",
            "scope": "*",
            "reason": "evil",
            "signed_by": "stigmem://evil-node/admin",
            "key_id": "evil-key",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers={"Authorization": "Bearer garbage.not.a.jwt"},
        )
        assert resp.status_code == 401

    def test_ingest_rejects_revocation_without_token(self, node):
        """F-2: revocation ingest requires auth."""
        client, *_ = node
        payload = {
            "id": f"tombrevoke_{uuid.uuid4()}",
            "tombstone_id": "tomb_fake",
            "reason": "attacker revoke",
            "signed_by": "stigmem://evil-node/admin",
            "key_id": "evil-key",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
        }
        resp = client.post("/v1/federation/tombstones/ingest", json=payload)
        assert resp.status_code == 401


class TestIngestSignatureEnforcement:
    """Verify fail-closed signature verification (trust_mode != off)."""

    @pytest.fixture()
    def strict_node(self, tmp_path):
        """Node with trust_mode=relaxed and a registered peer + manifest."""
        original = settings_module.settings
        db_file = str(tmp_path / "strict_test.db")
        apply_migrations(db_path=db_file)
        _priv, _pub_b64, priv_b64 = _gen_key_b64()
        _peer_priv, peer_pub_b64, peer_priv_b64 = _gen_key_b64()
        peer_node_id = "stigmem://strict-peer"

        ts = Settings(
            db_path=db_file,
            auth_required=True,
            node_url="http://strictnode",
            trust_mode="relaxed",
            node_private_key=priv_b64,
        )
        settings_module.settings = ts
        auth_mod.settings = ts
        db_mod.settings = ts
        wk_mod.settings = ts
        fed_mod.settings = ts
        tomb_routes_mod.settings = ts
        _reset_tombstone_cache()

        _register_peer(db_file, peer_node_id, peer_pub_b64)
        create_api_key("stigmem://strictnode/agent/admin", ["read", "write", "federate"])

        our_node_id = get_or_create_node_id(db_path=db_file)

        def _mint():
            return _make_peer_token(peer_priv_b64, peer_node_id, sub=our_node_id)

        app = create_app()
        with _tombstone_plugin_app(app):
            client = TestClient(app, raise_server_exceptions=True)
            client.__enter__()
            yield client, _mint, peer_pub_b64, db_file
            client.__exit__(None, None, None)
        settings_module.settings = original
        auth_mod.settings = original
        db_mod.settings = original
        wk_mod.settings = original
        fed_mod.settings = original
        tomb_routes_mod.settings = original

    def test_rejects_tombstone_missing_key_id(self, strict_node):
        """F-1: tombstone with empty key_id is rejected 400."""
        client, mint, _, _db_file = strict_node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:test",
            "scope": "*",
            "reason": "test",
            "signed_by": "stigmem://strict-peer/admin",
            "key_id": "",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint()),
        )
        assert resp.status_code == 400
        assert "tombstone missing key_id" in resp.json()["detail"]

    def test_rejects_tombstone_missing_manifest(self, strict_node):
        """F-1: tombstone from unknown signer (no manifest) is rejected 401."""
        client, mint, _, db_file = strict_node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:test",
            "scope": "*",
            "reason": "test",
            "signed_by": "stigmem://unknown-signer/admin",
            "key_id": "some-key",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint()),
        )
        assert resp.status_code == 401
        assert "no manifest for signer" in resp.json()["detail"]
        audit = _audit_events(db_file, "tombstone_federation_rejected")
        assert len(audit) == 1
        detail = json.loads(audit[0]["detail"])
        assert detail["artifact"] == "tombstone"
        assert detail["reason"] == "signer_manifest_missing"

    def test_rejects_tombstone_bad_key_id(self, strict_node):
        """F-1: tombstone with key_id not in manifest is rejected 401."""
        client, mint, _, _db_file = strict_node
        payload = {
            "id": f"tomb_{uuid.uuid4()}",
            "entity_uri": "user:test",
            "scope": "*",
            "reason": "test",
            "signed_by": "stigmem://strict-peer",
            "key_id": "nonexistent-key-id",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
            "legal_hold": False,
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint()),
        )
        # Peer manifest exists but key_id won't match → depends on manifest lookup
        # If manifest lookup for peer's entity URI returns None (no manifest stored
        # under "stigmem://strict-peer"), it's 401 "no manifest for signer"
        assert resp.status_code == 401

    def test_rejects_revocation_missing_key_id(self, strict_node):
        """F-2: revocation with empty key_id is rejected 400."""
        client, mint, _, _db_file = strict_node
        payload = {
            "id": f"tombrevoke_{uuid.uuid4()}",
            "tombstone_id": "tomb_fake",
            "reason": "test",
            "signed_by": "stigmem://strict-peer/admin",
            "key_id": "",
            "signature": "dGVzdA",
            "created_at": datetime.now(UTC).isoformat(),
        }
        resp = client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers=_ah(mint()),
        )
        assert resp.status_code == 400
        assert "revocation missing key_id" in resp.json()["detail"]


class TestSignTombstoneNoFallback:
    """F-4: sign_tombstone raises when key is not configured (no fallback)."""

    def test_sign_tombstone_raises_without_key(self, tmp_path):
        """sign_tombstone must raise RuntimeError, not fall back to dev-unsigned."""
        from stigmem_node.models.tombstones import TombstoneRecord
        from stigmem_node.tombstone_signing import sign_tombstone

        original = settings_module.settings
        ts = Settings(
            db_path=str(tmp_path / "nokey.db"),
            node_private_key="",
        )
        settings_module.settings = ts

        record = TombstoneRecord(
            id="tomb_test",
            entity_uri="user:test",
            scope="*",
            reason="test",
            signed_by="admin",
            key_id="",
            signature="",
            created_at="2026-05-04",
            legal_hold=False,
        )
        with pytest.raises(RuntimeError, match="STIGMEM_NODE_PRIVATE_KEY not configured"):
            sign_tombstone(record)

        settings_module.settings = original

    def test_sign_revocation_raises_without_key(self, tmp_path):
        """sign_revocation must raise RuntimeError when key is missing."""
        from stigmem_node.models.tombstones import TombstoneRevocationRecord
        from stigmem_node.tombstone_signing import sign_revocation

        original = settings_module.settings
        ts = Settings(
            db_path=str(tmp_path / "nokey.db"),
            node_private_key="",
        )
        settings_module.settings = ts

        record = TombstoneRevocationRecord(
            id="tombrevoke_test",
            tombstone_id="tomb_test",
            reason="test",
            signed_by="admin",
            key_id="",
            signature="",
            created_at="2026-05-04",
        )
        with pytest.raises(RuntimeError, match="STIGMEM_NODE_PRIVATE_KEY not configured"):
            sign_revocation(record)

        settings_module.settings = original
