"""Phase 2c W6.8 — secure v2 tombstone PUSH-ingest route.

The PULL path (``pull_tombstones_from_peer_once``, W6.5–W6.7) verifies origin-attestation
+ issuer-signer + relay_trusted gate + scope/tenant gate + fail-closed. This task brings the
PUSH-ingest route ``POST /v1/federation/tombstones/ingest`` to PARITY by routing a v2 envelope
through the SAME shared ``ingest_tombstone_entry`` helper — so the exposed receiver surface can
never be a weaker path than pull.

Tests (a–h):
  (a) v2 DIRECT tombstone (origin == sender) → applied (both sigs verified).
  (b) v2 RELAYED tombstone, relay ON + sender relay_trusted + origin resolvable → applied,
      origin columns + received_from persisted.
  (c) v2 RELAYED tombstone, sender NOT relay_trusted → 403, not applied.
  (d) v2 RELAYED tombstone, relay OFF → 403 (origin_not_sender), not applied.
  (e) v2 RELAYED tombstone, invalid ORIGIN sig → rejected (4xx), not applied.
  (f) v2 RELAYED tombstone, invalid ISSUER sig → rejected (4xx), not applied.
  (g) BACK-COMPAT (pinned): a bare (pre-v2) tombstone POST is ACCEPTED as a DIRECT,
      issuer-verified tombstone (received_from NULL) — existing single-node callers don't break.
  (h) covered by re-running tests/tombstones/test_tombstones.py (shared-helper refactor did not
      change the direct/bare-ingest behaviour).
"""

from __future__ import annotations

import base64
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.lifecycle.tombstones as tombstones_mod
import stigmem_node.routes.federation as fed_mod
import stigmem_node.routes.tombstones as tomb_routes_mod
import stigmem_node.settings as settings_module
from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.origin_signature import sign_tombstone_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.lifecycle.tombstone_signing import _signing_body
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.models.tombstones import TombstoneRecord
from stigmem_node.plugins.discovery import DiscoveredPlugin
from stigmem_node.plugins.testing import stigmem_plugins

from .helpers import generate_ed25519_b64, make_bound_peer

_TENANT = "default"

# Tombstone-plugin app harness (mirrors tests/tombstones/test_tombstones.py — the federation
# tombstone routes only mount when the experimental tombstones plugin is active).
_TOMBSTONE_PLUGIN_SRC = Path(__file__).resolve().parents[3] / "experimental" / "tombstones" / "src"
_TOMBSTONE_ENV = {
    "STIGMEM_TOMBSTONES_ENABLED": "true",
    "STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER": "true",
}


def _reset_tombstone_cache() -> None:
    tombstones_mod.invalidate_tombstone_cache()


def _tombstone_plugin_manifest() -> Any:
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    plugin = __import__("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


@contextmanager
def _tombstone_plugin_app(app: Any) -> Generator[None, None, None]:
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


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _tombstone_row(entity_uri: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstones WHERE entity_uri = ?", (entity_uri,)
        ).fetchone()
    return dict(row) if row is not None else None


def _make_peer_token(priv_b64: str, iss: str, sub: str) -> str:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    now_ms = int(time.time() * 1000)
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now_ms,
        "exp": now_ms + 3_600_000,
        "nonce": str(uuid.uuid4()),
        "scopes": ["public", "*"],
    }
    return pyjwt.encode(payload, privkey, algorithm="EdDSA")


def _issuer_signed_tombstone(
    issuer_priv: Ed25519PrivateKey,
    *,
    entity_uri: str,
    scope: str,
    signed_by: str,
    key_id: str,
) -> TombstoneRecord:
    rec = TombstoneRecord(
        id=f"tomb_{uuid.uuid4()}",
        entity_uri=entity_uri,
        scope=scope,
        reason=None,
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    sig = base64.urlsafe_b64encode(issuer_priv.sign(_signing_body(rec))).decode().rstrip("=")
    return rec.model_copy(update={"signature": sig})


def _origin_block(
    *,
    node_id: str,
    entity_uri: str,
    allowed_scopes: list[str],
) -> dict[str, Any]:
    return {
        "tenant": _TENANT,
        "node_id": node_id,
        "allowed_scopes": allowed_scopes,
        "allowed_tenants": [_TENANT],
        "entity_uri": entity_uri,
    }


def _v2_entry(
    origin_priv: Ed25519PrivateKey,
    *,
    tombstone: TombstoneRecord,
    origin: dict[str, Any],
    origin_sig: str | None = None,
) -> dict[str, Any]:
    if origin_sig is None:
        origin_sig = sign_tombstone_origin(
            origin_priv,
            tombstone_id=tombstone.id,
            entity_uri=tombstone.entity_uri,
            scope=tombstone.scope,
            origin_node_id=origin["node_id"],
            origin_tenant=origin["tenant"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_entity_uri=origin["entity_uri"],
        )
    return {
        "tombstone": tombstone.model_dump(),
        "origin": origin,
        "origin_sig": origin_sig,
    }


def _set_relay_enabled(value: bool) -> None:
    settings_module.settings.federation_relay_enabled = value


class _PushNode:
    def __init__(
        self,
        client: TestClient,
        *,
        our_node_id: str,
        sender_node_id: str,
        sender_entity_uri: str,
        sender_priv: Ed25519PrivateKey,
        sender_priv_b64: str,
        sender_key_id: str,
        origin_node_id: str,
        origin_entity_uri: str,
        origin_priv: Ed25519PrivateKey,
        origin_key_id: str,
    ) -> None:
        self.client = client
        self.our_node_id = our_node_id
        self.sender_node_id = sender_node_id
        self.sender_entity_uri = sender_entity_uri
        self.sender_priv = sender_priv
        self.sender_priv_b64 = sender_priv_b64
        self.sender_key_id = sender_key_id
        self.origin_node_id = origin_node_id
        self.origin_entity_uri = origin_entity_uri
        self.origin_priv = origin_priv
        self.origin_key_id = origin_key_id

    def sender_token(self) -> str:
        return _make_peer_token(self.sender_priv_b64, self.sender_node_id, sub=self.our_node_id)

    def post(self, payload: dict[str, Any]) -> Any:
        return self.client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers={"Authorization": f"Bearer {self.sender_token()}"},
        )


def _set_relay_trusted(db_file: str, node_id: str, value: int) -> None:
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("UPDATE peers SET relay_trusted = ? WHERE node_id = ?", (value, node_id))
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def push_node(tmp_path: Any) -> Generator[_PushNode, None, None]:
    """Tombstone-plugin app with a relay_trusted SENDER peer + separate ORIGIN bound-peer.

    trust_mode='relaxed' so the real crypto chain (resolve_origin_key + manifest verify +
    issuer-signer verify) runs end-to-end through the HTTP push surface.
    """
    db_file = str(tmp_path) + "/push_test.db"
    db_mod.apply_migrations(db_path=db_file)

    node_pub, node_priv_b64 = generate_ed25519_b64()

    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"
    sender_key_id = generate_key_id(sender_priv.public_key())

    origin_pub, origin_priv_b64 = generate_ed25519_b64()
    origin_priv = _priv_from_b64(origin_priv_b64)
    origin_node_id = f"stigmem://origin-{uuid.uuid4()}"
    origin_entity_uri = f"https://origin-{uuid.uuid4()}.example"
    origin_key_id = generate_key_id(origin_priv.public_key())

    original = settings_module.settings
    ts = settings_module.Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://pushnode",
        trust_mode="relaxed",
        node_private_key=node_priv_b64,
    )
    settings_module.settings = ts
    auth_mod.settings = ts
    db_mod.settings = ts
    fed_mod.settings = ts
    tomb_routes_mod.settings = ts
    _reset_tombstone_cache()

    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        conn.commit()
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=origin_node_id,
            entity_uri=origin_entity_uri,
            pub_b64=origin_pub,
            priv=origin_priv,
        )
        conn.commit()
    # The SENDER must use the federation_pubkey the peer JWT verifies against. make_bound_peer
    # already stored federation_pubkey=sender_pub, so the JWT signed by sender_priv verifies.

    our_node_id = db_mod.get_or_create_node_id(db_path=db_file)

    app = create_app()
    with _tombstone_plugin_app(app):
        client = TestClient(app, raise_server_exceptions=True)
        client.__enter__()
        yield _PushNode(
            client,
            our_node_id=our_node_id,
            sender_node_id=sender_node_id,
            sender_entity_uri=sender_entity_uri,
            sender_priv=sender_priv,
            sender_priv_b64=sender_priv_b64,
            sender_key_id=sender_key_id,
            origin_node_id=origin_node_id,
            origin_entity_uri=origin_entity_uri,
            origin_priv=origin_priv,
            origin_key_id=origin_key_id,
        )
        client.__exit__(None, None, None)

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original
    fed_mod.settings = original
    tomb_routes_mod.settings = original
    _reset_tombstone_cache()


# ---------------------------------------------------------------------------
# (a) v2 DIRECT tombstone (origin == sender) → applied
# ---------------------------------------------------------------------------


def test_push_v2_direct_tombstone_applied(push_node: _PushNode) -> None:
    _set_relay_enabled(True)  # relay ON must not change the direct path

    rec = _issuer_signed_tombstone(
        push_node.sender_priv,
        entity_uri="user:push-direct",
        scope="public",
        signed_by=push_node.sender_entity_uri,
        key_id=push_node.sender_key_id,
    )
    origin = _origin_block(
        node_id=push_node.sender_node_id,
        entity_uri=push_node.sender_entity_uri,
        allowed_scopes=["public"],
    )
    entry = _v2_entry(push_node.sender_priv, tombstone=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 200, resp.text
    assert resp.json()["written"] is True
    row = _tombstone_row("user:push-direct")
    assert row is not None
    # DIRECT/self → origin columns + received_from NULL (unchanged direct semantics).
    assert row["received_from"] is None
    assert row["origin_node_id"] is None
    assert row["origin_sig"] is None


# ---------------------------------------------------------------------------
# (b) v2 RELAYED tombstone, relay ON + relay_trusted + origin resolvable → applied
# ---------------------------------------------------------------------------


def test_push_v2_relayed_trusted_applied_with_columns(
    push_node: _PushNode, tmp_path: Any
) -> None:
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    rec = _issuer_signed_tombstone(
        push_node.origin_priv,
        entity_uri="user:push-relay",
        scope="public",
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _origin_block(
        node_id=push_node.origin_node_id,
        entity_uri=push_node.origin_entity_uri,
        allowed_scopes=["public", "team"],
    )
    entry = _v2_entry(push_node.origin_priv, tombstone=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 200, resp.text
    assert resp.json()["written"] is True
    row = _tombstone_row("user:push-relay")
    assert row is not None
    assert row["received_from"] == push_node.sender_node_id
    assert row["origin_node_id"] == push_node.origin_node_id
    assert row["origin_entity_uri"] == push_node.origin_entity_uri
    assert row["origin_sig"] == entry["origin_sig"]


# ---------------------------------------------------------------------------
# (c) v2 RELAYED tombstone, sender NOT relay_trusted → 403, not applied
# ---------------------------------------------------------------------------


def test_push_v2_relayed_untrusted_sender_rejected(push_node: _PushNode) -> None:
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 0)

    rec = _issuer_signed_tombstone(
        push_node.origin_priv,
        entity_uri="user:push-relay-untrusted",
        scope="public",
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _origin_block(
        node_id=push_node.origin_node_id,
        entity_uri=push_node.origin_entity_uri,
        allowed_scopes=["public"],
    )
    entry = _v2_entry(push_node.origin_priv, tombstone=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 403, resp.text
    assert "relay_sender_not_trusted" in resp.json()["detail"]
    assert _tombstone_row("user:push-relay-untrusted") is None


# ---------------------------------------------------------------------------
# (d) v2 RELAYED tombstone, relay OFF → 403 (origin_not_sender), not applied
# ---------------------------------------------------------------------------


def test_push_v2_relayed_relay_off_rejected(push_node: _PushNode) -> None:
    _set_relay_enabled(False)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    rec = _issuer_signed_tombstone(
        push_node.origin_priv,
        entity_uri="user:push-relay-off",
        scope="public",
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _origin_block(
        node_id=push_node.origin_node_id,
        entity_uri=push_node.origin_entity_uri,
        allowed_scopes=["public"],
    )
    entry = _v2_entry(push_node.origin_priv, tombstone=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 403, resp.text
    assert "origin_not_sender" in resp.json()["detail"]
    assert _tombstone_row("user:push-relay-off") is None


# ---------------------------------------------------------------------------
# (e) v2 RELAYED tombstone, invalid ORIGIN sig → rejected, not applied
# ---------------------------------------------------------------------------


def test_push_v2_relayed_invalid_origin_sig_rejected(push_node: _PushNode) -> None:
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    rec = _issuer_signed_tombstone(
        push_node.origin_priv,
        entity_uri="user:push-badorigin",
        scope="public",
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _origin_block(
        node_id=push_node.origin_node_id,
        entity_uri=push_node.origin_entity_uri,
        allowed_scopes=["public"],
    )
    entry = _v2_entry(
        push_node.origin_priv, tombstone=rec, origin=origin, origin_sig="not-a-valid-sig"
    )

    resp = push_node.post(entry)
    assert resp.status_code == 400, resp.text
    assert "origin_sig_invalid" in resp.json()["detail"]
    assert _tombstone_row("user:push-badorigin") is None


# ---------------------------------------------------------------------------
# (f) v2 RELAYED tombstone, invalid ISSUER sig → rejected, not applied
# ---------------------------------------------------------------------------


def test_push_v2_relayed_invalid_issuer_sig_rejected(push_node: _PushNode) -> None:
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    rec = _issuer_signed_tombstone(
        push_node.origin_priv,
        entity_uri="user:push-badissuer",
        scope="public",
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    # Corrupt the issuer signature; ORIGIN sig is signed over id/entity_uri/scope (unchanged).
    rec = rec.model_copy(update={"signature": "AAAA" + rec.signature[4:]})
    origin = _origin_block(
        node_id=push_node.origin_node_id,
        entity_uri=push_node.origin_entity_uri,
        allowed_scopes=["public"],
    )
    entry = _v2_entry(push_node.origin_priv, tombstone=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 400, resp.text
    assert "issuer_sig_invalid" in resp.json()["detail"]
    assert _tombstone_row("user:push-badissuer") is None


# ---------------------------------------------------------------------------
# (g) BACK-COMPAT pinned: bare (pre-v2) tombstone POST → accepted as DIRECT, issuer-verified
# ---------------------------------------------------------------------------


def test_push_bare_tombstone_accepted_as_direct(push_node: _PushNode) -> None:
    """PINNED back-compat decision: a bare (non-enveloped, pre-v2) tombstone POST is ACCEPTED
    as a DIRECT, issuer-verified tombstone (received_from NULL) so existing single-node callers
    do not break. A RELAYED tombstone must use the v2 envelope."""
    _set_relay_enabled(True)
    # The bare body is issuer-verified against the SENDER's stored manifest (signed_by = sender).
    rec = _issuer_signed_tombstone(
        push_node.sender_priv,
        entity_uri="user:push-bare",
        scope="public",
        signed_by=push_node.sender_entity_uri,
        key_id=push_node.sender_key_id,
    )

    resp = push_node.post(rec.model_dump())
    assert resp.status_code == 200, resp.text
    assert resp.json()["written"] is True
    row = _tombstone_row("user:push-bare")
    assert row is not None
    assert row["received_from"] is None
    assert row["origin_node_id"] is None
