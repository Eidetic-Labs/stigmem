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
import time as _time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt as _pyjwt
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
import stigmem_node.db as _db_mod
import stigmem_node.db as db_mod
import stigmem_node.lifecycle.tombstones as tombstones_mod
import stigmem_node.routes.federation as _fed_mod
import stigmem_node.settings as settings_module
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, sign_manifest
from stigmem_node.identity.trust_store import store_peer_manifest
from stigmem_node.lifecycle.tombstone_signing import _signing_body
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.models.tombstones import TombstoneRecord
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


# ---------------------------------------------------------------------------
# 4. Federation INBOUND bare-tombstone push: a peer pinned to a non-default tenant
#    must land its bare (pre-v2) tombstone in THAT tenant — not "default".
#
#    AC2-1 (F-SBOLA3 class, federation WRITE path): the bare/back-compat ingest
#    fall-through called ``apply_inbound_tombstone(record)`` without a tenant, so it
#    hardcoded the function default "default". The v2 + relay paths already resolve
#    the peer's pinned ``ingest_tenant`` fail-closed; this path must mirror them.
# ---------------------------------------------------------------------------

def _pub_b64(priv: Ed25519PrivateKey) -> str:
    return (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )


def _gen_keypair() -> tuple[Ed25519PrivateKey, str, str]:
    """Return (priv, pub_b64, priv_b64) for a fresh Ed25519 keypair."""
    priv = Ed25519PrivateKey.generate()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    return priv, _pub_b64(priv), priv_b64


def _make_peer_token(priv_b64: str, iss: str, sub: str) -> str:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    now_ms = int(_time.time() * 1000)
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now_ms,
        "exp": now_ms + 3_600_000,
        "nonce": str(uuid.uuid4()),
        "scopes": ["public", "*"],
    }
    return _pyjwt.encode(payload, privkey, algorithm="EdDSA")


def _make_fed_peer(
    *,
    db_file: str,
    node_id: str,
    entity_uri: str,
    pub_b64: str,
    priv: Ed25519PrivateKey,
    ingest_tenant: str | None,
) -> None:
    """Insert an active, entity_uri-bound federation peer + store its self-verifying manifest.

    Mirrors ``tests/federation/helpers.make_bound_peer`` so ``resolve_origin_key(node_id)``
    returns ``pub_b64`` (issuer-verify of the bare tombstone passes). ``ingest_tenant`` pins
    the per-peer tenant policy (migration 041); when non-default, the multi-tenant plugin must
    be active for the fail-closed resolver to honour it.
    """
    manifest = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(manifest, priv)
    store_peer_manifest(entity_uri, manifest, None, trust_mode="relaxed")

    conn = sqlite3.connect(db_file)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, entity_uri, declaration_sig, signed_at, ingest_tenant)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                node_id,
                "http://peer",
                pub_b64,
                '["public"]',
                "active",
                entity_uri,
                "test_dummy_sig",
                "2026-01-01T00:00:00Z",
                ingest_tenant,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _issuer_signed_bare_tombstone(
    issuer_priv: Ed25519PrivateKey, *, entity_uri: str, signed_by: str, key_id: str
) -> TombstoneRecord:
    rec = TombstoneRecord(
        id=f"tomb_{uuid.uuid4()}",
        entity_uri=entity_uri,
        scope="public",
        reason=None,
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    sig = base64.urlsafe_b64encode(issuer_priv.sign(_signing_body(rec))).decode().rstrip("=")
    return rec.model_copy(update={"signature": sig})


@pytest.fixture()
def fed_tombstone_node(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str], None, None]:
    """Tombstone + multi-tenant plugins active, trust_mode='relaxed', with the federation
    tombstone PUSH route mounted. Yields ``(client, db_file)``.

    The multi-tenant plugin is registered so a peer pinned to a non-default ``ingest_tenant``
    is honoured by the fail-closed resolver (otherwise it would raise PeerPolicyError).
    A non-default API key is created so the node is genuinely multi-tenant (the unpinned-peer
    fail-closed case fires).
    """
    db_file = str(tmp_path) + "/fed-tomb-tenant.db"
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    original_fed = _fed_mod.settings
    original_db = _db_mod.settings
    original_auth = auth_mod.settings
    node_priv, _node_pub, node_priv_b64 = _gen_keypair()
    test_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        trust_mode="relaxed",
        node_private_key=node_priv_b64,
    )
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    _db_mod.settings = test_settings
    _fed_mod.settings = test_settings

    # A non-default tenant key makes the node genuinely multi-tenant (probe in the resolver).
    create_api_key("agent:bob", ["read", "write", "admin"], tenant_id="tenant-b")

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
            yield c, db_file

    tombstones_mod.invalidate_tombstone_cache()
    settings_module.settings = original
    auth_mod.settings = original_auth
    _db_mod.settings = original_db
    _fed_mod.settings = original_fed


def _our_node_id(db_file: str) -> str:
    return _db_mod.get_or_create_node_id(db_path=db_file)


def _post_bare_tombstone(
    client: TestClient, rec: TombstoneRecord, *, peer_priv_b64: str, peer_node_id: str, our: str
) -> Any:
    token = _make_peer_token(peer_priv_b64, iss=peer_node_id, sub=our)
    return client.post(
        "/v1/federation/tombstones/ingest",
        json=rec.model_dump(),
        headers={"Authorization": f"Bearer {token}"},
    )


def _tombstone_tenant(db_file: str, tomb_id: str) -> str | None:
    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute("SELECT tenant_id FROM tombstones WHERE id = ?", (tomb_id,)).fetchone()
    finally:
        conn.close()
    return None if row is None else row[0]


def test_bare_push_lands_in_peer_pinned_tenant(
    fed_tombstone_node: tuple[TestClient, str],
) -> None:
    """A signature-verified peer pinned to ingest_tenant='tenant-b' that posts a BARE
    (pre-v2) tombstone must land it in tenant-b — NOT 'default' (the RTBF no-op /
    cross-tenant over-suppression bug)."""
    client, db_file = fed_tombstone_node
    priv, pub_b64, priv_b64 = _gen_keypair()
    node_id = f"stigmem://peer-{uuid.uuid4()}"
    entity_uri = f"https://peer-{uuid.uuid4()}.example"
    _make_fed_peer(
        db_file=db_file,
        node_id=node_id,
        entity_uri=entity_uri,
        pub_b64=pub_b64,
        priv=priv,
        ingest_tenant="tenant-b",
    )

    rec = _issuer_signed_bare_tombstone(
        priv,
        entity_uri="user:bare-tenant-b",
        signed_by=entity_uri,
        key_id=generate_key_id(priv.public_key()),
    )
    resp = _post_bare_tombstone(
        client, rec, peer_priv_b64=priv_b64, peer_node_id=node_id, our=_our_node_id(db_file)
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["written"] is True
    landed = _tombstone_tenant(db_file, rec.id)
    assert landed == "tenant-b", (
        f"bare tombstone from a tenant-b peer landed in {landed!r} (defaulted to 'default'?)"
    )


def test_v2_push_lands_in_peer_pinned_tenant(
    fed_tombstone_node: tuple[TestClient, str],
) -> None:
    """Regression pin for the v2-envelope counterpart: a v2 DIRECT tombstone from the
    same tenant-b-pinned peer ALSO lands in tenant-b — locking both ingest paths."""
    from stigmem_node.federation.origin_signature import sign_tombstone_origin

    client, db_file = fed_tombstone_node
    priv, pub_b64, priv_b64 = _gen_keypair()
    node_id = f"stigmem://peer-{uuid.uuid4()}"
    entity_uri = f"https://peer-{uuid.uuid4()}.example"
    _make_fed_peer(
        db_file=db_file,
        node_id=node_id,
        entity_uri=entity_uri,
        pub_b64=pub_b64,
        priv=priv,
        ingest_tenant="tenant-b",
    )

    rec = _issuer_signed_bare_tombstone(
        priv,
        entity_uri="user:v2-tenant-b",
        signed_by=entity_uri,
        key_id=generate_key_id(priv.public_key()),
    )
    origin = {
        "tenant": "default",
        "node_id": node_id,
        "allowed_scopes": ["public"],
        "allowed_tenants": ["default"],
        "entity_uri": entity_uri,
    }
    origin_sig = sign_tombstone_origin(
        priv,
        tombstone_id=rec.id,
        entity_uri=rec.entity_uri,
        scope=rec.scope,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
    )
    entry = {"tombstone": rec.model_dump(), "origin": origin, "origin_sig": origin_sig}
    token = _make_peer_token(priv_b64, iss=node_id, sub=_our_node_id(db_file))
    resp = client.post(
        "/v1/federation/tombstones/ingest",
        json=entry,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    landed = _tombstone_tenant(db_file, rec.id)
    assert landed == "tenant-b", f"v2 tombstone from a tenant-b peer landed in {landed!r}"


def test_bare_push_fail_closed_when_tenant_unresolvable(
    fed_tombstone_node: tuple[TestClient, str],
) -> None:
    """A peer with NO resolvable ingest tenant (unpinned on a multi-tenant node) → 403,
    no tombstone written. The bare path must NOT silently fall back to 'default'."""
    client, db_file = fed_tombstone_node
    priv, pub_b64, priv_b64 = _gen_keypair()
    node_id = f"stigmem://peer-{uuid.uuid4()}"
    entity_uri = f"https://peer-{uuid.uuid4()}.example"
    # No ingest_tenant pin → ambiguous on a multi-tenant node → PeerPolicyError → 403.
    _make_fed_peer(
        db_file=db_file,
        node_id=node_id,
        entity_uri=entity_uri,
        pub_b64=pub_b64,
        priv=priv,
        ingest_tenant=None,
    )

    rec = _issuer_signed_bare_tombstone(
        priv,
        entity_uri="user:bare-unresolvable",
        signed_by=entity_uri,
        key_id=generate_key_id(priv.public_key()),
    )
    resp = _post_bare_tombstone(
        client, rec, peer_priv_b64=priv_b64, peer_node_id=node_id, our=_our_node_id(db_file)
    )
    assert resp.status_code == 403, resp.text
    assert _tombstone_tenant(db_file, rec.id) is None, "tombstone written despite fail-closed 403"
