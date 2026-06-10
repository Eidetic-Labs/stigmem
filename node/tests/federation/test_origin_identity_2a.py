from stigmem_node.db import db


def test_peers_has_entity_uri_column(client):
    """Migration 043 adds a nullable entity_uri column to peers."""
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    assert "entity_uri" in cols


def test_existing_peer_row_defaults_entity_uri_null(client):
    """Backward-compat: a peer inserted without entity_uri reads NULL (not '')."""
    with db() as conn:
        # NOTE: declaration_sig + signed_at are NOT NULL in the live peers schema
        # (migration 038). They are supplied here only to satisfy those constraints;
        # entity_uri is deliberately omitted to exercise the NULL-default backward-compat path.
        conn.execute(
            "INSERT INTO peers "
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, "
            "declaration_sig, signed_at) "
            "VALUES ('p1', 'stigmem:node:n1', 'http://x', 'PUB', '[]', 'active', "
            "'SIG', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
        row = conn.execute("SELECT entity_uri FROM peers WHERE id='p1'").fetchone()
    assert row["entity_uri"] is None


def test_wellknown_publishes_entity_uri(fed_node):
    """The node advertises its own org entity_uri so peers can record+verify it.

    The entity_uri block is guarded by ``if settings.federation_enabled:`` and the
    default ``client`` fixture leaves federation disabled. We use the suite's existing
    ``fed_node`` fixture (conftest.py) — same mechanism test_well_known.py uses for the
    enabled-node case — which patches a federation_enabled=True Settings via _patch_settings.
    """
    body = fed_node.client.get("/.well-known/stigmem").json()
    assert "entity_uri" in body
    assert body["entity_uri"]  # non-empty (defaults to node_url when unset)


def test_get_node_entity_uri_defaults_to_node_url():
    from stigmem_node.db import get_node_entity_uri
    from stigmem_node.settings import settings

    assert get_node_entity_uri() in (settings.entity_uri or settings.node_url, settings.node_url)


def _store_peer_with_manifest(node_id, entity_uri, pub_b64, priv):
    """Insert an active peer bound to entity_uri and store its self-signed manifest."""
    from stigmem_node.db import db
    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest
    from stigmem_node.identity.trust_store import store_peer_manifest

    key_id = generate_key_id(priv.public_key())
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=key_id,
        public_key=pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(m, priv)
    store_peer_manifest(entity_uri, m, None, trust_mode="relaxed")
    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, entity_uri, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                node_id,
                node_id,
                "http://x",
                pub_b64,
                "[]",
                "active",
                entity_uri,
                "SIG",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()


def test_resolve_origin_key_returns_manifest_pubkey(client):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from stigmem_node.federation.origin_identity import resolve_origin_key

    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    _store_peer_with_manifest("stigmem:node:o1", "https://o1.example", pub_b64, priv)

    keys = resolve_origin_key("stigmem:node:o1")
    assert pub_b64 in keys


def test_resolve_origin_key_unbound_peer_fails_closed(client):
    import pytest

    from stigmem_node.db import db
    from stigmem_node.federation.origin_identity import (
        OriginIdentityError,
        resolve_origin_key,
    )

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "p2",
                "stigmem:node:o2",
                "http://x",
                "PUB",
                "[]",
                "active",
                "SIG",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()
    with pytest.raises(OriginIdentityError):
        resolve_origin_key("stigmem:node:o2")  # entity_uri is NULL -> fail closed


# ---------------------------------------------------------------------------
# Task 5 — bind + verify peers.entity_uri at registration (fail-open to NULL)
# ---------------------------------------------------------------------------


def _build_declaration(node_id, node_url, pub_b64, priv_b64, scopes, signed_at):
    """Build a valid PeerDeclaration body (mirrors test_peer_registration.py)."""
    from conftest import sign_declaration

    fields_to_sign = {
        "allowed_scopes": scopes,
        "federation_pubkey": pub_b64,
        "node_id": node_id,
        "node_url": node_url,
        "signed_at": signed_at,
    }
    sig = sign_declaration(priv_b64, fields_to_sign)
    return {
        "node_id": node_id,
        "node_url": node_url,
        "federation_pubkey": pub_b64,
        "allowed_scopes": scopes,
        "declaration_sig": sig,
        "signed_at": signed_at,
    }


def _mock_well_known(monkeypatch, peer_pub, entity_uri):
    """Stub the well-known fetch so it returns federation_pubkey + entity_uri offline."""
    import httpx as _httpx

    class _MockAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url):
            return _httpx.Response(
                200,
                json={"federation_pubkey": peer_pub, "entity_uri": entity_uri},
            )

    monkeypatch.setattr(
        "stigmem_node.routes._federation_impl.httpx.AsyncClient",
        lambda **_: _MockAsyncClient(),
    )


def _store_manifest_at(entity_uri, node_id, manifest_pub_b64, manifest_priv_b64):
    """Pre-store a self-signed manifest at entity_uri so get_peer_manifest resolves offline.

    The manifest is signed with the key matching ``manifest_pub_b64`` (verify_manifest
    self-checks the signature against the manifest's own public_key). Issued 2026-01-01,
    expires 2026-12-01 — currently valid (today 2026-06-09) and within the 365-day window.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest
    from stigmem_node.identity.trust_store import store_peer_manifest

    raw = base64.urlsafe_b64decode(manifest_priv_b64 + "=" * (-len(manifest_priv_b64) % 4))
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=manifest_pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(m, priv)
    store_peer_manifest(entity_uri, m, None, trust_mode="relaxed")


def test_registration_binds_entity_uri_when_manifest_consistent(fed_node, monkeypatch):
    """Manifest at E proves same key controls node_id AND entity_uri -> entity_uri bound."""
    import uuid

    from conftest import generate_keypair

    from stigmem_node.db import db as node_db

    peer_pub, peer_priv = generate_keypair()
    node_id = f"stigmem://test-bind-{uuid.uuid4()}"
    node_url = "http://test-bind"
    entity_uri = f"https://bind-{uuid.uuid4()}.example"

    # Manifest at E: public_key == peer_pub AND entities includes node_id (consistent).
    _store_manifest_at(entity_uri, node_id, peer_pub, peer_priv)
    _mock_well_known(monkeypatch, peer_pub, entity_uri)

    body = _build_declaration(
        node_id, node_url, peer_pub, peer_priv, ["public"], "2026-05-02T00:00:00Z"
    )
    r = fed_node.client.post(
        "/v1/federation/peers",
        json=body,
        headers={"Authorization": f"Bearer {fed_node.federate_key}"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "pending_approval", r.text

    with node_db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
    assert row is not None
    assert row["entity_uri"] == entity_uri


def test_registration_leaves_entity_uri_null_when_manifest_key_mismatch(fed_node, monkeypatch):
    """Manifest at E signed by a DIFFERENT key than peer's -> entity_uri stays NULL (fail-open)."""
    import uuid

    from conftest import generate_keypair

    from stigmem_node.db import db as node_db

    peer_pub, peer_priv = generate_keypair()
    other_pub, other_priv = generate_keypair()  # distinct key controls the manifest
    node_id = f"stigmem://test-mismatch-{uuid.uuid4()}"
    node_url = "http://test-mismatch"
    entity_uri = f"https://mismatch-{uuid.uuid4()}.example"

    # Manifest at E has public_key=other_pub != peer_pub. (Self-signed by other_priv so
    # verify_manifest passes; the binding still fails on the public_key != peer_pub check.)
    _store_manifest_at(entity_uri, node_id, other_pub, other_priv)
    _mock_well_known(monkeypatch, peer_pub, entity_uri)

    body = _build_declaration(
        node_id, node_url, peer_pub, peer_priv, ["public"], "2026-05-02T00:00:00Z"
    )
    r = fed_node.client.post(
        "/v1/federation/peers",
        json=body,
        headers={"Authorization": f"Bearer {fed_node.federate_key}"},
    )
    # Fail-OPEN: registration still succeeds (declaration verified), only binding skipped.
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "pending_approval", r.text

    with node_db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
    assert row is not None
    assert row["entity_uri"] is None


def _fed_admin_key() -> str:
    """Mint an admin:federation key so the PATCH route's permission check is satisfied.

    The ``client`` fixture runs with ``auth_required=False`` (its default identity is
    ``_ANON`` with read/write/federate only), but ``patch_peer_policy`` gates on
    ``can_admin_federation()``. ``resolve_identity`` still resolves a real key from the
    Authorization header even in non-required mode, so we pass this key to authorize —
    matching the pattern in test_peer_policy_patch.py. The route's permission check is
    NOT weakened.
    """
    from stigmem_node.auth import create_api_key

    return create_api_key("agent:federation-admin", ["admin:federation", "federate"])


def test_same_domain_rejected_without_verified_entity_uri(client):
    """Binding trust_tier=same_domain to a peer with NULL entity_uri is rejected (422)."""
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            ("pNT", "stigmem:node:nt", "http://x", "PUB", "[]", "active", "SIG",
             "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pNT",
        json={"trust_tier": "same_domain"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 422
    assert "entity_uri" in resp.json()["detail"].lower()


def test_same_domain_allowed_with_verified_entity_uri(client):
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, entity_uri, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("pV", "stigmem:node:v", "http://x", "PUB", "[]", "active", "https://v.example",
             "SIG", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pV",
        json={"trust_tier": "same_domain"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200


def test_cross_org_tier_allowed_without_entity_uri(client):
    """cross_org (the default tier) must NOT require entity_uri — only same_domain is gated."""
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            ("pCO", "stigmem:node:co", "http://x", "PUB", "[]", "active", "SIG",
             "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pCO",
        json={"trust_tier": "cross_org"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200
