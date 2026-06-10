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
