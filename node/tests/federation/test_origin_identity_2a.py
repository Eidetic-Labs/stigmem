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
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, declaration_sig, signed_at) "
            "VALUES ('p1', 'stigmem:node:n1', 'http://x', 'PUB', '[]', 'active', 'SIG', '2026-01-01T00:00:00Z')"
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
