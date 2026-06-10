"""Phase 2b — v2 origin signature, envelope, and per-origin tenant map."""

from stigmem_node.db import db


def test_facts_has_v2_origin_columns(client):
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(facts)").fetchall()]
    assert "origin_tenant" in cols
    assert "origin_allowed_tenants" in cols
    assert "origin_sig" in cols


def test_peer_tenant_map_table_exists(client):
    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES "
            "('pm1','stigmem:node:m1','http://x','PUB','[]','active','SIG','2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO peer_tenant_map (peer_id, origin_tenant, local_tenant) "
            "VALUES ('pm1', 'acme', 'tenant-acme')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT local_tenant FROM peer_tenant_map WHERE peer_id='pm1' AND origin_tenant='acme'"
        ).fetchone()
    assert row["local_tenant"] == "tenant-acme"


def test_peer_tenant_map_cascades_on_peer_delete(client):
    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES "
            "('pm2','stigmem:node:m2','http://x','PUB','[]','active','SIG','2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO peer_tenant_map (peer_id, origin_tenant, local_tenant) "
            "VALUES ('pm2', 't', 'lt')"
        )
        conn.execute("DELETE FROM peers WHERE id='pm2'")
        conn.commit()
        row = conn.execute("SELECT 1 FROM peer_tenant_map WHERE peer_id='pm2'").fetchone()
    assert row is None
