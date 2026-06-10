"""Phase 2b — v2 origin signature, envelope, and per-origin tenant map."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from stigmem_node.db import db
from stigmem_node.federation.origin_signature import (
    OriginSignatureError,
    canonical_origin_tuple,
    sign_origin,
    verify_origin_signature,
)


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


_CID = "sha256:" + "a" * 64
_FID = "11111111-1111-1111-1111-111111111111"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return priv, pub_b64


def _origin_block(node_id="stigmem:node:o1", tenant="acme"):
    return {"tenant": tenant, "node_id": node_id, "allowed_scopes": ["public"],
            "allowed_tenants": [tenant]}


def test_sign_and_verify_roundtrip():
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(
        priv, fact_id=_FID, cid=_CID, origin=origin, valid_until="2027-01-01T00:00:00Z"
    )
    verify_origin_signature(sig, fact_id=_FID, cid=_CID, origin=origin,
                            valid_until="2027-01-01T00:00:00Z", allowed_pubkeys={pub})


def test_verify_rejects_tampered_tenant():
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(sig, fact_id=_FID, cid=_CID, origin=dict(origin, tenant="victim"),
                                valid_until=None, allowed_pubkeys={pub})


def test_verify_rejects_tampered_fact_id():
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(sig, fact_id="22222222-2222-2222-2222-222222222222", cid=_CID,
                                origin=origin, valid_until=None, allowed_pubkeys={pub})


def test_verify_rejects_tampered_valid_until():
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(
        priv, fact_id=_FID, cid=_CID, origin=origin, valid_until="2027-01-01T00:00:00Z"
    )
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(sig, fact_id=_FID, cid=_CID, origin=origin,
                                valid_until="2099-01-01T00:00:00Z", allowed_pubkeys={pub})


def test_verify_rejects_wrong_key():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(sig, fact_id=_FID, cid=_CID, origin=origin,
                                valid_until=None, allowed_pubkeys={other_pub})


def test_verify_accepts_any_key_in_set():
    """Rotation-window dual-trust: verify succeeds if ANY key in the set matches."""
    priv, pub = _keypair()
    _, other_pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    verify_origin_signature(sig, fact_id=_FID, cid=_CID, origin=origin,
                            valid_until=None, allowed_pubkeys={other_pub, pub})


def test_empty_sig_or_keyset_rejected():
    origin = _origin_block()
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            "", fact_id=_FID, cid=_CID, origin=origin, valid_until=None, allowed_pubkeys={"k"}
        )
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            "sig", fact_id=_FID, cid=_CID, origin=origin, valid_until=None, allowed_pubkeys=set()
        )


def test_canonical_tuple_is_order_insensitive():
    a = canonical_origin_tuple(fact_id=_FID, cid=_CID, origin_tenant="t", origin_node_id="n",
                               origin_allowed_scopes=["team", "public"],
                               origin_allowed_tenants=["b", "a"], valid_until=None)
    b = canonical_origin_tuple(fact_id=_FID, cid=_CID, origin_tenant="t", origin_node_id="n",
                               origin_allowed_scopes=["public", "team"],
                               origin_allowed_tenants=["a", "b"], valid_until=None)
    assert a == b


def _insert_peer(conn, peer_id, node_id, **cols):
    base = {
        "id": peer_id, "node_id": node_id, "node_url": "http://x",
        "federation_pubkey": "PUB", "allowed_scopes": "[]", "status": "active",
        "declaration_sig": "SIG", "signed_at": "2026-01-01T00:00:00Z",
    }
    base.update(cols)
    keys = ", ".join(base)
    ph = ", ".join("?" * len(base))
    conn.execute(f"INSERT INTO peers ({keys}) VALUES ({ph})", tuple(base.values()))  # noqa: S608


def test_origin_tenant_explicit_mapping_wins(client):
    from stigmem_node.db import db
    from stigmem_node.federation.peer_policy import resolve_origin_tenant_for_peer
    with db() as conn:
        _insert_peer(conn, "pt1", "stigmem:node:t1")
        conn.execute("INSERT INTO peer_tenant_map (peer_id, origin_tenant, local_tenant) "
                     "VALUES ('pt1', 'acme', 'tenant-acme')")
        conn.commit()
        peer = conn.execute("SELECT * FROM peers WHERE id='pt1'").fetchone()
        assert resolve_origin_tenant_for_peer(peer, "acme", conn) == "tenant-acme"


def test_origin_tenant_unmapped_nondefault_denied(client):
    import pytest

    from stigmem_node.db import db
    from stigmem_node.federation.peer_policy import PeerPolicyError, resolve_origin_tenant_for_peer
    with db() as conn:
        _insert_peer(conn, "pt2", "stigmem:node:t2")
        conn.commit()
        peer = conn.execute("SELECT * FROM peers WHERE id='pt2'").fetchone()
        with pytest.raises(PeerPolicyError):
            resolve_origin_tenant_for_peer(peer, "acme", conn)


def test_origin_tenant_default_falls_back_on_single_tenant_node(client):
    """No map rows + origin_tenant='default' on a single-tenant node -> Phase-1 pin."""
    from stigmem_node.db import db
    from stigmem_node.federation.peer_policy import resolve_origin_tenant_for_peer
    with db() as conn:
        _insert_peer(conn, "pt3", "stigmem:node:t3", ingest_tenant="default")
        conn.commit()
        peer = conn.execute("SELECT * FROM peers WHERE id='pt3'").fetchone()
        assert resolve_origin_tenant_for_peer(peer, "default", conn) == "default"


def test_origin_tenant_default_denied_when_map_exists(client):
    import pytest

    from stigmem_node.db import db
    from stigmem_node.federation.peer_policy import PeerPolicyError, resolve_origin_tenant_for_peer
    with db() as conn:
        _insert_peer(conn, "pt4", "stigmem:node:t4", ingest_tenant="default")
        conn.execute("INSERT INTO peer_tenant_map (peer_id, origin_tenant, local_tenant) "
                     "VALUES ('pt4', 'acme', 'tenant-acme')")
        conn.commit()
        peer = conn.execute("SELECT * FROM peers WHERE id='pt4'").fetchone()
        with pytest.raises(PeerPolicyError):
            resolve_origin_tenant_for_peer(peer, "default", conn)


def test_origin_tenant_default_denied_on_multitenant_node(client, monkeypatch):
    """F-4 security crux: on a multi-tenant node an unmapped origin_tenant='default'
    is DENIED — never silently landing in the default tenant. The probe is imported
    function-locally from ..multi_tenant_gate, so patch it at that source module."""
    import pytest

    from stigmem_node.db import db
    from stigmem_node.federation.peer_policy import PeerPolicyError, resolve_origin_tenant_for_peer

    monkeypatch.setattr(
        "stigmem_node.multi_tenant_gate.multi_tenant_plugin_registered", lambda: True
    )
    with db() as conn:
        _insert_peer(conn, "pt5", "stigmem:node:t5", ingest_tenant="default")
        conn.commit()
        peer = conn.execute("SELECT * FROM peers WHERE id='pt5'").fetchone()
        with pytest.raises(PeerPolicyError):
            resolve_origin_tenant_for_peer(peer, "default", conn)


def test_ingest_fact_persists_origin_block(client):
    import json as _json

    from stigmem_node.cid import compute_cid
    from stigmem_node.db import db
    from stigmem_node.federation.federation_ingest import ingest_fact

    fact = {
        "id": "44444444-4444-4444-4444-444444444444",
        "entity": "stigmem://test/agent/o", "relation": "test:name",
        "value": {"type": "string", "v": "x"}, "source": "stigmem:node:o1",
        "timestamp": "2026-06-01T00:00:00Z", "scope": "public",
        "confidence": 1.0,
    }
    fact["cid"] = compute_cid(
        entity=fact["entity"], relation=fact["relation"], value_type="string",
        value_v="x", source=fact["source"], scope="public",
        confidence=1.0, interpret_as="content",
    )
    ingest_fact(
        fact, "stigmem:node:o1", tenant_id="default",
        origin_node_id="stigmem:node:o1", origin_allowed_scopes=["public"],
        origin_tenant="acme", origin_allowed_tenants=["beta", "acme"], origin_sig="SIGB64",
    )
    with db() as conn:
        row = conn.execute(
            "SELECT origin_tenant, origin_allowed_tenants, origin_sig FROM facts WHERE id=?",
            (fact["id"],),
        ).fetchone()
    assert row["origin_tenant"] == "acme"
    # F-8: stored byte-identical to the signed canonical form == json.dumps(sorted(...))
    assert row["origin_allowed_tenants"] == _json.dumps(["acme", "beta"])
    assert row["origin_sig"] == "SIGB64"
