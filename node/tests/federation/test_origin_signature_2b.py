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
