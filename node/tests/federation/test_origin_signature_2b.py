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
            "allowed_tenants": [tenant], "entity_uri": "https://o1.example"}


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
                               origin_allowed_tenants=["b", "a"], valid_until=None,
                               entity_uri="https://o.example")
    b = canonical_origin_tuple(fact_id=_FID, cid=_CID, origin_tenant="t", origin_node_id="n",
                               origin_allowed_scopes=["public", "team"],
                               origin_allowed_tenants=["a", "b"], valid_until=None,
                               entity_uri="https://o.example")
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


def _fed_admin_key() -> str:
    """Mint an admin:federation key so the PATCH route's permission check is satisfied.

    Mirrors test_origin_identity_2a.py / test_peer_policy_patch.py: the ``client``
    fixture's default anon identity has no ``admin:federation`` capability and would 403.
    """
    from stigmem_node.auth import create_api_key

    return create_api_key("agent:federation-admin", ["admin:federation", "federate"])


def test_patch_tenant_map_sets_rows(client):
    with db() as conn:
        _insert_peer(conn, "ptm1", "stigmem:node:tm1")
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/ptm1",
        json={"tenant_map": {"acme": "tenant-acme", "beta": "tenant-beta"}},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200, resp.text
    with db() as conn:
        rows = conn.execute(
            "SELECT origin_tenant, local_tenant FROM peer_tenant_map "
            "WHERE peer_id='ptm1' ORDER BY origin_tenant"
        ).fetchall()
    mapping = {r["origin_tenant"]: r["local_tenant"] for r in rows}
    assert mapping == {"acme": "tenant-acme", "beta": "tenant-beta"}


def test_patch_tenant_map_full_replace_and_clear(client):
    with db() as conn:
        _insert_peer(conn, "ptm2", "stigmem:node:tm2")
        conn.commit()
    admin = {"Authorization": f"Bearer {_fed_admin_key()}"}
    r1 = client.patch(
        "/v1/federation/peers/ptm2",
        json={"tenant_map": {"acme": "tenant-acme"}},
        headers=admin,
    )
    assert r1.status_code == 200, r1.text
    r2 = client.patch(
        "/v1/federation/peers/ptm2",
        json={"tenant_map": {}},
        headers=admin,
    )
    assert r2.status_code == 200, r2.text
    with db() as conn:
        rows = conn.execute(
            "SELECT 1 FROM peer_tenant_map WHERE peer_id='ptm2'"
        ).fetchall()
    assert rows == []


def test_patch_tenant_map_only_not_rejected_by_no_fields_guard(client):
    with db() as conn:
        _insert_peer(conn, "ptm3", "stigmem:node:tm3")
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/ptm3",
        json={"tenant_map": {"acme": "tenant-acme"}},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200, resp.text


def test_patch_tenant_map_invalid_tenant_id_422(client):
    with db() as conn:
        _insert_peer(conn, "ptm4", "stigmem:node:tm4")
        conn.commit()
    admin = {"Authorization": f"Bearer {_fed_admin_key()}"}
    bad_key = client.patch(
        "/v1/federation/peers/ptm4",
        json={"tenant_map": {"ACME!": "tenant-acme"}},
        headers=admin,
    )
    assert bad_key.status_code == 422, bad_key.text
    bad_val = client.patch(
        "/v1/federation/peers/ptm4",
        json={"tenant_map": {"acme": "Not A Tenant"}},
        headers=admin,
    )
    assert bad_val.status_code == 422, bad_val.text


def test_patch_tenant_map_audited(client):
    import json as _json

    with db() as conn:
        _insert_peer(conn, "ptm5", "stigmem:node:tm5")
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/ptm5",
        json={"tenant_map": {"acme": "tenant-acme"}},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200, resp.text
    with db() as conn:
        audit = conn.execute(
            "SELECT detail FROM federation_audit "
            "WHERE peer_id='ptm5' AND event_type='peer_policy_updated'"
        ).fetchone()
    assert audit is not None, "peer_policy_updated audit entry must be written"
    detail = _json.loads(audit["detail"])
    assert "tenant_map" in detail["updated"]


def test_patch_tenant_map_stores_normalized_ids(client):
    """A mixed-case tenant id validates (NFKC/lowercase) and is stored in canonical
    form, so the canonical wire origin_tenant the ingest path looks up actually matches."""
    with db() as conn:
        _insert_peer(conn, "ptm6", "stigmem:node:tm6")
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/ptm6",
        json={"tenant_map": {"ACME": "Tenant-ACME"}},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200, resp.text
    with db() as conn:
        row = conn.execute(
            "SELECT origin_tenant, local_tenant FROM peer_tenant_map WHERE peer_id='ptm6'"
        ).fetchone()
    assert row["origin_tenant"] == "acme"
    assert row["local_tenant"] == "tenant-acme"


def test_patch_tenant_map_replaces_with_new_nonempty_set(client):
    """Full-replace: a second non-empty map drops the old rows and stores only the new."""
    with db() as conn:
        _insert_peer(conn, "ptm7", "stigmem:node:tm7")
        conn.commit()
    admin = {"Authorization": f"Bearer {_fed_admin_key()}"}
    client.patch("/v1/federation/peers/ptm7",
                 json={"tenant_map": {"acme": "tenant-acme"}}, headers=admin)
    resp = client.patch("/v1/federation/peers/ptm7",
                        json={"tenant_map": {"beta": "tenant-beta"}}, headers=admin)
    assert resp.status_code == 200, resp.text
    with db() as conn:
        rows = conn.execute(
            "SELECT origin_tenant, local_tenant FROM peer_tenant_map WHERE peer_id='ptm7'"
        ).fetchall()
    mapping = {r["origin_tenant"]: r["local_tenant"] for r in rows}
    assert mapping == {"beta": "tenant-beta"}  # old 'acme' row gone


def test_bound_peer_envelope_verifies_end_to_end(client):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from stigmem_node.db import db
    from stigmem_node.federation.origin_identity import resolve_origin_key
    from stigmem_node.federation.origin_signature import verify_origin_signature

    from .helpers import make_bound_peer, make_v2_envelope

    priv = Ed25519PrivateKey.generate()
    pub = base64.urlsafe_b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode().rstrip("=")
    with db() as conn:
        make_bound_peer(conn, node_id="stigmem:node:b1",
                        entity_uri="https://b1.example", pub_b64=pub, priv=priv)
        conn.commit()
    keys = resolve_origin_key("stigmem:node:b1")
    assert pub in keys
    env = make_v2_envelope(
        priv,
        facts=[{"id": "33333333-3333-3333-3333-333333333333",
                "entity": "stigmem://t/a", "relation": "r",
                "value": {"type": "string", "v": "x"}, "source": "stigmem:node:b1",
                "scope": "public", "timestamp": "2026-06-01T00:00:00Z", "confidence": 1.0}],
        origin={"tenant": "default", "node_id": "stigmem:node:b1",
                "allowed_scopes": ["public"], "allowed_tenants": ["default"],
                "entity_uri": "https://b1.example"},
    )
    assert env["v"] == 2
    entry = env["facts"][0]
    assert entry["fact"]["cid"]  # envelope builder populated the cid
    verify_origin_signature(
        entry["origin_sig"], fact_id=entry["fact"]["id"], cid=entry["fact"]["cid"],
        origin=entry["origin"], valid_until=entry["fact"].get("valid_until"), allowed_pubkeys=keys,
    )  # no raise = the test infra is sound
