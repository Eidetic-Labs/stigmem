"""Tests for W4.1: operator origin-pin store + admin API.

The pin is the same trust primitive as 2a peer approval: the operator asserts
an out-of-band ``(entity_uri, node_id, key_fingerprint)`` binding.  The
fingerprint is computed with the same primitive as ``peer_pubkey_fingerprint``
so it is directly comparable to a manifest key's fingerprint (needed in W4.2
resolver).
"""

from __future__ import annotations

import uuid

from conftest import FedNode

from stigmem_node.auth import create_api_key
from stigmem_node.db import db as _db_ctx
from stigmem_node.routes._federation_impl import peer_pubkey_fingerprint

from .helpers import generate_ed25519_b64

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _admin_key() -> str:
    return create_api_key(
        "agent:federation-admin", ["admin:federation", "federate"]
    )


def _pin_uri(suffix: str = "") -> str:
    return f"stigmem://origin-{uuid.uuid4()}{suffix}"


def _node_id(suffix: str = "") -> str:
    return f"stigmem://node-pin-{uuid.uuid4()}{suffix}"


# ---------------------------------------------------------------------------
# 1. Store-level CRUD round-trips (unit)
# ---------------------------------------------------------------------------


class TestOriginPinsStore:
    def test_put_get_roundtrip(self, fed_node: FedNode) -> None:
        from stigmem_node.federation.origin_pins import get_origin_pin, put_origin_pin

        uri = _pin_uri()
        nid = _node_id()
        fp = "sha256:aabbcc"
        with _db_ctx() as conn:
            put_origin_pin(conn, entity_uri=uri, node_id=nid, key_fingerprint=fp, pinned_by="op:a")
            conn.commit()
        with _db_ctx() as conn:
            row = get_origin_pin(conn, entity_uri=uri, node_id=nid)
        assert row is not None
        assert row["entity_uri"] == uri
        assert row["node_id"] == nid
        assert row["key_fingerprint"] == fp
        assert row["pinned_by"] == "op:a"
        assert row["pinned_at"] is not None

    def test_get_absent_returns_none(self, fed_node: FedNode) -> None:
        from stigmem_node.federation.origin_pins import get_origin_pin

        with _db_ctx() as conn:
            result = get_origin_pin(conn, entity_uri=_pin_uri(), node_id=_node_id())
        assert result is None

    def test_list_contains_pin(self, fed_node: FedNode) -> None:
        from stigmem_node.federation.origin_pins import list_origin_pins, put_origin_pin

        uri = _pin_uri()
        nid = _node_id()
        with _db_ctx() as conn:
            put_origin_pin(
                conn, entity_uri=uri, node_id=nid, key_fingerprint="sha256:dd", pinned_by=None
            )
            conn.commit()
        with _db_ctx() as conn:
            pins = list_origin_pins(conn)
        assert any(p["entity_uri"] == uri and p["node_id"] == nid for p in pins)

    def test_delete_removes_pin_returns_true(self, fed_node: FedNode) -> None:
        from stigmem_node.federation.origin_pins import (
            delete_origin_pin,
            get_origin_pin,
            put_origin_pin,
        )

        uri = _pin_uri()
        nid = _node_id()
        with _db_ctx() as conn:
            put_origin_pin(
                conn, entity_uri=uri, node_id=nid, key_fingerprint="sha256:ee", pinned_by=None
            )
            conn.commit()
        with _db_ctx() as conn:
            deleted = delete_origin_pin(conn, entity_uri=uri, node_id=nid)
            conn.commit()
        assert deleted is True
        with _db_ctx() as conn:
            assert get_origin_pin(conn, entity_uri=uri, node_id=nid) is None

    def test_delete_absent_returns_false(self, fed_node: FedNode) -> None:
        from stigmem_node.federation.origin_pins import delete_origin_pin

        with _db_ctx() as conn:
            result = delete_origin_pin(conn, entity_uri=_pin_uri(), node_id=_node_id())
        assert result is False

    def test_upsert_replaces_fingerprint(self, fed_node: FedNode) -> None:
        """Pinning a different key for an existing (entity_uri, node_id) replaces it."""
        from stigmem_node.federation.origin_pins import get_origin_pin, put_origin_pin

        uri = _pin_uri()
        nid = _node_id()
        with _db_ctx() as conn:
            put_origin_pin(
                conn, entity_uri=uri, node_id=nid, key_fingerprint="sha256:old", pinned_by="op:a"
            )
            conn.commit()
        with _db_ctx() as conn:
            put_origin_pin(
                conn, entity_uri=uri, node_id=nid, key_fingerprint="sha256:new", pinned_by="op:b"
            )
            conn.commit()
        with _db_ctx() as conn:
            row = get_origin_pin(conn, entity_uri=uri, node_id=nid)
        assert row is not None
        assert row["key_fingerprint"] == "sha256:new"
        assert row["pinned_by"] == "op:b"

    def test_upsert_same_key_is_idempotent(self, fed_node: FedNode) -> None:
        """Pinning the same key twice is a no-op (no error, fingerprint unchanged)."""
        from stigmem_node.federation.origin_pins import get_origin_pin, put_origin_pin

        uri = _pin_uri()
        nid = _node_id()
        fp = "sha256:same"
        with _db_ctx() as conn:
            put_origin_pin(conn, entity_uri=uri, node_id=nid, key_fingerprint=fp, pinned_by="op:x")
            conn.commit()
        with _db_ctx() as conn:
            put_origin_pin(conn, entity_uri=uri, node_id=nid, key_fingerprint=fp, pinned_by="op:y")
            conn.commit()
        with _db_ctx() as conn:
            row = get_origin_pin(conn, entity_uri=uri, node_id=nid)
        assert row is not None
        assert row["key_fingerprint"] == fp


# ---------------------------------------------------------------------------
# 2. Fingerprint helper uses the same primitive as peer_pubkey_fingerprint
# ---------------------------------------------------------------------------


class TestFingerprintHelper:
    def test_pubkey_fingerprint_matches_peer_primitive(self) -> None:
        from stigmem_node.federation.origin_pins import fingerprint_from_pubkey

        pub_b64, _ = generate_ed25519_b64()
        expected = peer_pubkey_fingerprint(pub_b64)
        assert fingerprint_from_pubkey(pub_b64) == expected

    def test_fingerprint_format_is_sha256_prefixed(self) -> None:
        from stigmem_node.federation.origin_pins import fingerprint_from_pubkey

        pub_b64, _ = generate_ed25519_b64()
        fp = fingerprint_from_pubkey(pub_b64)
        assert fp.startswith("sha256:")
        assert len(fp) == len("sha256:") + 64  # 32 bytes hex = 64 chars


# ---------------------------------------------------------------------------
# 3. Admin route: POST /v1/federation/origin-pins (create)
# ---------------------------------------------------------------------------


class TestOriginPinsRoutePost:
    def test_admin_can_post_pin(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _pin_uri()
        nid = _node_id()
        pub_b64, _ = generate_ed25519_b64()
        from stigmem_node.federation.origin_pins import fingerprint_from_pubkey

        fp = fingerprint_from_pubkey(pub_b64)
        r = fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": uri, "node_id": nid, "key_fingerprint": fp},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 201), r.text
        body = r.json()
        assert body["entity_uri"] == uri
        assert body["node_id"] == nid
        assert body["key_fingerprint"] == fp

    def test_non_admin_gets_403_on_post(self, fed_node: FedNode) -> None:
        r = fed_node.client.post(
            "/v1/federation/origin-pins",
            json={
                "entity_uri": _pin_uri(),
                "node_id": _node_id(),
                "key_fingerprint": "sha256:ff",
            },
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text

    def test_post_missing_field_422(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": _pin_uri()},  # missing node_id + key_fingerprint
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 422, r.text

    def test_post_writes_audit_event(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _pin_uri()
        nid = _node_id()
        r = fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": uri, "node_id": nid, "key_fingerprint": "sha256:audit-test"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 201), r.text
        with _db_ctx() as conn:
            audit = conn.execute(
                "SELECT * FROM federation_audit WHERE event_type = 'origin_pin_set'"
                " ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        assert audit is not None, "origin_pin_set audit entry must be written"


# ---------------------------------------------------------------------------
# 4. Admin route: GET /v1/federation/origin-pins (list)
# ---------------------------------------------------------------------------


class TestOriginPinsRouteGet:
    def test_admin_can_list(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        # Seed one pin via POST so we have something to list
        uri = _pin_uri()
        nid = _node_id()
        fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": uri, "node_id": nid, "key_fingerprint": "sha256:list-test"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        r = fed_node.client.get(
            "/v1/federation/origin-pins",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "pins" in body
        assert isinstance(body["pins"], list)
        assert any(p["entity_uri"] == uri and p["node_id"] == nid for p in body["pins"])

    def test_non_admin_gets_403_on_list(self, fed_node: FedNode) -> None:
        r = fed_node.client.get(
            "/v1/federation/origin-pins",
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# 5. Admin route: DELETE /v1/federation/origin-pins/{entity_uri}/{node_id}
# ---------------------------------------------------------------------------


class TestOriginPinsRouteDelete:
    def test_admin_can_delete(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _pin_uri()
        nid = _node_id()
        fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": uri, "node_id": nid, "key_fingerprint": "sha256:del"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        r = fed_node.client.delete(
            "/v1/federation/origin-pins",
            params={"entity_uri": uri, "node_id": nid},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 200, r.text
        # Verify it's gone
        r2 = fed_node.client.get(
            "/v1/federation/origin-pins",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert not any(
            p["entity_uri"] == uri and p["node_id"] == nid
            for p in r2.json()["pins"]
        )

    def test_delete_absent_returns_404(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _pin_uri()
        nid = _node_id()
        r = fed_node.client.delete(
            "/v1/federation/origin-pins",
            params={"entity_uri": uri, "node_id": nid},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 404, r.text

    def test_non_admin_gets_403_on_delete(self, fed_node: FedNode) -> None:
        uri = _pin_uri()
        nid = _node_id()
        r = fed_node.client.delete(
            "/v1/federation/origin-pins",
            params={"entity_uri": uri, "node_id": nid},
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text

    def test_delete_writes_audit_event(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _pin_uri()
        nid = _node_id()
        fed_node.client.post(
            "/v1/federation/origin-pins",
            json={"entity_uri": uri, "node_id": nid, "key_fingerprint": "sha256:delaudit"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        r = fed_node.client.delete(
            "/v1/federation/origin-pins",
            params={"entity_uri": uri, "node_id": nid},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 200, r.text
        with _db_ctx() as conn:
            audit = conn.execute(
                "SELECT * FROM federation_audit WHERE event_type = 'origin_pin_deleted'"
                " ORDER BY ts DESC LIMIT 1"
            ).fetchone()
        assert audit is not None, "origin_pin_deleted audit entry must be written"
