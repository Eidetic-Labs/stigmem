"""Tests for the DNSSEC first-trust operator-confirm admin API (Rev 6 I9 / 3b.8).

The operator-confirm queue (``pending_first_trust``, migration 055) is the sole
non-DNSSEC first-trust fallback. These routes surface the queue and let an admin
take an explicit, friction-proportionate action on a parked candidate:

  * ``GET  /v1/federation/dnssec/pending``        — list quarantined candidates
  * ``POST /v1/federation/dnssec/pending/confirm`` — paste-to-confirm (fpr MUST
    byte-equal the stored candidate_key_fpr, NF-D4-5) -> pin + clear pending
  * ``POST /v1/federation/dnssec/pending/reject``  — clear pending without trust

All three are admin-gated (``admin:federation``); a caller WITHOUT that
capability gets 403, NOT 404 (TB-3: the route exists and is auth-gated, not
missing). ``entity_uri`` travels in the JSON body, never the URL (it carries
``://`` and ``/`` — privacy + encoding).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from conftest import FedNode

from stigmem_node.auth import create_api_key
from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.dnssec.quarantine import get_pending, quarantine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _admin_key() -> str:
    return create_api_key("agent:federation-admin", ["admin:federation", "federate"])


def _entity_uri() -> str:
    return f"https://memory-{uuid.uuid4().hex[:8]}.acme.example/"


def _node_id() -> str:
    return f"stigmem://node-{uuid.uuid4().hex[:8]}"


def _stage(
    *,
    entity_uri: str,
    node_id: str,
    candidate_key_fpr: str = "sha256:cafef00d",
    source: str = "unsigned",
    relay_peer: str | None = "peer-x",
) -> None:
    """Park one candidate in the operator-confirm queue."""
    with _db_ctx() as conn:
        quarantine(
            conn,
            entity_uri=entity_uri,
            node_id=node_id,
            candidate_key_fpr=candidate_key_fpr,
            source=source,
            relay_peer=relay_peer,
            now=datetime.now(UTC),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# 1. Auth gating — unauthorized caller gets 403, NOT 404 (TB-3)
# ---------------------------------------------------------------------------


class TestAdminGating:
    def test_list_non_admin_gets_403_not_404(self, fed_node: FedNode) -> None:
        r = fed_node.client.get(
            "/v1/federation/dnssec/pending",
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text

    def test_confirm_non_admin_gets_403_not_404(self, fed_node: FedNode) -> None:
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={
                "entity_uri": _entity_uri(),
                "node_id": _node_id(),
                "key_fpr": "sha256:cafef00d",
            },
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text

    def test_reject_non_admin_gets_403_not_404(self, fed_node: FedNode) -> None:
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/reject",
            json={"entity_uri": _entity_uri(), "node_id": _node_id()},
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# 2. GET /v1/federation/dnssec/pending — list staged rows
# ---------------------------------------------------------------------------


class TestListPending:
    def test_admin_lists_staged_rows(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _entity_uri()
        nid = _node_id()
        _stage(
            entity_uri=uri,
            node_id=nid,
            candidate_key_fpr="sha256:listrow",
            source="insecure-delegation",
            relay_peer="peer-list",
        )
        r = fed_node.client.get(
            "/v1/federation/dnssec/pending",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "pending" in body and isinstance(body["pending"], list)
        match = [
            p for p in body["pending"] if p["entity_uri"] == uri and p["node_id"] == nid
        ]
        assert len(match) == 1
        row = match[0]
        assert row["candidate_key_fpr"] == "sha256:listrow"
        assert row["source"] == "insecure-delegation"
        assert row["relay_peer"] == "peer-list"
        assert "seen_at" in row

    def test_empty_queue_lists_empty(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.get(
            "/v1/federation/dnssec/pending",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["pending"] == []


# ---------------------------------------------------------------------------
# 3. POST /v1/federation/dnssec/pending/confirm — paste-to-confirm (NF-D4-5)
# ---------------------------------------------------------------------------


class TestConfirm:
    def test_matching_fpr_creates_pin_and_clears_pending(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _entity_uri()
        nid = _node_id()
        fpr = "sha256:matchme"
        _stage(entity_uri=uri, node_id=nid, candidate_key_fpr=fpr)

        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={"entity_uri": uri, "node_id": nid, "key_fpr": fpr},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 201), r.text
        pin = r.json()
        assert pin["entity_uri"] == uri
        assert pin["node_id"] == nid
        assert pin["key_fpr"] == fpr
        # host is derived via host_from_entity_uri (I3) from the entity_uri.
        assert pin["host"]

        # Pending row is cleared; the pin is now the stored anchor.
        with _db_ctx() as conn:
            assert get_pending(conn, uri, nid) is None
            from stigmem_node.federation.dnssec.pin import get_pin

            stored = get_pin(conn, uri, nid)
        assert stored is not None
        assert stored.key_fpr == fpr

    def test_wrong_fpr_does_not_trust_and_keeps_row(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _entity_uri()
        nid = _node_id()
        _stage(entity_uri=uri, node_id=nid, candidate_key_fpr="sha256:thereal")

        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={"entity_uri": uri, "node_id": nid, "key_fpr": "sha256:wrong"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        # fpr mismatch -> 4xx, do NOT trust.
        assert 400 <= r.status_code < 500, r.text
        with _db_ctx() as conn:
            # Row still parked (not trusted, not cleared).
            assert get_pending(conn, uri, nid) is not None
            from stigmem_node.federation.dnssec.pin import get_pin

            assert get_pin(conn, uri, nid) is None

    def test_wrong_fpr_writes_audit_event(self, fed_node: FedNode) -> None:
        # A wrong-fingerprint confirm is a MITM/attack signal: it must be audited
        # (federation_audit row with dnssec_first_trust_confirm_rejected), even
        # though it 422s and leaves the row parked.
        admin_key = _admin_key()
        uri = _entity_uri()
        nid = _node_id()
        _stage(entity_uri=uri, node_id=nid, candidate_key_fpr="sha256:thereal")

        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={"entity_uri": uri, "node_id": nid, "key_fpr": "sha256:attacker"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 422, r.text
        with _db_ctx() as conn:
            rows = conn.execute(
                "SELECT detail FROM federation_audit "
                "WHERE peer_id=? AND event_type='dnssec_first_trust_confirm_rejected'",
                (uri,),
            ).fetchall()
        assert len(rows) == 1, rows
        assert "fpr_mismatch" in (rows[0][0] or "")

    def test_successful_confirm_and_reject_still_audit(self, fed_node: FedNode) -> None:
        # The pre-existing success/reject audit events still fire (no regression).
        admin_key = _admin_key()
        uri_ok = _entity_uri()
        nid_ok = _node_id()
        fpr = "sha256:auditok"
        _stage(entity_uri=uri_ok, node_id=nid_ok, candidate_key_fpr=fpr)
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={"entity_uri": uri_ok, "node_id": nid_ok, "key_fpr": fpr},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 201), r.text

        uri_rej = _entity_uri()
        nid_rej = _node_id()
        _stage(entity_uri=uri_rej, node_id=nid_rej, candidate_key_fpr="sha256:rej")
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/reject",
            json={"entity_uri": uri_rej, "node_id": nid_rej},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 204), r.text

        with _db_ctx() as conn:
            confirmed = conn.execute(
                "SELECT COUNT(*) FROM federation_audit "
                "WHERE peer_id=? AND event_type='dnssec_first_trust_confirmed'",
                (uri_ok,),
            ).fetchone()[0]
            rejected = conn.execute(
                "SELECT COUNT(*) FROM federation_audit "
                "WHERE peer_id=? AND event_type='dnssec_first_trust_rejected'",
                (uri_rej,),
            ).fetchone()[0]
        assert confirmed == 1
        assert rejected == 1

    def test_confirm_absent_row_returns_404(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={
                "entity_uri": _entity_uri(),
                "node_id": _node_id(),
                "key_fpr": "sha256:cafef00d",
            },
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 404, r.text

    def test_confirm_missing_field_422(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/confirm",
            json={"entity_uri": _entity_uri()},  # missing node_id + key_fpr
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 422, r.text


# ---------------------------------------------------------------------------
# 4. POST /v1/federation/dnssec/pending/reject — clear without trust
# ---------------------------------------------------------------------------


class TestReject:
    def test_reject_clears_row_without_trust(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        uri = _entity_uri()
        nid = _node_id()
        _stage(entity_uri=uri, node_id=nid, candidate_key_fpr="sha256:rejectme")

        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/reject",
            json={"entity_uri": uri, "node_id": nid},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code in (200, 204), r.text
        with _db_ctx() as conn:
            assert get_pending(conn, uri, nid) is None
            from stigmem_node.federation.dnssec.pin import get_pin

            # No pin created (rejected, never trusted).
            assert get_pin(conn, uri, nid) is None

    def test_reject_absent_row_returns_404(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.post(
            "/v1/federation/dnssec/pending/reject",
            json={"entity_uri": _entity_uri(), "node_id": _node_id()},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 404, r.text
