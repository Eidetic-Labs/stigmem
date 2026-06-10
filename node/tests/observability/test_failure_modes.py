"""Failure mode acceptance scenarios — spec §11.

Tests §11.3 (Partial Failure) and §11.4 (Replay Attack).
§11.1 (Split-Brain) conflict detection covered in test_federation.py.
§11.2 (Malicious Peer) scope/source enforcement covered in test_federation.py.

These tests validate protocol invariants without full two-server HTTP; the
replication functions are called directly where possible to keep tests fast
and deterministic.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid

import pytest
from conftest import FedNode, generate_keypair, make_peer_token

# ---------------------------------------------------------------------------
# §11.3 — Partial Failure: cursor persistence + idempotent ingestion
# ---------------------------------------------------------------------------


class TestPartialFailure:
    """
    §11.3 setup: publisher (Node B) has N public facts.
    Subscriber (Node A) pulls batches, persists cursor after each batch.
    If cursor is NOT persisted for a batch (simulated crash), the next pull
    re-fetches that batch and idempotency ensures no duplicates.
    """

    def _seed_facts(self, fed_node: FedNode, n: int) -> list[dict]:
        """Return N fact dicts representing what a publisher would serve."""
        facts = []
        base_ms = int(time.time() * 1000)
        for i in range(n):
            facts.append(
                {
                    "id": str(uuid.uuid4()),
                    "entity": f"test:entity-{i}",
                    "relation": "test:value",
                    "value": {"type": "string", "v": f"val-{i}"},
                    "source": "agent:publisher",
                    "timestamp": f"2026-05-02T00:00:0{i % 10}Z",
                    "hlc": f"{base_ms + i}.0",
                    "confidence": 1.0,
                    "scope": "public",
                    "valid_until": None,
                }
            )
        return facts

    def test_idempotent_ingestion_no_duplicates(self, fed_node: FedNode) -> None:
        """Re-ingesting the same fact is a silent no-op; no duplicate row created."""
        from stigmem_node.federation_ingest import ingest_fact

        fact = {
            "id": str(uuid.uuid4()),
            "entity": "test:idem",
            "relation": "test:x",
            "value": {"type": "string", "v": "v1"},
            "source": "agent:pub",
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{int(time.time() * 1000)}.0",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }

        r1 = ingest_fact(fact, "stigmem://remote", tenant_id="default")
        r2 = ingest_fact(fact, "stigmem://remote", tenant_id="default")  # replay
        r3 = ingest_fact(fact, "stigmem://remote", tenant_id="default")  # triple replay

        assert r1 is True
        assert r2 is False  # already exists — no-op
        assert r3 is False

        conn = sqlite3.connect(fed_node.db_path)
        count = conn.execute("SELECT COUNT(*) FROM facts WHERE id = ?", (fact["id"],)).fetchone()[0]
        conn.close()
        assert count == 1  # exactly one row, not three

    def test_cursor_saved_after_batch(self, fed_node: FedNode) -> None:
        """save_cursor stores the new cursor; load_cursor returns it."""
        from stigmem_node.federation_pull import load_cursor, save_cursor

        # Need a peer_id in the DB
        peer_id = str(uuid.uuid4())
        conn = sqlite3.connect(fed_node.db_path)
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                "stigmem://pub",
                "http://pub",
                "pubkey_placeholder",
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        assert load_cursor(peer_id) is None  # starts at beginning

        cursor_value = f"{int(time.time() * 1000)}.0"
        save_cursor(peer_id, cursor_value)
        assert load_cursor(peer_id) == cursor_value

        # Simulate updating cursor to a later position
        cursor_value_2 = f"{int(time.time() * 1000) + 100}.0"
        save_cursor(peer_id, cursor_value_2)
        assert load_cursor(peer_id) == cursor_value_2

    def test_partial_ingest_then_resume(self, fed_node: FedNode) -> None:
        """
        §11.3 core scenario:
        1. Publisher has 20 facts.
        2. Pull facts 0–9 (batch 1); save cursor at 9.
        3. Simulate crash: facts 10–14 ingested but cursor NOT saved.
        4. Resume from cursor-9: re-pull 10–14 (idempotent), then pull 15–19.
        5. Final state: 20 unique facts, no duplicates.
        """
        from stigmem_node.federation_ingest import ingest_fact
        from stigmem_node.federation_pull import load_cursor, save_cursor

        sender = "stigmem://publisher"
        facts = self._seed_facts(fed_node, 20)

        peer_id = str(uuid.uuid4())
        conn = sqlite3.connect(fed_node.db_path)
        conn.execute(
            """INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes,
               status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                sender,
                "http://pub",
                "pk",
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        # Batch 1: ingest facts 0–9, save cursor
        for f in facts[:10]:
            ingest_fact(f, sender, tenant_id="default")
        save_cursor(peer_id, facts[9]["hlc"])

        # Simulate partial batch: ingest 10–14 but do NOT save cursor
        for f in facts[10:15]:
            ingest_fact(f, sender, tenant_id="default")
        # cursor still points to facts[9]["hlc"]
        assert load_cursor(peer_id) == facts[9]["hlc"]

        # Resume: re-ingest facts 10–14 (idempotent no-ops) + ingest 15–19
        for f in facts[10:]:  # 10–19; 10–14 are re-plays
            ingest_fact(f, sender, tenant_id="default")
        save_cursor(peer_id, facts[19]["hlc"])

        # Verify final state: exactly 20 unique user facts (+ meta-facts)
        conn = sqlite3.connect(fed_node.db_path)
        user_fact_ids = set(
            r[0]
            for r in conn.execute(
                """SELECT id FROM facts
                   WHERE received_from IS NOT NULL AND relation != 'stigmem:received_from'"""
            ).fetchall()
        )
        conn.close()
        assert len(user_fact_ids) == 20
        assert load_cursor(peer_id) == facts[19]["hlc"]

    def test_local_reads_unaffected_during_pull_failure(self, fed_node: FedNode) -> None:
        """Local facts remain readable when pull fails (partition safety, §6.6 rule 4)."""
        # Assert a local fact
        r = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": "test:local",
                "relation": "test:val",
                "value": {"type": "string", "v": "always-readable"},
                "source": "agent:test",
                "confidence": 1.0,
                "scope": "local",
            },
        )
        assert r.status_code == 201

        # Simulate a failed pull (exception in ingest — bad fact format)
        from stigmem_node.federation_ingest import ingest_fact

        with pytest.raises(KeyError):
            ingest_fact({"id": "bad"}, "stigmem://broken", tenant_id="default")  # missing required fields

        # Local read still works
        r2 = fed_node.client.get("/v1/facts?entity=test:local")
        assert r2.status_code == 200
        assert r2.json()["total"] == 1

    def test_far_future_hlc_rejected_with_audit(self, fed_node: FedNode) -> None:
        """Inbound HLC beyond the future skew bound is rejected and audit-logged."""
        from stigmem_node.federation_ingest import FederationHlcSkewError, ingest_fact

        fact_id = str(uuid.uuid4())
        future_ms = int(time.time() * 1000) + 301_000
        fact = {
            "id": fact_id,
            "entity": "test:hlc-future",
            "relation": "test:x",
            "value": {"type": "string", "v": "future"},
            "source": "agent:pub",
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{future_ms}.0",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }

        with pytest.raises(FederationHlcSkewError) as caught:
            ingest_fact(fact, "stigmem://remote-future", tenant_id="default")

        assert caught.value.direction == "future"

        conn = sqlite3.connect(fed_node.db_path)
        conn.row_factory = sqlite3.Row
        try:
            stored = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
            audit = conn.execute(
                "SELECT * FROM fact_audit_log WHERE event_type = 'peer_hlc_anomaly'"
            ).fetchone()
        finally:
            conn.close()

        assert stored is None
        assert audit is not None
        detail = json.loads(audit["detail"])
        assert detail["direction"] == "future"
        assert detail["sender_node_id"] == "stigmem://remote-future"

    def test_far_past_hlc_rejected_with_audit(self, fed_node: FedNode) -> None:
        """Inbound HLC beyond the past skew bound is rejected and audit-logged."""
        from stigmem_node.federation_ingest import FederationHlcSkewError, ingest_fact

        fact_id = str(uuid.uuid4())
        past_ms = int(time.time() * 1000) - 2_592_001_000
        fact = {
            "id": fact_id,
            "entity": "test:hlc-past",
            "relation": "test:x",
            "value": {"type": "string", "v": "past"},
            "source": "agent:pub",
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{past_ms}.0",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }

        with pytest.raises(FederationHlcSkewError) as caught:
            ingest_fact(fact, "stigmem://remote-past", tenant_id="default")

        assert caught.value.direction == "past"

        conn = sqlite3.connect(fed_node.db_path)
        conn.row_factory = sqlite3.Row
        try:
            stored = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_id,)).fetchone()
            audit = conn.execute(
                "SELECT * FROM fact_audit_log WHERE event_type = 'peer_hlc_anomaly'"
            ).fetchone()
        finally:
            conn.close()

        assert stored is None
        assert audit is not None
        detail = json.loads(audit["detail"])
        assert detail["direction"] == "past"
        assert detail["sender_node_id"] == "stigmem://remote-past"


# ---------------------------------------------------------------------------
# §11.4 — Replay Attack (fully exercised in test_federation.py; extra cases here)
# ---------------------------------------------------------------------------


class TestReplayAttack:
    def test_token_used_once_succeeds(self, fed_node: FedNode) -> None:
        """First use of a valid token → HTTP 200 (§11.4 scenario 1)."""
        peer_pub, peer_priv = generate_keypair()
        peer_node_id = "stigmem://replay-peer-1"

        conn = sqlite3.connect(fed_node.db_path)
        peer_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes,
               status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                peer_node_id,
                "http://peer",
                peer_pub,
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        token = make_peer_token(peer_priv, peer_node_id, fed_node.node_id, ["public"])
        r = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.json()}"

    def test_replay_within_window_rejected_with_audit(self, fed_node: FedNode) -> None:
        """Replay within nonce window → 401, audit log written (§11.4 scenario 2)."""
        peer_pub, peer_priv = generate_keypair()
        peer_node_id = "stigmem://replay-peer-2"

        conn = sqlite3.connect(fed_node.db_path)
        peer_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes,
               status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                peer_node_id,
                "http://peer",
                peer_pub,
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        nonce = str(uuid.uuid4())
        token = make_peer_token(peer_priv, peer_node_id, fed_node.node_id, ["public"], nonce=nonce)

        r1 = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {token}"}
        )
        assert r1.status_code == 200

        r2 = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {token}"}
        )
        assert r2.status_code == 401
        assert r2.json()["detail"] == "nonce_already_seen"

        # Audit log must capture the replay attempt
        audit = fed_node.client.get(
            "/v1/federation/audit",
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        ).json()
        replay_entries = [e for e in audit["entries"] if e["event_type"] == "replay_attempt"]
        assert len(replay_entries) >= 1

    def test_fact_store_not_corrupted_by_replay(self, fed_node: FedNode) -> None:
        """Replay does not modify any facts in the store."""

        peer_pub, peer_priv = generate_keypair()
        peer_node_id = "stigmem://replay-peer-3"

        conn = sqlite3.connect(fed_node.db_path)
        peer_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes,
               status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                peer_node_id,
                "http://peer",
                peer_pub,
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        nonce = str(uuid.uuid4())
        token = make_peer_token(peer_priv, peer_node_id, fed_node.node_id, ["public"], nonce=nonce)

        # First use (legitimate)
        r1 = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {token}"}
        )
        assert r1.status_code == 200

        # Count facts before replay
        conn = sqlite3.connect(fed_node.db_path)
        count_before = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
        conn.close()

        # Replay (rejected)
        r2 = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {token}"}
        )
        assert r2.status_code == 401

        # Fact count must not have changed
        conn = sqlite3.connect(fed_node.db_path)
        count_after = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
        conn.close()
        assert count_before == count_after

    def test_expired_token_rejected(self, fed_node: FedNode) -> None:
        """Expired token → 401 token_expired (§11.4 scenario 4)."""
        peer_pub, peer_priv = generate_keypair()
        peer_node_id = "stigmem://expiry-peer-2"

        conn = sqlite3.connect(fed_node.db_path)
        conn.execute(
            """INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes,
               status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                peer_node_id,
                "http://peer",
                peer_pub,
                '["public"]',
                "active",
                "2026-05-02T00:00:00Z",
                "sig",
                "2026-05-02T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        expired_token = make_peer_token(
            peer_priv,
            peer_node_id,
            fed_node.node_id,
            ["public"],
            ttl_ms=1,
            offset_ms=-3_600_000,  # issued 1 hour ago, TTL=1ms → long expired
        )
        r = fed_node.client.get(
            "/v1/federation/facts", headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "token_expired"


# ---------------------------------------------------------------------------
# HLC property tests
# ---------------------------------------------------------------------------


class TestHLC:
    def test_tick_monotone(self) -> None:
        from stigmem_node.hlc import HLC

        h = HLC()
        prev = h.tick()
        for _ in range(100):
            curr = h.tick()
            assert HLC.compare(prev, curr) < 0
            prev = curr

    def test_receive_advances_beyond_remote(self) -> None:
        from stigmem_node.hlc import HLC

        h = HLC()
        future_ms = int(time.time() * 1000) + 60_000  # 1 minute in the future
        result = h.receive(f"{future_ms}.5")
        wall, ctr = result.split(".")
        assert int(wall) >= future_ms

    def test_compare_ordering(self) -> None:
        from stigmem_node.hlc import HLC

        assert HLC.compare("1000.0", "1001.0") < 0
        assert HLC.compare("1001.0", "1000.0") > 0
        assert HLC.compare("1000.0", "1000.0") == 0
        assert HLC.compare("1000.1", "1000.2") < 0
        assert HLC.compare("1000.2", "1000.1") > 0
