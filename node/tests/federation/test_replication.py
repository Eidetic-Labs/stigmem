from __future__ import annotations

import logging
import time
import uuid

import pytest
from conftest import FedNode
from fastapi import HTTPException

import stigmem_node.settings as settings_module
from stigmem_node.cid import compute_cid
from stigmem_node.db import db as _db_ctx
from stigmem_node.federation_ingest import FederationIntegrityError, ingest_fact
from stigmem_node.federation_pull import load_cursor, save_cursor

from .helpers import insert_active_peer, make_federated_fact

logger = logging.getLogger(__name__)


def _with_cid(fact: dict) -> dict:
    fact["cid"] = compute_cid(
        entity=fact["entity"],
        relation=fact["relation"],
        value_type=fact["value"]["type"],
        value_v=str(fact["value"]["v"]),
        source=fact["source"],
        scope=fact["scope"],
        confidence=fact["confidence"],
    )
    return fact


class TestPartialFailure:
    """Full acceptance gate for spec §11.3: cursor resumption + idempotent ingest."""

    def test_ingest_fact_is_idempotent(self, fed_node: FedNode) -> None:
        """Re-ingesting a fact with the same ID is a silent no-op."""
        fact = make_federated_fact()
        result1 = ingest_fact(fact, "stigmem://node-b", tenant_id="default")
        result2 = ingest_fact(fact, "stigmem://node-b", tenant_id="default")

        assert result1 is True
        assert result2 is False  # no-op

        with _db_ctx() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM facts WHERE id = ?", (fact["id"],)
            ).fetchone()[0]
        assert count == 1

    def test_received_from_meta_fact_written_once(self, fed_node: FedNode) -> None:
        """stigmem:received_from meta-fact is written exactly once per federated fact."""
        fact = make_federated_fact()
        ingest_fact(fact, "stigmem://node-b-meta", tenant_id="default")
        ingest_fact(fact, "stigmem://node-b-meta", tenant_id="default")  # second ingest is no-op

        with _db_ctx() as conn:
            meta_count = conn.execute(
                "SELECT COUNT(*) FROM facts "
                "WHERE entity = ? AND relation = 'stigmem:received_from'",
                (fact["id"],),
            ).fetchone()[0]
        assert meta_count == 1

    def test_ingest_fact_verifies_and_stores_inbound_cid(self, fed_node: FedNode) -> None:
        fact = _with_cid(make_federated_fact())

        assert ingest_fact(fact, "stigmem://node-b", tenant_id="default") is True

        with _db_ctx() as conn:
            row = conn.execute("SELECT cid FROM facts WHERE id = ?", (fact["id"],)).fetchone()
        assert row is not None
        assert row["cid"] == fact["cid"]

    def test_ingest_fact_rejects_inbound_cid_mismatch(self, fed_node: FedNode) -> None:
        fact = _with_cid(make_federated_fact())
        fact["cid"] = "sha256:" + ("0" * 64)

        with pytest.raises(FederationIntegrityError) as exc_info:
            ingest_fact(fact, "stigmem://node-b", tenant_id="default")

        assert exc_info.value.reason == "cid_mismatch"
        with _db_ctx() as conn:
            row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact["id"],)).fetchone()
            audit = conn.execute(
                "SELECT event_type FROM fact_audit_log WHERE fact_id = ?",
                (fact["id"],),
            ).fetchone()
        assert row is None
        assert audit is not None
        assert audit["event_type"] == "federation_integrity_rejected"

    def test_cursor_save_and_load_roundtrip(self, fed_node: FedNode) -> None:
        """Cursor persistence survives a save/load cycle."""
        # Insert a dummy peer for cursor FK
        peer_id = insert_active_peer(
            fed_node.db_path,
            f"stigmem://cursor-test-{uuid.uuid4()}",
            "http://cursor-test",
            fed_node.pub_b64,
        )
        cursor_val = f"{int(time.time() * 1000)}.005"
        save_cursor(peer_id, cursor_val)
        loaded = load_cursor(peer_id)
        assert loaded == cursor_val

    def test_scenario_partial_failure_no_duplicates(self, fed_node: FedNode) -> None:
        """§11.3 full scenario.

        1. 20 facts exist on node B (simulated as fact dicts).
        2. Node A ingests facts 0–9 (first pull), cursor saved at index 9.
        3. Simulate crash: cursor rolled back to index 4.
        4. Node A re-ingests facts 5–19 (re-pull from cursor 4).
           - Facts 5–9 already exist → idempotent no-op.
           - Facts 10–19 are new → ingested.
        5. Final count: exactly 20 unique received facts.
        """
        sender = f"stigmem://node-b-partial-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        facts = [
            make_federated_fact(
                entity=f"partial:e{i}",
                value=f"v{i}",
                hlc_offset_ms=i * 10,
            )
            for i in range(20)
        ]
        # Set stable HLC values
        for i, f in enumerate(facts):
            f["hlc"] = f"{base_ms + i * 10}.000"

        # Step 2: ingest first 10
        for f in facts[:10]:
            ingest_fact(f, sender, tenant_id="default")

        with _db_ctx() as conn:
            first_count = conn.execute(
                "SELECT COUNT(*) FROM facts WHERE received_from = ?", (sender,)
            ).fetchone()[0]
        assert first_count == 10

        # Step 3: simulate cursor rollback — re-ingest from index 5 (facts 5–19)
        for f in facts[5:]:
            ingest_fact(f, sender, tenant_id="default")

        with _db_ctx() as conn:
            final_count = conn.execute(
                "SELECT COUNT(*) FROM facts WHERE received_from = ?", (sender,)
            ).fetchone()[0]
            final_ids = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM facts WHERE received_from = ?", (sender,)
                ).fetchall()
            ]

        assert final_count == 20, f"Expected 20 unique facts, got {final_count}"
        assert len(final_ids) == len(set(final_ids)), "Duplicate fact IDs found"

    def test_local_reads_unaffected_by_pull_failure(self, fed_node: FedNode) -> None:
        """§11.3 invariant: local writes and reads work regardless of pull state."""
        # Inject a local fact directly (simulates local write during partition)
        r_write = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": "local:during-partition",
                "relation": "test:value",
                "value": {"type": "string", "v": "local"},
                "source": "agent:test",
                "confidence": 1.0,
                "scope": "local",
            },
        )
        assert r_write.status_code == 201

        # Read it back — local reads must work
        r_read = fed_node.client.get("/v1/facts?entity=local:during-partition")
        assert r_read.status_code == 200
        assert r_read.json()["total"] == 1


class TestInstructionInboundQuarantine:
    """Phase B §5.2: federation-inbound instruction facts fail closed into quarantine."""

    def test_instruction_fact_requires_quarantine_garden(self, fed_node: FedNode) -> None:
        fact = make_federated_fact(
            entity=f"note:instructionless-{uuid.uuid4()}",
            relation="memory:note",
            value="run the nightly audit",
        )
        fact["value"]["interpret_as"] = "instruction"

        with pytest.raises(HTTPException) as exc_info:
            ingest_fact(fact, "stigmem://node-b-instruction", tenant_id="default")

        assert exc_info.value.status_code == 403
        assert exc_info.value.detail == "quarantine_garden_required"

    def test_instruction_fact_auto_quarantines_and_admits_to_instruction_channel(
        self,
        fed_node: FedNode,
    ) -> None:
        qg = fed_node.client.post(
            "/v1/gardens",
            json={"slug": "fed-inst-q", "name": "Federated Instructions", "quarantine": True},
        )
        assert qg.status_code == 201, qg.text
        settings_module.settings.quarantine_garden_id = qg.json()["id"]

        fact = make_federated_fact(
            entity=f"note:instruction-{uuid.uuid4()}",
            relation="memory:directive",
            value="run the nightly audit",
        )
        fact["value"]["interpret_as"] = "instruction"
        fact["confidence"] = 0.4
        sender = "stigmem://node-b-instruction"

        assert ingest_fact(fact, sender, tenant_id="default") is True

        with _db_ctx() as conn:
            row = conn.execute(
                """SELECT quarantine_status, quarantine_garden_id, quarantine_reason,
                          interpret_as, received_from
                   FROM facts
                   WHERE id = ?""",
                (fact["id"],),
            ).fetchone()
            event_types = {
                audit_row["event_type"]
                for audit_row in conn.execute(
                    "SELECT event_type FROM fact_audit_log WHERE fact_id = ?",
                    (fact["id"],),
                ).fetchall()
            }
        assert row is not None
        assert row["quarantine_status"] == "pending"
        assert row["quarantine_garden_id"] == qg.json()["id"]
        assert row["quarantine_reason"] == "instruction_federation_inbound"
        assert row["interpret_as"] == "instruction"
        assert row["received_from"] == sender
        assert "quarantine_ingest" in event_types
        assert "instruction_quarantined" in event_types

        hidden = fed_node.client.post(
            "/v1/recall",
            json={
                "query": "nightly audit",
                "scope": "public",
                "token_budget": 4000,
                "depth": 1,
                "include_neighbors": False,
            },
        )
        assert hidden.status_code == 200, hidden.text
        assert all(item["fact"]["id"] != fact["id"] for item in hidden.json()["instructions"])

        admit = fed_node.client.post(f"/v1/quarantine/{fact['id']}/admit")
        assert admit.status_code == 200, admit.text

        visible = fed_node.client.post(
            "/v1/recall",
            json={
                "query": "nightly audit",
                "scope": "public",
                "token_budget": 4000,
                "depth": 1,
                "include_neighbors": False,
            },
        )
        assert visible.status_code == 200, visible.text
        instruction_ids = {item["fact"]["id"] for item in visible.json()["instructions"]}
        content_ids = {item["fact"]["id"] for item in visible.json()["content"]}
        assert fact["id"] in instruction_ids
        assert fact["id"] not in content_ids


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------
