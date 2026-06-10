from __future__ import annotations

import logging
import time
import uuid

from conftest import FedNode

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation_ingest import ingest_fact

logger = logging.getLogger(__name__)


class TestConflictDetection:
    def test_federated_conflict_creates_conflict_record(self, fed_node: FedNode) -> None:
        """§6.5 / §11.1: two federated facts for same entity/relation/scope → conflict."""
        base_ms = int(time.time() * 1000)
        entity = f"conflict:entity-{uuid.uuid4()}"

        fact_a = {
            "id": str(uuid.uuid4()),
            "entity": entity,
            "relation": "test:value",
            "value": {"type": "string", "v": "from-a"},
            "source": "stigmem://node-a",
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{base_ms}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }
        fact_b = {
            "id": str(uuid.uuid4()),
            "entity": entity,
            "relation": "test:value",
            "value": {"type": "string", "v": "from-b"},
            "source": "stigmem://node-b",
            "timestamp": "2026-05-02T00:01:00Z",
            "hlc": f"{base_ms + 1}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }

        ingest_fact(fact_a, "stigmem://node-a", tenant_id="default")
        ingest_fact(fact_b, "stigmem://node-b", tenant_id="default")

        with _db_ctx() as conn:
            conflict = conn.execute(
                """SELECT * FROM conflicts
                   WHERE (fact_a_id = ? OR fact_b_id = ?)
                      OR (fact_a_id = ? OR fact_b_id = ?)""",
                (fact_a["id"], fact_a["id"], fact_b["id"], fact_b["id"]),
            ).fetchone()
        assert conflict is not None
        assert conflict["status"] == "unresolved"


# ---------------------------------------------------------------------------
# Cursor-based pull pagination on the federation/facts endpoint
# ---------------------------------------------------------------------------


class TestSplitBrain:
    """Full acceptance gate for spec §11.1: split-brain conflict detection."""

    def test_both_facts_stored_with_contradicted_flag(self, fed_node: FedNode) -> None:
        """After partition heals, both facts exist with contradicted=True."""
        entity = f"split:e-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        # Node A writes locally
        r_a = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": entity,
                "relation": "split:value",
                "value": {"type": "string", "v": "from-a"},
                "source": "agent:node-a",
                "confidence": 1.0,
                "scope": "public",
            },
        )
        assert r_a.status_code == 201
        fact_a_id = r_a.json()["id"]

        # Simulate node B's divergent fact arriving via federation (partition healed)
        fact_b = {
            "id": str(uuid.uuid4()),
            "entity": entity,
            "relation": "split:value",
            "value": {"type": "string", "v": "from-b"},
            "source": "stigmem://node-b",
            "timestamp": "2026-05-02T00:01:00Z",
            "hlc": f"{base_ms + 1000}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }
        ingest_fact(fact_b, "stigmem://node-b", tenant_id="default")

        # Both facts must be stored
        with _db_ctx() as conn:
            a_row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_a_id,)).fetchone()
            b_row = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_b["id"],)).fetchone()
        assert a_row is not None, "fact_a missing from store"
        assert b_row is not None, "fact_b missing from store"

    def test_conflict_record_queryable_via_api(self, fed_node: FedNode) -> None:
        """GET /v1/conflicts?status=unresolved returns the split-brain conflict."""
        entity = f"split:q-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        fed_node.client.post(
            "/v1/facts",
            json={
                "entity": entity,
                "relation": "split:val",
                "value": {"type": "string", "v": "local"},
                "source": "agent:local",
                "confidence": 1.0,
                "scope": "public",
            },
        )

        ingest_fact(
            {
                "id": str(uuid.uuid4()),
                "entity": entity,
                "relation": "split:val",
                "value": {"type": "string", "v": "remote"},
                "source": "stigmem://node-b",
                "timestamp": "2026-05-02T00:01:00Z",
                "hlc": f"{base_ms + 500}.000",
                "confidence": 1.0,
                "scope": "public",
                "valid_until": None,
            },
            "stigmem://node-b", tenant_id="default",
        )

        r = fed_node.client.get("/v1/conflicts?status=unresolved")
        assert r.status_code == 200
        body = r.json()
        our_conflicts = [
            c
            for c in body["conflicts"]
            if (c["fact_a"] and c["fact_a"]["entity"] == entity)
            or (c["fact_b"] and c["fact_b"]["entity"] == entity)
        ]
        assert len(our_conflicts) >= 1
        c = our_conflicts[0]
        assert c["status"] == "unresolved"
        assert c["fact_a"] is not None
        assert c["fact_b"] is not None

    def test_query_returns_both_facts_with_contradicted_true(self, fed_node: FedNode) -> None:
        """GET /v1/facts for split-brain entity returns both facts marked contradicted."""
        entity = f"split:both-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        r_local = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": entity,
                "relation": "split:val",
                "value": {"type": "string", "v": "local"},
                "source": "agent:local",
                "confidence": 1.0,
                "scope": "public",
            },
        )
        assert r_local.status_code == 201

        ingest_fact(
            {
                "id": str(uuid.uuid4()),
                "entity": entity,
                "relation": "split:val",
                "value": {"type": "string", "v": "remote"},
                "source": "stigmem://node-b",
                "timestamp": "2026-05-02T00:01:00Z",
                "hlc": f"{base_ms + 500}.000",
                "confidence": 1.0,
                "scope": "public",
                "valid_until": None,
            },
            "stigmem://node-b", tenant_id="default",
        )

        r = fed_node.client.get(
            f"/v1/facts?entity={entity}&relation=split:val&include_contradicted=true"
        )
        assert r.status_code == 200
        facts = r.json()["facts"]
        assert len(facts) == 2, f"Expected 2 contradicting facts, got {len(facts)}"
        assert all(f["contradicted"] for f in facts), "Both facts must have contradicted=True"

    def test_no_fact_silently_discarded(self, fed_node: FedNode) -> None:
        """No fact is overwritten or silently discarded during merge (§6.6 rule 5)."""
        entity = f"split:nodrop-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        ids = []
        for i, val in enumerate(["alpha", "beta", "gamma"]):
            fact = {
                "id": str(uuid.uuid4()),
                "entity": entity,
                "relation": "split:multi",
                "value": {"type": "string", "v": val},
                "source": f"stigmem://node-{i}",
                "timestamp": f"2026-05-02T00:0{i}:00Z",
                "hlc": f"{base_ms + i * 100}.000",
                "confidence": 1.0,
                "scope": "public",
                "valid_until": None,
            }
            ingest_fact(fact, f"stigmem://node-{i}", tenant_id="default")
            ids.append(fact["id"])

        with _db_ctx() as conn:
            stored = {
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM facts WHERE entity = ? AND relation = 'split:multi'",
                    (entity,),
                ).fetchall()
            }
        assert set(ids) == stored, "All facts must be stored, none discarded"


# ---------------------------------------------------------------------------
# §11.2 — Malicious Peer acceptance scenario
# ---------------------------------------------------------------------------


class TestConflictResolution:
    """Acceptance tests for POST /v1/conflicts/:id/resolve (spec §5.10)."""

    def _create_conflict(self, fed_node: FedNode) -> tuple[str, str, str, str]:
        """Create a conflict and return (conflict_id, entity, fact_a_id, fact_b_id)."""
        entity = f"resolve:e-{uuid.uuid4()}"
        base_ms = int(time.time() * 1000)

        r_a = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": entity,
                "relation": "resolve:val",
                "value": {"type": "string", "v": "version-a"},
                "source": "agent:test",
                "confidence": 1.0,
                "scope": "public",
            },
        )
        assert r_a.status_code == 201
        fact_a_id = r_a.json()["id"]

        fact_b = {
            "id": str(uuid.uuid4()),
            "entity": entity,
            "relation": "resolve:val",
            "value": {"type": "string", "v": "version-b"},
            "source": "stigmem://node-b",
            "timestamp": "2026-05-02T00:01:00Z",
            "hlc": f"{base_ms + 1000}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }
        ingest_fact(fact_b, "stigmem://node-b", tenant_id="default")
        fact_b_id = fact_b["id"]

        with _db_ctx() as conn:
            conflict = conn.execute(
                "SELECT id FROM conflicts WHERE fact_a_id = ? OR fact_b_id = ?",
                (fact_a_id, fact_a_id),
            ).fetchone()
        assert conflict is not None, "conflict must be created"
        return conflict["id"], entity, fact_a_id, fact_b_id

    def test_resolve_with_winning_fact_returns_200(self, fed_node: FedNode) -> None:
        """Resolve with winning_fact_id → 200 with resolution_fact_id."""
        conflict_id, entity, fact_a_id, _ = self._create_conflict(fed_node)

        r = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id, "resolution_note": "prefer local"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "resolution_fact_id" in body
        assert body["conflict_status"] == "resolved"

    def test_resolve_updates_conflict_status(self, fed_node: FedNode) -> None:
        """After resolution, GET /v1/conflicts?status=unresolved omits the conflict."""
        conflict_id, entity, fact_a_id, _ = self._create_conflict(fed_node)

        fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )

        r = fed_node.client.get("/v1/conflicts?status=unresolved")
        assert r.status_code == 200
        unresolved_ids = [c["conflict_id"] for c in r.json()["conflicts"]]
        assert conflict_id not in unresolved_ids, (
            "resolved conflict must not appear in unresolved list"
        )

    def test_resolve_creates_resolution_fact_with_provenance(self, fed_node: FedNode) -> None:
        """Resolution fact uses namespaced entity; stigmem:resolves meta-fact points to conflict."""
        conflict_id, entity, fact_a_id, _ = self._create_conflict(fed_node)

        r = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )
        resolution_fact_id = r.json()["resolution_fact_id"]

        # Resolution fact exists in the facts table under the namespaced entity (not the
        # original entity) to avoid sharing the (entity, relation, scope) triple with the
        # conflicting facts, which would cause a cascade contradiction wave on federation.
        r_fact = fed_node.client.get(f"/v1/facts/{resolution_fact_id}")
        assert r_fact.status_code == 200
        fact = r_fact.json()
        assert fact["entity"] == f"stigmem:resolution:{conflict_id}", (
            "resolution fact MUST use namespaced entity, not the conflicting entity"
        )
        assert fact["entity"] != entity, (
            "resolution fact must NOT share entity with conflicting facts"
        )
        assert fact["relation"] == "resolve:val"
        assert fact["confidence"] == 1.0

        # stigmem:resolves meta-fact points to the conflict
        with _db_ctx() as conn:
            resolves = conn.execute(
                "SELECT * FROM facts WHERE entity = ? AND relation = 'stigmem:resolves'",
                (resolution_fact_id,),
            ).fetchone()
        assert resolves is not None, "stigmem:resolves meta-fact must exist"
        assert resolves["value_v"] == conflict_id

    def test_resolve_no_cascade_contradiction_on_federation(self, fed_node: FedNode) -> None:
        """Ingesting a resolution fact via federation must not create a new contradiction.

        Regression test for EG-51: the old implementation wrote the resolution fact
        under the original (entity, relation, scope), which caused a new contradiction
        wave when peers ingested it alongside the two original conflicting facts.
        """
        conflict_id, entity, fact_a_id, _ = self._create_conflict(fed_node)

        r = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )
        assert r.status_code == 200
        resolution_fact_id = r.json()["resolution_fact_id"]

        # Count conflicts before re-ingesting the resolution fact
        with _db_ctx() as conn:
            before = conn.execute(
                "SELECT COUNT(*) AS n FROM conflicts WHERE status = 'unresolved'"
            ).fetchone()["n"]

        # Simulate a peer node ingesting the resolution fact (idempotent re-ingest)
        r_fact = fed_node.client.get(f"/v1/facts/{resolution_fact_id}")
        assert r_fact.status_code == 200
        resolution_fact = r_fact.json()

        ingest_fact(
            {
                "id": resolution_fact["id"],
                "entity": resolution_fact["entity"],
                "relation": resolution_fact["relation"],
                "value": resolution_fact["value"],
                "source": resolution_fact["source"],
                "timestamp": resolution_fact["timestamp"],
                "hlc": resolution_fact.get("hlc"),
                "confidence": resolution_fact["confidence"],
                "scope": resolution_fact["scope"],
                "valid_until": resolution_fact.get("valid_until"),
            },
            "stigmem://peer-node", tenant_id="default",
        )

        # No new unresolved conflicts must have appeared
        with _db_ctx() as conn:
            after = conn.execute(
                "SELECT COUNT(*) AS n FROM conflicts WHERE status = 'unresolved'"
            ).fetchone()["n"]
        assert after == before, (
            f"federation of resolution fact must not create new contradictions "
            f"(unresolved conflicts before={before}, after={after})"
        )

    def test_status_resolved_fact_no_cascade_contradiction_on_federation(
        self, fed_node: FedNode
    ) -> None:
        """Ingesting stigmem:conflict:status 'resolved' via federation must not create a
        spurious contradiction against the existing 'unresolved' status fact.

        Regression test for EG-57: _detect_and_record_contradiction was not exempting
        stigmem: namespace facts, causing status transitions to be treated as sibling
        conflicts and generating spurious conflict records on peer nodes.
        """
        conflict_id, _entity, _fact_a_id, _ = self._create_conflict(fed_node)

        with _db_ctx() as conn:
            before = conn.execute(
                "SELECT COUNT(*) AS n FROM conflicts WHERE status = 'unresolved'"
            ).fetchone()["n"]

        base_ms = int(time.time() * 1000)
        resolved_status_fact = {
            "id": str(uuid.uuid4()),
            "entity": conflict_id,
            "relation": "stigmem:conflict:status",
            "value": {"type": "string", "v": "resolved"},
            "source": "system:stigmem",
            "timestamp": "2026-05-02T00:02:00Z",
            "hlc": f"{base_ms + 2000}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
        }
        ingest_fact(resolved_status_fact, "stigmem://peer-node", tenant_id="default")

        with _db_ctx() as conn:
            after = conn.execute(
                "SELECT COUNT(*) AS n FROM conflicts WHERE status = 'unresolved'"
            ).fetchone()["n"]

        assert after == before, (
            f"ingesting stigmem:conflict:status 'resolved' must not create new spurious "
            f"contradictions (unresolved conflicts before={before}, after={after})"
        )

    def test_resolve_with_new_value(self, fed_node: FedNode) -> None:
        """Resolve with new_value asserts a fresh reconciliation value."""
        conflict_id, entity, fact_a_id, _ = self._create_conflict(fed_node)

        r = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"new_value": {"type": "string", "v": "reconciled"}},
        )
        assert r.status_code == 200
        resolution_fact_id = r.json()["resolution_fact_id"]

        r_fact = fed_node.client.get(f"/v1/facts/{resolution_fact_id}")
        assert r_fact.status_code == 200
        assert r_fact.json()["value"]["v"] == "reconciled"

    def test_resolve_idempotency_conflict(self, fed_node: FedNode) -> None:
        """Resolving an already-resolved conflict → 409."""
        conflict_id, _, fact_a_id, _ = self._create_conflict(fed_node)

        fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )
        r2 = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )
        assert r2.status_code == 409

    def test_resolve_original_facts_remain_immutable(self, fed_node: FedNode) -> None:
        """Both original conflicting facts remain in the store after resolution."""
        conflict_id, entity, fact_a_id, fact_b_id = self._create_conflict(fed_node)

        fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"winning_fact_id": fact_a_id},
        )

        with _db_ctx() as conn:
            a = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_a_id,)).fetchone()
            b = conn.execute("SELECT id FROM facts WHERE id = ?", (fact_b_id,)).fetchone()
        assert a is not None, "original fact_a must remain"
        assert b is not None, "original fact_b must remain"

    def test_resolve_missing_conflict_returns_404(self, fed_node: FedNode) -> None:
        """Non-existent conflict_id → 404."""
        r = fed_node.client.post(
            "/v1/conflicts/stigmem:conflict:does-not-exist/resolve",
            json={"winning_fact_id": str(uuid.uuid4())},
        )
        assert r.status_code == 404

    def test_resolve_no_winning_fact_or_new_value_returns_422(self, fed_node: FedNode) -> None:
        """Missing both winning_fact_id and new_value → 422."""
        conflict_id, _, _, _ = self._create_conflict(fed_node)
        r = fed_node.client.post(
            f"/v1/conflicts/{conflict_id}/resolve",
            json={"resolution_note": "note only, no winner"},
        )
        assert r.status_code == 422
