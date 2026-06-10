"""Unit tests for Migration 004 scope-propagation columns (spec §6.8).

Validates the three invariants introduced by 004_scope_propagation.sql:
  1. origin_node_id populated at ingest from sender node_id
  2. origin_allowed_scopes populated from peer registry, not payload
  3. re_federation_blocked=1 for company-scope facts, 0 for all others

These tests call ingest_fact() directly (same pattern as test_federation.py)
and verify column values in the sqlite DB. Docker not required.

CAP lens: re_federation_blocked is written atomically with the fact INSERT —
there is no window where a company fact can exist in the DB without the block.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any

from conftest import FedNode, generate_keypair, make_peer_token

from stigmem_node.federation_ingest import ingest_fact

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fact(
    entity: str | None = None,
    relation: str = "test:prop",
    value: str = "v",
    scope: str = "public",
) -> dict[str, Any]:
    base_ms = int(time.time() * 1000)
    sender_id = "stigmem://origin-node-for-source"
    return {
        "id": str(uuid.uuid4()),
        "entity": entity or f"test://scope-prop/{uuid.uuid4()}",
        "relation": relation,
        "value": {"type": "string", "v": value},
        "source": sender_id,
        "timestamp": "2026-05-02T00:00:00Z",
        "hlc": f"{base_ms}.000",
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }


def _db_fetch_fact(db_path: str, fact_id: str) -> sqlite3.Row | None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM facts WHERE id = ?", (fact_id,)).fetchone()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScopePropagationColumnsUnit:
    """Unit-level validation of Migration 004 columns via direct ingest_fact().

    Uses fed_node fixture (single-node with settings patched) so ingest_fact()
    writes to the isolated test DB. No Docker required.
    """

    def test_origin_node_id_populated_on_ingest(self, fed_node: FedNode) -> None:
        """Spec §6.8.1: origin_node_id must record the sender's node_id."""
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        fact = _make_fact(scope="public")
        # source must match sender_node_id for ingest to accept (non-forgery rule);
        # override source to match our sender
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=["public"], tenant_id="default")

        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None, "fact not found in DB after ingest"
        assert row["origin_node_id"] == sender_id, (
            f"origin_node_id should be {sender_id!r}, got {row['origin_node_id']!r}"
        )

    def test_origin_allowed_scopes_populated_from_peer_scopes(self, fed_node: FedNode) -> None:
        """Spec §6.8.1: origin_allowed_scopes comes from peer registry, not payload scope."""
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        declared_scopes = ["public", "internal"]
        fact = _make_fact(scope="public")
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=declared_scopes, tenant_id="default")

        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None
        assert row["origin_allowed_scopes"] is not None, (
            "origin_allowed_scopes must be non-null for federated facts"
        )
        stored = json.loads(row["origin_allowed_scopes"])
        assert set(stored) == set(declared_scopes), (
            f"expected {sorted(declared_scopes)}, got {sorted(stored)}"
        )

    def test_public_fact_re_federation_blocked_is_zero(self, fed_node: FedNode) -> None:
        """Spec §6.8.2: public-scope inbound facts must have re_federation_blocked=0."""
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        fact = _make_fact(scope="public")
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=["public"], tenant_id="default")

        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None
        assert row["re_federation_blocked"] == 0, (
            "public-scope fact MUST have re_federation_blocked=0 (spec §6.8.2)"
        )

    def test_company_fact_re_federation_blocked_is_one(self, fed_node: FedNode) -> None:
        """Spec §6.8.2: company-scope inbound facts must have re_federation_blocked=1.

        This is the key non-transitive grant invariant: a company-scope fact
        received from a peer must NEVER be re-relayed to a third node.
        The re_federation_blocked column is set atomically with the INSERT.
        """
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        fact = _make_fact(scope="company")
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=["public", "company"], tenant_id="default")

        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None
        assert row["re_federation_blocked"] == 1, (
            "company-scope inbound fact MUST have re_federation_blocked=1 (spec §6.8.2)"
        )

    def test_team_scope_not_blocked(self, fed_node: FedNode) -> None:
        """Team-scope facts (not company) must have re_federation_blocked=0.

        Only 'company' scope triggers the non-transitive grant block.
        Valid scopes are: local, team, company, public.
        """
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        fact = _make_fact(scope="team")
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=["public", "team"], tenant_id="default")

        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None
        assert row["re_federation_blocked"] == 0, (
            "team-scope fact MUST have re_federation_blocked=0 — "
            "only 'company' scope triggers the block (spec §6.8.2)"
        )

    def test_company_fact_excluded_from_pull_endpoint(self, fed_node: FedNode) -> None:
        """Spec §6.8.2: re_federation_blocked=1 facts MUST NOT appear in the pull response.

        Verifies the WHERE clause filter in routes/federation.py:
        a company-scope fact ingested from peer-A must not be served when
        peer-B calls GET /v1/federation/facts on this node.
        """
        sender_id = f"stigmem://sender-{uuid.uuid4()}"
        fact = _make_fact(scope="company")
        fact["source"] = sender_id

        ingest_fact(fact, sender_id, origin_allowed_scopes=["public", "company"], tenant_id="default")

        # Confirm re_federation_blocked=1 in DB
        row = _db_fetch_fact(fed_node.db_path, fact["id"])
        assert row is not None and row["re_federation_blocked"] == 1, (
            "precondition: company fact must be blocked in DB"
        )

        # Third node pulls — must not see the company fact
        pub_b64_third, priv_b64_third = generate_keypair()
        third_id = f"stigmem://third-node-{uuid.uuid4()}"

        # Register third node as an active peer
        conn = sqlite3.connect(fed_node.db_path)
        try:
            conn.execute(
                """INSERT INTO peers
                   (id, node_id, node_url, federation_pubkey, allowed_scopes,
                    status, established_at, declaration_sig, signed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    third_id,
                    "http://third-node",
                    pub_b64_third,
                    json.dumps(["public", "company"]),
                    "active",
                    "2026-05-02T00:00:00Z",
                    "dummy_sig",
                    "2026-05-02T00:00:00Z",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        pull_token = make_peer_token(
            priv_b64_third, third_id, fed_node.node_id, ["public", "company"]
        )
        pull_resp = fed_node.client.get(
            "/v1/federation/facts",
            params={"limit": 500},
            headers={"Authorization": f"Bearer {pull_token}"},
        )
        assert pull_resp.status_code == 200, f"pull failed: {pull_resp.text}"

        returned_ids = {f["id"] for f in pull_resp.json().get("facts", [])}
        assert fact["id"] not in returned_ids, (
            f"company fact {fact['id']} (re_federation_blocked=1) appeared in pull response — "
            "spec §6.8.2 violation: company-scope facts MUST NOT re-federate to third nodes"
        )

    def test_derived_fact_excluded_from_pull_endpoint(self, fed_node: FedNode) -> None:
        """R-21: facts derived from recalled/source facts must not replicate outbound."""
        source_resp = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": f"source:{uuid.uuid4()}",
                "relation": "memory:note",
                "value": {"type": "string", "v": "source"},
                "source": "agent:test-fed",
                "scope": "company",
            },
        )
        assert source_resp.status_code == 201, source_resp.text
        source_id = source_resp.json()["id"]

        derived_resp = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": f"summary:{uuid.uuid4()}",
                "relation": "memory:summary",
                "value": {"type": "text", "v": "derived summary"},
                "source": "agent:test-fed",
                "scope": "company",
                "write_mode": "summarize_with_provenance",
                "derived_from": [{"fact_id": source_id}],
            },
        )
        assert derived_resp.status_code == 201, derived_resp.text
        derived_id = derived_resp.json()["id"]

        pub_b64_third, priv_b64_third = generate_keypair()
        third_id = f"stigmem://third-node-{uuid.uuid4()}"

        conn = sqlite3.connect(fed_node.db_path)
        try:
            conn.execute(
                """INSERT INTO peers
                   (id, node_id, node_url, federation_pubkey, allowed_scopes,
                    status, established_at, declaration_sig, signed_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    third_id,
                    "http://third-node",
                    pub_b64_third,
                    json.dumps(["public", "company"]),
                    "active",
                    "2026-05-02T00:00:00Z",
                    "dummy_sig",
                    "2026-05-02T00:00:00Z",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        pull_token = make_peer_token(
            priv_b64_third, third_id, fed_node.node_id, ["public", "company"]
        )
        pull_resp = fed_node.client.get(
            "/v1/federation/facts",
            params={"limit": 500},
            headers={"Authorization": f"Bearer {pull_token}"},
        )
        assert pull_resp.status_code == 200, pull_resp.text

        returned_ids = {f["id"] for f in pull_resp.json().get("facts", [])}
        assert source_id in returned_ids
        assert derived_id not in returned_ids
