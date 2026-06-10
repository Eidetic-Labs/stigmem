from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from conftest import FedNode, make_peer_token

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation_ingest import ingest_fact
from stigmem_node.hlc import node_hlc

from .helpers import generate_ed25519_b64, insert_active_peer, make_federated_fact

logger = logging.getLogger(__name__)


class TestPullEndpoint:
    def test_no_token_returns_401(self, fed_node: FedNode) -> None:
        r = fed_node.client.get("/v1/federation/facts")
        assert r.status_code == 401

    def test_valid_token_returns_200(self, fed_node: FedNode) -> None:
        node_b_pub, node_b_priv = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-{uuid.uuid4()}"
        insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b", node_b_pub)

        token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
        r = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert "facts" in body
        assert "cursor" in body
        assert "has_more" in body

    def test_scope_violation_returns_403_and_audit(self, fed_node: FedNode) -> None:
        """§11.2 / §6.4: requesting a scope not in peer declaration → 403 + audit entry."""
        node_b_pub, node_b_priv = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-scope-{uuid.uuid4()}"
        # Peer registered with only ["public"] in allowed_scopes
        insert_active_peer(
            fed_node.db_path,
            node_b_id,
            "http://testnode-b-scope",
            node_b_pub,
            allowed_scopes=["public"],
        )
        # Token claims company scope (intersection with ["public"] excludes company)
        token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["company", "public"])
        r = fed_node.client.get(
            "/v1/federation/facts?scope=company",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 403
        # Audit entry for scope_violation must be written
        with _db_ctx() as conn:
            entry = conn.execute(
                "SELECT * FROM federation_audit WHERE event_type='scope_violation' LIMIT 1"
            ).fetchone()
        assert entry is not None

    def test_facts_returned_in_hlc_order(self, fed_node: FedNode) -> None:
        """Pull endpoint returns facts ordered by HLC ASC, filterable by scope."""
        node_b_pub, node_b_priv = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-order-{uuid.uuid4()}"
        insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b-order", node_b_pub)

        # Ingest 5 facts into node A from node B (simulates prior pull)
        sender = "stigmem://node-b-order"
        facts = [make_federated_fact(entity=f"order:e{i}", hlc_offset_ms=i * 10) for i in range(5)]
        for f in facts:
            ingest_fact(f, sender, tenant_id="default")

        token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
        r = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        # The facts endpoint returns locally-stored public facts with HLC
        returned = r.json()["facts"]
        hlcs = [f["hlc"] for f in returned if f.get("hlc")]
        assert hlcs == sorted(hlcs)

    def test_non_default_tenant_facts_not_returned_from_node_level_pull(
        self,
        fed_node: FedNode,
    ) -> None:
        """Node-level federation pull only exports default-tenant facts."""
        default_resp = fed_node.client.post(
            "/v1/facts",
            json={
                "entity": f"fed:default:{uuid.uuid4()}",
                "relation": "test:value",
                "value": {"type": "string", "v": "default-visible"},
                "source": "agent:test",
                "scope": "public",
            },
        )
        assert default_resp.status_code == 201
        default_id = default_resp.json()["id"]
        non_default_id = str(uuid.uuid4())

        with _db_ctx() as conn:
            conn.execute(
                """INSERT INTO facts
                   (id, entity, relation, value_type, value_v, source, timestamp,
                    confidence, scope, hlc, tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    non_default_id,
                    f"fed:tenant-a:{uuid.uuid4()}",
                    "test:value",
                    "string",
                    "tenant-hidden",
                    "agent:test",
                    datetime.now(UTC).isoformat(),
                    1.0,
                    "public",
                    node_hlc.tick(),
                    "tenant-a",
                ),
            )

        node_b_pub, node_b_priv = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-tenant-filter-{uuid.uuid4()}"
        insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b-tenant", node_b_pub)

        token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
        r = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert r.status_code == 200
        returned_ids = {fact["id"] for fact in r.json()["facts"]}
        assert default_id in returned_ids
        assert non_default_id not in returned_ids


# ---------------------------------------------------------------------------
# §11.4 — Replay Attack acceptance scenario
# ---------------------------------------------------------------------------


class TestReplayProtection:
    """Full acceptance gate for spec §11.4."""

    def _register_peer_b(self, fed_node: FedNode) -> tuple[str, str, str]:
        """Register a fresh node-B keypair as active peer with node A.
        Returns (node_b_id, pub_b64, priv_b64).
        """
        pub_b64, priv_b64 = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-replay-{uuid.uuid4()}"
        insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b-r", pub_b64)
        return node_b_id, pub_b64, priv_b64

    def test_step1_first_use_succeeds(self, fed_node: FedNode) -> None:
        """§11.4 step 1: Valid token used once → 200."""
        node_b_id, _, priv = self._register_peer_b(fed_node)
        token = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"])
        r = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_step2_immediate_replay_rejected(self, fed_node: FedNode) -> None:
        """§11.4 step 2: Same token replayed immediately → 401 nonce_already_seen."""
        node_b_id, _, priv = self._register_peer_b(fed_node)
        token = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"])

        r1 = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r1.status_code == 200

        r2 = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 401
        assert r2.json().get("detail") == "nonce_already_seen"

    def test_step3_same_nonce_fresh_token_rejected(self, fed_node: FedNode) -> None:
        """§11.4 step 3: New token with same nonce as used token → 401 nonce_already_seen."""
        node_b_id, _, priv = self._register_peer_b(fed_node)
        shared_nonce = str(uuid.uuid4())

        token1 = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"], nonce=shared_nonce)
        token2 = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"], nonce=shared_nonce)

        r1 = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert r1.status_code == 200

        # token2 is freshly signed but shares the same nonce
        r2 = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert r2.status_code == 401
        assert r2.json().get("detail") == "nonce_already_seen"

    def test_step4_expired_token_rejected(self, fed_node: FedNode) -> None:
        """§11.4 step 4: Token with exp in the past → 401 token_expired."""
        node_b_id, _, priv = self._register_peer_b(fed_node)
        # iat = 2 hours ago, ttl = 1ms → exp ≈ 2 hours ago
        token = make_peer_token(
            priv,
            node_b_id,
            fed_node.node_id,
            ["public"],
            ttl_ms=1,
            offset_ms=-7_200_000,
        )
        r = fed_node.client.get(
            "/v1/federation/facts",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401
        assert r.json().get("detail") == "token_expired"

    def test_replay_audit_entries_written(self, fed_node: FedNode) -> None:
        """Replay attempt is recorded in federation_audit."""
        node_b_id, _, priv = self._register_peer_b(fed_node)
        token = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"])

        fed_node.client.get("/v1/federation/facts", headers={"Authorization": f"Bearer {token}"})
        fed_node.client.get("/v1/federation/facts", headers={"Authorization": f"Bearer {token}"})

        with _db_ctx() as conn:
            entry = conn.execute(
                "SELECT * FROM federation_audit WHERE event_type='replay_attempt' LIMIT 1"
            ).fetchone()
        assert entry is not None


# ---------------------------------------------------------------------------
# §11.3 — Partial Failure acceptance scenario
# ---------------------------------------------------------------------------


class TestFederationFactsPagination:
    def test_cursor_pagination(self, fed_node: FedNode) -> None:
        """Cursor from first page fetches next page, no duplicates."""
        # Create local public facts via the API so they are served by the pull endpoint.
        # (Federated inbound facts have received_from set and are not re-exported per §3.1.)
        for i in range(10):
            fed_node.client.post(
                "/v1/facts",
                json={
                    "entity": f"page:e{i}-{uuid.uuid4()}",
                    "relation": "test:value",
                    "value": {"type": "string", "v": f"v{i}"},
                    "source": "agent:test",
                    "confidence": 1.0,
                    "scope": "public",
                },
            )

        node_b_pub, node_b_priv = generate_ed25519_b64()
        node_b_id = f"stigmem://test-b-page-{uuid.uuid4()}"
        insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b-page", node_b_pub)

        token1 = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
        r1 = fed_node.client.get(
            "/v1/federation/facts?limit=5",
            headers={"Authorization": f"Bearer {token1}"},
        )
        assert r1.status_code == 200
        page1 = r1.json()
        assert len(page1["facts"]) == 5
        assert page1["has_more"] is True
        cursor = page1["cursor"]
        assert cursor is not None

        token2 = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
        r2 = fed_node.client.get(
            f"/v1/federation/facts?limit=5&cursor={cursor}",
            headers={"Authorization": f"Bearer {token2}"},
        )
        assert r2.status_code == 200
        page2 = r2.json()
        assert len(page2["facts"]) == 5

        # No overlap between pages
        ids1 = {f["id"] for f in page1["facts"]}
        ids2 = {f["id"] for f in page2["facts"]}
        assert ids1.isdisjoint(ids2), "Overlapping fact IDs between pages"


# ---------------------------------------------------------------------------
# Peer registration signature verification (spec §5.6, §6.1)
# ---------------------------------------------------------------------------
