"""Integration tests for graph adjacency index + neighbors() — spec §20 (Phase 9).

Backend-parameterised: run with --backend=sqlite (default) or --backend=libsql.
"""

from __future__ import annotations

import sqlite3
import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stigmem_node.plugins import PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins

# ---------------------------------------------------------------------------
# Test entity URIs
# ---------------------------------------------------------------------------

_ALICE = "stigmem://testnode/agent/alice"
_BOB = "stigmem://testnode/agent/bob"
_CAROL = "stigmem://testnode/agent/carol"
_DAVE = "stigmem://testnode/agent/dave"
_MEMORY_GARDEN_ACL_SRC = (
    Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl" / "src"
)


def _memory_garden_acl_manifest() -> PluginManifest:
    if str(_MEMORY_GARDEN_ACL_SRC) not in sys.path:
        sys.path.insert(0, str(_MEMORY_GARDEN_ACL_SRC))
    import importlib

    plugin = importlib.import_module("stigmem_plugin_memory_garden_acl")
    return plugin.plugin_manifest()


def _enable_acl_recall_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STIGMEM_MEMORY_GARDEN_ACL_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_MEMORY_GARDEN_ACL_APPLY_RECALL_FILTER", "true")


def _ref_fact(
    entity: str,
    relation: str,
    target: str,
    scope: str = "local",
    confidence: float = 1.0,
    valid_until: str | None = None,
) -> dict:
    payload: dict = {
        "entity": entity,
        "relation": relation,
        "value": {"type": "ref", "v": target},
        "source": entity,
        "confidence": confidence,
        "scope": scope,
    }
    if valid_until is not None:
        payload["valid_until"] = valid_until
    return payload


# ---------------------------------------------------------------------------
# Core traversal tests
# ---------------------------------------------------------------------------


class TestGraphNeighbors:
    def test_depth1_returns_direct_neighbor(self, client: TestClient) -> None:
        r = client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        assert r.status_code == 201

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        body = r.json()
        assert body["entity"] == _ALICE
        entities = [n["entity"] for n in body["neighbors"]]
        assert _BOB in entities

    def test_depth1_hops_field(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        bob_entry = next(n for n in r.json()["neighbors"] if n["entity"] == _BOB)
        assert bob_entry["hops"] == 1
        assert bob_entry["path"] == [_ALICE]

    def test_depth2_traversal(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_BOB, "memory:knows", _CAROL))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=2&scope=local")
        assert r.status_code == 200
        body = r.json()
        entities = [n["entity"] for n in body["neighbors"]]
        assert _BOB in entities
        assert _CAROL in entities

        carol_entry = next(n for n in body["neighbors"] if n["entity"] == _CAROL)
        assert carol_entry["hops"] == 2
        assert _ALICE in carol_entry["path"]
        assert _BOB in carol_entry["path"]

    def test_depth3_traversal(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_BOB, "memory:knows", _CAROL))
        client.post("/v1/facts", json=_ref_fact(_CAROL, "memory:knows", _DAVE))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=3&scope=local")
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _DAVE in entities

    def test_depth_exceeds_cap_returns_400(self, client: TestClient) -> None:
        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=4&scope=local")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert "graph_depth_exceeded" in str(detail)

    def test_scope_required_missing_returns_422(self, client: TestClient) -> None:
        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1")
        assert r.status_code == 422

    def test_no_neighbors_returns_empty_list(self, client: TestClient) -> None:
        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        assert r.json()["neighbors"] == []

    def test_non_ref_fact_not_indexed(self, client: TestClient) -> None:
        client.post(
            "/v1/facts",
            json={
                "entity": _ALICE,
                "relation": "memory:name",
                "value": {"type": "string", "v": "Alice"},
                "source": _ALICE,
                "confidence": 1.0,
                "scope": "local",
            },
        )
        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        assert r.json()["neighbors"] == []

    def test_reverse_edge_traversal(self, client: TestClient) -> None:
        # BOB → ALICE; querying from ALICE should still find BOB (reverse traversal)
        client.post("/v1/facts", json=_ref_fact(_BOB, "memory:knows", _ALICE))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities

    def test_scope_isolation(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, scope="local"))
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _CAROL, scope="company"))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities
        assert _CAROL not in entities

    def test_relation_filter_prefix_glob(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_ALICE, "org:member", _CAROL))

        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&relation_filter=memory:*"
        )
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities
        assert _CAROL not in entities

    def test_relation_filter_exact_match(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:likes", _CAROL))

        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&relation_filter=memory:knows"
        )
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities
        assert _CAROL not in entities

    def test_confidence_pruning(self, client: TestClient) -> None:
        # Edge below min_confidence should not appear
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, confidence=0.05))

        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&min_confidence=0.1"
        )
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB not in entities

    def test_high_confidence_passes_filter(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, confidence=0.9))

        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&min_confidence=0.1"
        )
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities

    def test_deduplication_shortest_path(self, client: TestClient) -> None:
        # ALICE→BOB and ALICE→CAROL→BOB: BOB should appear once at hops=1
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _CAROL))
        client.post("/v1/facts", json=_ref_fact(_CAROL, "memory:knows", _BOB))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=2&scope=local")
        assert r.status_code == 200
        bob_entries = [n for n in r.json()["neighbors"] if n["entity"] == _BOB]
        assert len(bob_entries) == 1
        assert bob_entries[0]["hops"] == 1

    def test_total_hint_field(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _CAROL))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        assert r.json()["total_hint"] >= 2

    def test_confidence_returned_in_response(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, confidence=0.75))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        bob_entry = next(n for n in r.json()["neighbors"] if n["entity"] == _BOB)
        assert abs(bob_entry["confidence"] - 0.75) < 0.01


# ---------------------------------------------------------------------------
# Pagination tests
# ---------------------------------------------------------------------------


class TestGraphPagination:
    def test_pagination_first_page(self, client: TestClient) -> None:
        targets = [f"stigmem://testnode/entity/t{i:03d}" for i in range(25)]
        for t in targets:
            client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:relates", t))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&page_size=10")
        assert r.status_code == 200
        body = r.json()
        assert len(body["neighbors"]) == 10
        assert body["next_cursor"] is not None

    def test_pagination_second_page(self, client: TestClient) -> None:
        targets = [f"stigmem://testnode/entity/t{i:03d}" for i in range(25)]
        for t in targets:
            client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:relates", t))

        r1 = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&page_size=10")
        cursor = r1.json()["next_cursor"]

        r2 = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&page_size=10&cursor={cursor}"
        )
        assert r2.status_code == 200
        assert len(r2.json()["neighbors"]) > 0
        # Pages should not overlap
        first_set = {n["entity"] for n in r1.json()["neighbors"]}
        second_set = {n["entity"] for n in r2.json()["neighbors"]}
        assert first_set.isdisjoint(second_set)

    def test_last_page_has_no_cursor(self, client: TestClient) -> None:
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&page_size=100")
        assert r.status_code == 200
        assert r.json()["next_cursor"] is None

    def test_invalid_cursor_returns_400(self, client: TestClient) -> None:
        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local&cursor=notavalidcursor"
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# Federation edge filtering
# ---------------------------------------------------------------------------


class TestGraphFederationFilter:
    def test_federated_edge_hidden_without_federate_perm(
        self,
        tmp_db: str,
        authed_client: tuple,
        backend: str,
    ) -> None:
        """Edges from federated sources must not be returned to callers without federate perm."""
        if backend == "libsql":
            pytest.skip("direct SQLite injection not available on libsql")

        client, raw_key = authed_client  # auth_required=True, key has read+write only

        # Inject a federated edge directly into entity_edges
        conn = sqlite3.connect(tmp_db)
        conn.row_factory = sqlite3.Row
        edge_id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)
        conn.execute(
            """INSERT INTO entity_edges
               (id, subject, relation, object, scope, garden_id, tenant_id,
                received_from, valid_until, confidence, source_trust, decay_epoch, created_at)
               VALUES (?,?,?,?,?,NULL,'default','stigmem://remote-node',NULL,1.0,NULL,NULL,?)""",
            (edge_id, _ALICE, "memory:knows", _BOB, "local", now_ms),
        )
        conn.commit()
        conn.close()

        r = client.get(
            f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB not in entities

    def test_federated_edge_visible_with_federate_perm(
        self,
        tmp_db: str,
        backend: str,
    ) -> None:
        """Edges from federated sources ARE returned when caller has federate permission."""
        if backend == "libsql":
            pytest.skip("direct SQLite injection not available on libsql")

        from conftest import _make_enc_settings, _patch_settings, _restore_settings

        import stigmem_node.settings as settings_module
        from stigmem_node.auth import create_api_key
        from stigmem_node.main import create_app

        # We need auth_required=True so we can supply a specific key
        original = settings_module.settings
        test_settings = _make_enc_settings(
            tmp_db, backend, "off", auth_required=True, node_url="http://testnode"
        )
        extra = _patch_settings(test_settings)

        fed_key = create_api_key("stigmem://testnode/agent/feeder", ["read", "write", "federate"])

        # Inject federated edge
        conn = sqlite3.connect(tmp_db)
        edge_id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)
        conn.execute(
            """INSERT INTO entity_edges
               (id, subject, relation, object, scope, garden_id, tenant_id,
                received_from, valid_until, confidence, source_trust, decay_epoch, created_at)
               VALUES (?,?,?,?,?,NULL,'default','stigmem://remote-node',NULL,1.0,NULL,NULL,?)""",
            (edge_id, _ALICE, "memory:knows", _BOB, "local", now_ms),
        )
        conn.commit()
        conn.close()

        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            r = c.get(
                f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local",
                headers={"Authorization": f"Bearer {fed_key}"},
            )
            assert r.status_code == 200
            entities = [n["entity"] for n in r.json()["neighbors"]]
            assert _BOB in entities

        _restore_settings(original, extra)


# ---------------------------------------------------------------------------
# Garden ACL
# ---------------------------------------------------------------------------


class TestGraphGardenACL:
    def test_garden_edge_hidden_from_non_member(
        self,
        tmp_db: str,
        authed_client: tuple,
        backend: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Garden edges are hidden from non-members by default (core recall filter)."""
        if backend == "libsql":
            pytest.skip("direct SQLite injection not available on libsql")

        client, raw_key = authed_client  # caller = stigmem://testnode/agent/test

        # Create a garden as the caller (who auto-becomes admin)
        r_g = client.post(
            "/v1/gardens",
            json={"slug": "private-g", "name": "Private", "scope": "local"},
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert r_g.status_code == 201
        garden_uuid = r_g.json()["id"]

        # Inject an edge tagged to the garden for a DIFFERENT entity (outsider POV)
        conn = sqlite3.connect(tmp_db)
        edge_id = str(uuid.uuid4())
        now_ms = int(time.time() * 1000)
        conn.execute(
            """INSERT INTO entity_edges
               (id, subject, relation, object, scope, garden_id, tenant_id,
                received_from, valid_until, confidence, source_trust, decay_epoch, created_at)
               VALUES (?,?,?,?,?,?,?,NULL,NULL,1.0,NULL,NULL,?)""",
            (edge_id, _ALICE, "memory:knows", _CAROL, "local", garden_uuid, "default", now_ms),
        )
        conn.commit()
        conn.close()

        from conftest import _make_enc_settings, _patch_settings, _restore_settings

        import stigmem_node.settings as settings_module
        from stigmem_node.auth import create_api_key
        from stigmem_node.main import create_app

        original = settings_module.settings
        test_settings = _make_enc_settings(
            tmp_db, backend, "off", auth_required=True, node_url="http://testnode"
        )
        extra = _patch_settings(test_settings)

        outsider_key = create_api_key("stigmem://testnode/agent/outsider", ["read"])
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            default_r = c.get(
                f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local",
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert default_r.status_code == 200
            default_entities = [n["entity"] for n in default_r.json()["neighbors"]]
            # Recall filtering is core/default-on: the garden edge is hidden even
            # without the plugin or env flags.
            assert _CAROL not in default_entities

            _enable_acl_recall_filter(monkeypatch)
            with stigmem_plugins([_memory_garden_acl_manifest()]):
                r = c.get(
                    f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local",
                    headers={"Authorization": f"Bearer {outsider_key}"},
                )
            assert r.status_code == 200
            entities = [n["entity"] for n in r.json()["neighbors"]]
            assert _CAROL not in entities

        _restore_settings(original, extra)


# ---------------------------------------------------------------------------
# Expiry / decay
# ---------------------------------------------------------------------------


class TestGraphExpiry:
    def test_expired_edge_hidden(self, client: TestClient) -> None:
        # Insert a fact that expires immediately
        past = "2000-01-01T00:00:00+00:00"
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, valid_until=past))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB not in entities

    def test_active_edge_visible(self, client: TestClient) -> None:
        # Future expiry — should be visible
        future = "2099-01-01T00:00:00+00:00"
        client.post("/v1/facts", json=_ref_fact(_ALICE, "memory:knows", _BOB, valid_until=future))

        r = client.get(f"/v1/graph/neighbors?entity={_ALICE}&depth=1&scope=local")
        assert r.status_code == 200
        entities = [n["entity"] for n in r.json()["neighbors"]]
        assert _BOB in entities
