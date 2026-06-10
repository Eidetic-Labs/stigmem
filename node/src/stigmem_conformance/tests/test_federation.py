"""Conformance: federation basics — peer registration and pull endpoint.

This module tests single-node federation groundwork: registering a peer,
verifying the well-known endpoint advertises federation capability, and that
the pull endpoint is available.

Multi-node federation (split-brain, 4-node scenarios) belongs in the
integration test suite (node/tests/test_4node_federation.py) rather than the
per-backend conformance suite.
"""

from __future__ import annotations

from .conftest import ConformanceClient


class TestWellKnown:
    def test_wellknown_returns_200(self, conformance_client: ConformanceClient) -> None:
        r = conformance_client.client.get("/.well-known/stigmem")
        assert r.status_code == 200

    def test_wellknown_has_required_fields(self, conformance_client: ConformanceClient) -> None:
        body = conformance_client.client.get("/.well-known/stigmem").json()
        # Spec §5.3: required fields
        for field in ("version", "node_id", "node_url", "auth", "federation"):
            assert field in body, f"Missing required well-known field: {field}"

    def test_wellknown_version_is_string(self, conformance_client: ConformanceClient) -> None:
        body = conformance_client.client.get("/.well-known/stigmem").json()
        assert isinstance(body["version"], str) and body["version"]


class TestFederationPeerRegistration:
    def test_peers_endpoint_exists(self, conformance_client: ConformanceClient) -> None:
        r = conformance_client.client.get("/v1/federation/peers")
        assert r.status_code in (200, 403)  # 403 if auth required in strict mode

    def test_register_peer_requires_fields(self, conformance_client: ConformanceClient) -> None:
        r = conformance_client.client.post("/v1/federation/peers", json={})
        # Empty payload should be rejected
        assert r.status_code in (400, 422)

    def test_pull_endpoint_exists(self, conformance_client: ConformanceClient) -> None:
        # Spec §5.22: federation pull endpoint is GET /v1/federation/facts
        r = conformance_client.client.get("/v1/federation/facts")
        assert r.status_code in (200, 400, 401, 403)  # 401/403 if auth required

    def test_pull_returns_facts_array(self, conformance_client: ConformanceClient) -> None:
        r = conformance_client.client.get("/v1/federation/facts")
        if r.status_code == 200:
            body = r.json()
            assert "facts" in body or isinstance(body, list)
            if isinstance(body, dict):
                # F-FED-2b clean break: the pull endpoint serves the v2 signed-origin
                # envelope only. Pin the wire version and, when facts are present, the
                # per-entry shape (fact + signed origin block + origin_sig).
                assert body.get("v") == 2
                for entry in body.get("facts", []):
                    for key in ("fact", "origin", "origin_sig"):
                        assert key in entry, f"v2 pull entry missing {key!r}"
                    origin = entry["origin"]
                    for key in ("tenant", "node_id", "allowed_scopes", "allowed_tenants"):
                        assert key in origin, f"v2 origin block missing {key!r}"


class TestFederationConflictAPI:
    def test_conflicts_list_exists(self, conformance_client: ConformanceClient) -> None:
        r = conformance_client.client.get("/v1/conflicts")
        assert r.status_code in (200, 403)

    def test_empty_conflicts_returns_empty_list(
        self, conformance_client: ConformanceClient
    ) -> None:
        r = conformance_client.client.get("/v1/conflicts")
        if r.status_code == 200:
            body = r.json()
            items = body.get("conflicts", body) if isinstance(body, dict) else body
            assert isinstance(items, list)
