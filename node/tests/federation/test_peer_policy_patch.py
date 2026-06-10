"""Tests for the per-peer tenant-policy management surface.

Covers ``PATCH /v1/federation/peers/{id}`` (operator-set tenant policy) and the
policy fields surfaced by ``GET /v1/federation/peers`` (migration 041).
"""

from __future__ import annotations

import uuid

from conftest import FedNode

from stigmem_node.auth import create_api_key
from stigmem_node.db import db as _db_ctx

from .helpers import generate_ed25519_b64, insert_active_peer


def _seed_peer(fed_node: FedNode) -> str:
    pub_b64, _ = generate_ed25519_b64()
    return insert_active_peer(
        fed_node.db_path,
        node_id=f"stigmem://peer-policy-{uuid.uuid4()}",
        node_url="http://peer-policy",
        pub_b64=pub_b64,
    )


def _admin_key() -> str:
    return create_api_key("agent:federation-admin", ["admin:federation", "federate"])


class TestPeerPolicyPatch:
    def test_admin_patch_sets_policy_and_surfaces_in_list(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        admin_key = _admin_key()

        patch = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={
                "ingest_tenant": "tenant-a",
                "pull_tenant": "tenant-a",
                "trust_tier": "cross_org",
            },
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert patch.status_code == 200, patch.text
        body = patch.json()
        assert body["peer_id"] == peer_id
        assert set(body["updated"]) == {"ingest_tenant", "pull_tenant", "trust_tier"}

        listing = fed_node.client.get(
            "/v1/federation/peers",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert listing.status_code == 200, listing.text
        peers = {p["peer_id"]: p for p in listing.json()["peers"]}
        assert peer_id in peers
        row = peers[peer_id]
        assert row["ingest_tenant"] == "tenant-a"
        assert row["pull_tenant"] == "tenant-a"
        assert row["trust_tier"] == "cross_org"
        assert row["allowed_tenants"] == []

        # A security-relevant policy mutation must leave a federation_audit trail.
        with _db_ctx() as conn:
            audit = conn.execute(
                "SELECT * FROM federation_audit "
                "WHERE peer_id = ? AND event_type = 'peer_policy_updated'",
                (peer_id,),
            ).fetchone()
        assert audit is not None, "peer_policy_updated audit entry must be written"

    def test_admin_patch_allowed_tenants_list(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        admin_key = _admin_key()

        patch = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={"allowed_tenants": ["tenant-a", "tenant-b"]},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert patch.status_code == 200, patch.text

        listing = fed_node.client.get(
            "/v1/federation/peers",
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        peers = {p["peer_id"]: p for p in listing.json()["peers"]}
        assert peers[peer_id]["allowed_tenants"] == ["tenant-a", "tenant-b"]

    def test_bogus_trust_tier_rejected_422(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        admin_key = _admin_key()
        r = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={"trust_tier": "bogus"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 422, r.text

    def test_non_list_allowed_tenants_rejected_422(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        admin_key = _admin_key()
        r = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={"allowed_tenants": "not-a-list"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 422, r.text

    def test_non_admin_rejected_403(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        # fed_node.federate_key has read/write/federate but NOT admin:federation.
        r = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={"ingest_tenant": "tenant-a"},
            headers={"Authorization": f"Bearer {fed_node.federate_key}"},
        )
        assert r.status_code == 403, r.text

    def test_unknown_peer_404(self, fed_node: FedNode) -> None:
        admin_key = _admin_key()
        r = fed_node.client.patch(
            f"/v1/federation/peers/{uuid.uuid4()}",
            json={"ingest_tenant": "tenant-a"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 404, r.text

    def test_empty_body_400(self, fed_node: FedNode) -> None:
        peer_id = _seed_peer(fed_node)
        admin_key = _admin_key()
        r = fed_node.client.patch(
            f"/v1/federation/peers/{peer_id}",
            json={},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 400, r.text
