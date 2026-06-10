"""Phase 2a — GET /.well-known/stigmem-manifest.json serves the node's own manifest.

This is the path peers fetch at approval time (``_check_tl_inclusion_for_peer``) to
retrieve+verify+store the peer's published OrgManifest. Before this endpoint existed,
no node served the path, so the approval-time fetch 404'd and entity_uri never bound.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from stigmem_node.identity.manifest import manifest_from_dict, manifest_to_dict

from .helpers import fed_keypair, make_manifest


def test_well_known_manifest_returns_published_manifest(identity_client: TestClient) -> None:
    """Publish the node's own manifest via the federation key, then GET the well-known path."""
    priv, pub_b64, _ = fed_keypair()
    # The node's own entity_uri == settings.node_url for the identity_client fixture.
    entity_uri = "http://testnode"
    m = make_manifest(priv, pub_b64, entity_uri=entity_uri, entities=[entity_uri])

    put = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    assert put.status_code == 200, put.text

    resp = identity_client.get("/.well-known/stigmem-manifest.json")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Body round-trips through manifest_from_dict (so a peer can verify+store it).
    round_tripped = manifest_from_dict(body)
    assert round_tripped.entity_uri == entity_uri
    assert round_tripped.public_key == pub_b64
    assert round_tripped.key_id == m.key_id


def test_well_known_manifest_404_when_unpublished(identity_client: TestClient) -> None:
    """No manifest published for the node's entity_uri yet → 404."""
    resp = identity_client.get("/.well-known/stigmem-manifest.json")
    assert resp.status_code == 404
