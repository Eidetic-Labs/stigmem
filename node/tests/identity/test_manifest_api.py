from __future__ import annotations

from fastapi.testclient import TestClient

from stigmem_node.identity.manifest import manifest_to_dict

from .helpers import fed_keypair, make_manifest


def test_manifest_resolve_roundtrip(identity_client: TestClient):
    priv, pub_b64, _ = fed_keypair()
    entity_uri = "https://resolve-test.org"
    m = make_manifest(priv, pub_b64, entity_uri=entity_uri)

    resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    assert resp.status_code == 200

    from urllib.parse import quote

    encoded = quote(entity_uri, safe="")
    resp = identity_client.get(f"/v1/federation/manifest/{encoded}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["entity_uri"] == entity_uri
    assert data["key_id"] == m.key_id


def test_manifest_resolve_unknown_returns_404(identity_client: TestClient):
    from urllib.parse import quote

    encoded = quote("https://unknown-entity.org", safe="")
    resp = identity_client.get(f"/v1/federation/manifest/{encoded}")
    assert resp.status_code == 404


# ===========================================================================
# 11. Manifest rate-limit
# ===========================================================================


def test_manifest_put_rate_limit(identity_client: TestClient):
    """More than 10 manifest PUTs per entity_uri per hour must be rejected with 429."""
    import stigmem_node.routes.identity as identity_mod

    priv, pub_b64, _ = fed_keypair()
    entity_uri = "https://rate-limit-test.org"

    # Clear any prior state for this entity
    identity_mod._manifest_submit_log.pop(entity_uri, None)

    for i in range(10):
        m = make_manifest(priv, pub_b64, entity_uri=entity_uri)
        resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
        assert resp.status_code == 200, f"request {i} failed: {resp.text}"

    # 11th request must be rate-limited
    m = make_manifest(priv, pub_b64, entity_uri=entity_uri)
    resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    assert resp.status_code == 429, resp.text

    # Cleanup
    identity_mod._manifest_submit_log.pop(entity_uri, None)


# ===========================================================================
# 12. Quarantine ingest writes fact_audit_log entry (ACM-198)
# ===========================================================================
