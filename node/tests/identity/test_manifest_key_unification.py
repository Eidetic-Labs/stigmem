"""Fed Phase 2a — manifest key-unification: PUT /v1/federation/manifest must reject
any manifest whose public_key diverges from this node's federation/peer-token key.

A node may only publish its OWN manifest, signed by its federation key. Accepting a
manifest that carries an independent key is the laundering precondition this check
closes (Task 3 of the identity-unification phase).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest


def test_put_manifest_rejects_foreign_public_key(identity_client: TestClient):
    """A manifest with a valid self-signature but a FOREIGN public_key (not the
    node's federation key) must be rejected with HTTP 422 mentioning the federation key.

    The manifest is self-signed by the foreign key so it passes verify_manifest — the
    route must reject it for key MISMATCH, not for a bad signature.
    """
    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    m = OrgManifest(
        entity_uri="https://evil.example",
        key_id=generate_key_id(priv.public_key()),
        public_key=pub_b64,
        issued_at="2026-06-01T00:00:00Z",
        expires_at="2027-06-01T00:00:00Z",
        entities=["https://evil.example"],
    )
    sign_manifest(m, priv)

    resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))

    assert resp.status_code == 422, resp.text
    assert "federation key" in resp.json()["detail"].lower()
