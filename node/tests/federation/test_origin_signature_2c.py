"""Phase 2c W3.1 — entity_uri + tuple-version (tv="2.1") bound into the signed origin tuple.

The v2.1 canonical tuple is a HARD CUTOVER: ``entity_uri`` is mandatory and ``tv`` is a
hardcoded in-body constant committing the signature to its field set. There is NO
backward-compatible 6-field verify path — an origin block missing ``entity_uri`` is
REJECTED, never verified under the legacy 2b tuple (anti-downgrade: a 6-field fallback
would let a relay strip ``entity_uri`` and defeat the origin->entity binding).
"""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from stigmem_node.federation.origin_signature import (
    OriginSignatureError,
    canonical_origin_tuple,
    sign_origin,
    verify_origin_signature,
)

_CID = "sha256:" + "a" * 64
_FID = "11111111-1111-1111-1111-111111111111"
_ENTITY_URI = "https://origin.example"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return priv, pub_b64


def _origin_block(
    node_id: str = "stigmem:node:o1",
    tenant: str = "acme",
    entity_uri: str = _ENTITY_URI,
) -> dict:
    return {
        "tenant": tenant,
        "node_id": node_id,
        "allowed_scopes": ["public"],
        "allowed_tenants": [tenant],
        "entity_uri": entity_uri,
    }


def test_canonical_tuple_includes_entity_uri_and_tv() -> None:
    """The JCS bytes must carry both ``entity_uri`` and the hardcoded ``tv`` "2.1"."""
    body = canonical_origin_tuple(
        fact_id=_FID,
        cid=_CID,
        origin_tenant="t",
        origin_node_id="n",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["a"],
        valid_until=None,
        entity_uri=_ENTITY_URI,
    )
    assert b'"entity_uri":"https://origin.example"' in body
    assert b'"tv":"2.1"' in body


def test_sign_and_verify_roundtrip_with_entity_uri() -> None:
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(
        priv, fact_id=_FID, cid=_CID, origin=origin, valid_until="2027-01-01T00:00:00Z"
    )
    verify_origin_signature(
        sig,
        fact_id=_FID,
        cid=_CID,
        origin=origin,
        valid_until="2027-01-01T00:00:00Z",
        allowed_pubkeys={pub},
    )


def test_verify_rejects_missing_entity_uri() -> None:
    """ANTI-DOWNGRADE: an origin block with no entity_uri key is REJECTED outright —
    it must NOT fall back to a legacy 6-field tuple."""
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    legacy = {k: v for k, v in origin.items() if k != "entity_uri"}
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            sig, fact_id=_FID, cid=_CID, origin=legacy, valid_until=None, allowed_pubkeys={pub}
        )


def test_verify_rejects_empty_entity_uri() -> None:
    """ANTI-DOWNGRADE: an empty entity_uri is treated as absent → rejected."""
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            sig,
            fact_id=_FID,
            cid=_CID,
            origin=dict(origin, entity_uri=""),
            valid_until=None,
            allowed_pubkeys={pub},
        )


def test_sign_rejects_missing_entity_uri() -> None:
    """A v2.1 signature cannot be produced without an entity_uri (mandatory field)."""
    priv, _ = _keypair()
    origin = {k: v for k, v in _origin_block().items() if k != "entity_uri"}
    with pytest.raises(OriginSignatureError):
        sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)


def test_verify_rejects_tampered_entity_uri() -> None:
    """A relay that lies about the origin's entity_uri fails verification."""
    priv, pub = _keypair()
    origin = _origin_block()
    sig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=origin, valid_until=None)
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            sig,
            fact_id=_FID,
            cid=_CID,
            origin=dict(origin, entity_uri="https://attacker.example"),
            valid_until=None,
            allowed_pubkeys={pub},
        )
