"""Phase 2c W6.3 — tombstone ORIGIN-ATTESTATION signature.

Distinct from the existing tombstone issuer-signer signature (lifecycle/tombstone_signing.py).
This signature binds WHO ORIGINATED a relayed tombstone + its propagation grant, so a relay
cannot launder or re-scope a suppression. It mirrors the FACT origin signature (W3.1) but for
tombstones, with a DISTINCT hardcoded tuple version ``tv = "t2.1"`` for domain separation: a
tombstone origin sig can never be confused with / replayed as a fact origin sig.

The tuple binds the tombstone's ``id``, ``entity_uri`` and ``scope`` — the anti-relaunder
property: a relay that widens ``scope`` (e.g. "local" -> "*") or changes ``entity_uri``
invalidates the signature.
"""

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from stigmem_node.federation.origin_signature import (
    OriginSignatureError,
    canonical_tombstone_origin_tuple,
    sign_origin,
    sign_tombstone_origin,
    verify_origin_signature,
    verify_tombstone_origin_signature,
)

_TID = "22222222-2222-2222-2222-222222222222"
_FID = "11111111-1111-1111-1111-111111111111"
_CID = "sha256:" + "a" * 64
_ENTITY_URI = "https://subject.example"
_ORIGIN_ENTITY_URI = "https://origin.example"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return priv, pub_b64


def _kwargs(
    *,
    tombstone_id: str = _TID,
    entity_uri: str = _ENTITY_URI,
    scope: str = "local",
    origin_node_id: str = "stigmem:node:o1",
    origin_tenant: str = "acme",
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
    origin_entity_uri: str = _ORIGIN_ENTITY_URI,
) -> dict[str, Any]:
    return {
        "tombstone_id": tombstone_id,
        "entity_uri": entity_uri,
        "scope": scope,
        "origin_node_id": origin_node_id,
        "origin_tenant": origin_tenant,
        "origin_allowed_scopes": ["local", "public"]
        if origin_allowed_scopes is None
        else origin_allowed_scopes,
        "origin_allowed_tenants": ["acme", "beta"]
        if origin_allowed_tenants is None
        else origin_allowed_tenants,
        "origin_entity_uri": origin_entity_uri,
    }


# (a) canonical tuple shape ---------------------------------------------------


def test_canonical_tombstone_tuple_is_jcs_with_tv_and_binds_id_entity_scope() -> None:
    body = canonical_tombstone_origin_tuple(
        tombstone_id=_TID,
        entity_uri=_ENTITY_URI,
        scope="local",
        origin_node_id="n",
        origin_tenant="t",
        origin_allowed_scopes=["public", "local"],
        origin_allowed_tenants=["beta", "acme"],
        origin_entity_uri=_ORIGIN_ENTITY_URI,
    )
    # DISTINCT version (NOT the fact tuple's "2.1").
    assert b'"tv":"t2.1"' in body
    # Binds the tombstone identity fields.
    assert b'"tid":"' + _TID.encode() in body
    assert b'"entity_uri":"https://subject.example"' in body
    assert b'"scope":"local"' in body
    # JCS: keys sorted; sets sorted lexicographically.
    assert body.index(b'"entity_uri"') < body.index(b'"origin_allowed_scopes"') < body.index(
        b'"tid"'
    ) < body.index(b'"tv"')
    assert b'"origin_allowed_scopes":["local","public"]' in body
    assert b'"origin_allowed_tenants":["acme","beta"]' in body


# (b) round-trip --------------------------------------------------------------


def test_sign_and_verify_roundtrip() -> None:
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv, **kw)
    verify_tombstone_origin_signature(sig, **kw, allowed_pubkeys={pub})


# (c) tamper any field --------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad",
    [
        ("tombstone_id", "99999999-9999-9999-9999-999999999999"),
        ("entity_uri", "https://attacker.example"),
        ("origin_node_id", "stigmem:node:evil"),
        ("origin_tenant", "evilco"),
        ("origin_entity_uri", "https://relay.example"),
    ],
)
def test_verify_rejects_tampered_scalar_field(field: str, bad: str) -> None:
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(sig, **{**kw, field: bad}, allowed_pubkeys={pub})


def test_verify_rejects_tampered_allowed_scope() -> None:
    priv, pub = _keypair()
    kw = _kwargs(origin_allowed_scopes=["local"])
    sig = sign_tombstone_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(
            sig, **{**kw, "origin_allowed_scopes": ["local", "public"]}, allowed_pubkeys={pub}
        )


def test_verify_rejects_scope_widening_relaunder() -> None:
    """ANTI-RELAUNDER: a relay that widens the suppression scope ("local" -> "*")
    invalidates the origin attestation."""
    priv, pub = _keypair()
    kw = _kwargs(scope="local")
    sig = sign_tombstone_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(sig, **{**kw, "scope": "*"}, allowed_pubkeys={pub})


# (d) anti-downgrade ----------------------------------------------------------


def test_sign_rejects_missing_origin_entity_uri() -> None:
    priv, _ = _keypair()
    kw = _kwargs(origin_entity_uri="")
    with pytest.raises(OriginSignatureError):
        sign_tombstone_origin(priv, **kw)


def test_verify_rejects_missing_origin_entity_uri() -> None:
    """ANTI-DOWNGRADE: an empty origin_entity_uri is rejected, never silently verified."""
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(
            sig, **{**kw, "origin_entity_uri": ""}, allowed_pubkeys={pub}
        )


def test_verify_rejects_missing_entity_uri() -> None:
    """The tombstone subject entity_uri is mandatory at verify time too."""
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(sig, **{**kw, "entity_uri": ""}, allowed_pubkeys={pub})


# (e) rotation window ---------------------------------------------------------


def test_verify_accepts_any_key_in_rotation_set() -> None:
    priv_a, pub_a = _keypair()
    _, pub_b = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv_a, **kw)
    verify_tombstone_origin_signature(sig, **kw, allowed_pubkeys={pub_b, pub_a})


def test_verify_rejects_when_key_not_in_set() -> None:
    priv_a, _ = _keypair()
    _, pub_b = _keypair()
    kw = _kwargs()
    sig = sign_tombstone_origin(priv_a, **kw)
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(sig, **kw, allowed_pubkeys={pub_b})


# (f) domain separation from the FACT origin sig ------------------------------


def test_tombstone_origin_sig_does_not_verify_as_fact_origin_sig() -> None:
    """tv="t2.1" domain separation: a tombstone origin sig must NOT verify under the FACT
    verify_origin_signature, and a fact origin sig must NOT verify as a tombstone origin sig.
    """
    priv, pub = _keypair()
    # A tombstone origin sig.
    tkw = _kwargs()
    tsig = sign_tombstone_origin(priv, **tkw)
    # A fact origin sig built so its scalar fields line up where they can.
    fact_origin = {
        "tenant": tkw["origin_tenant"],
        "node_id": tkw["origin_node_id"],
        "allowed_scopes": tkw["origin_allowed_scopes"],
        "allowed_tenants": tkw["origin_allowed_tenants"],
        "entity_uri": tkw["origin_entity_uri"],
    }
    fsig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=fact_origin, valid_until=None)

    # Cross-verify both directions: each must be rejected under the other's verifier.
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            tsig,
            fact_id=_FID,
            cid=_CID,
            origin=fact_origin,
            valid_until=None,
            allowed_pubkeys={pub},
        )
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(fsig, **tkw, allowed_pubkeys={pub})
