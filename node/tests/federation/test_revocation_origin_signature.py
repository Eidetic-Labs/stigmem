"""Phase 2c Rev-1 — revocation ORIGIN-ATTESTATION signature.

Distinct from the existing revocation issuer-signer signature
(sign_revocation/verify_revocation_signature). This signature binds WHO ORIGINATED a
relayed tombstone REVERSAL + its propagation grant, so a relay cannot launder or re-target
a revocation. It mirrors the FACT origin signature (W3.1) and the TOMBSTONE origin signature
(W6.3), but for revocations, with a DISTINCT hardcoded tuple version ``tv = "r2.1"`` for
domain separation: a revocation origin sig can never be confused with / replayed as a
tombstone or fact origin sig.

A revocation has no entity_uri/scope of its own — it references a tombstone by id. The tuple
therefore binds the revocation ``id`` (as ``rid``) and the referenced ``tombstone_id`` instead.
"""

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from stigmem_node.federation.origin_signature import (
    OriginSignatureError,
    canonical_revocation_origin_tuple,
    sign_origin,
    sign_revocation_origin,
    sign_tombstone_origin,
    verify_origin_signature,
    verify_revocation_origin_signature,
    verify_tombstone_origin_signature,
)

_RID = "33333333-3333-3333-3333-333333333333"
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
    revocation_id: str = _RID,
    tombstone_id: str = _TID,
    origin_node_id: str = "stigmem:node:o1",
    origin_tenant: str = "acme",
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
    origin_entity_uri: str = _ORIGIN_ENTITY_URI,
) -> dict[str, Any]:
    return {
        "revocation_id": revocation_id,
        "tombstone_id": tombstone_id,
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


# (b) canonical tuple shape ---------------------------------------------------


def test_canonical_revocation_tuple_is_jcs_with_tv_and_binds_rid_and_tombstone_id() -> None:
    body = canonical_revocation_origin_tuple(
        revocation_id=_RID,
        tombstone_id=_TID,
        origin_node_id="n",
        origin_tenant="t",
        origin_allowed_scopes=["public", "local"],
        origin_allowed_tenants=["beta", "acme"],
        origin_entity_uri=_ORIGIN_ENTITY_URI,
    )
    # DISTINCT version (NOT the fact tuple's "2.1" nor the tombstone tuple's "t2.1").
    assert b'"tv":"r2.1"' in body
    # Binds the revocation + referenced-tombstone identity fields.
    assert b'"rid":"' + _RID.encode() in body
    assert b'"tombstone_id":"' + _TID.encode() in body
    # JCS: keys sorted; sets sorted lexicographically.
    assert body.index(b'"origin_allowed_scopes"') < body.index(b'"rid"') < body.index(
        b'"tombstone_id"'
    ) < body.index(b'"tv"')
    assert b'"origin_allowed_scopes":["local","public"]' in body
    assert b'"origin_allowed_tenants":["acme","beta"]' in body


# (c) round-trip --------------------------------------------------------------


def test_sign_and_verify_roundtrip() -> None:
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_revocation_origin(priv, **kw)
    verify_revocation_origin_signature(sig, **kw, allowed_pubkeys={pub})


# (d) tamper any field --------------------------------------------------------


@pytest.mark.parametrize(
    "field,bad",
    [
        ("revocation_id", "99999999-9999-9999-9999-999999999999"),
        ("tombstone_id", "88888888-8888-8888-8888-888888888888"),
        ("origin_node_id", "stigmem:node:evil"),
        ("origin_tenant", "evilco"),
        ("origin_entity_uri", "https://relay.example"),
    ],
)
def test_verify_rejects_tampered_scalar_field(field: str, bad: str) -> None:
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_revocation_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(sig, **{**kw, field: bad}, allowed_pubkeys={pub})


def test_verify_rejects_tampered_allowed_scope() -> None:
    priv, pub = _keypair()
    kw = _kwargs(origin_allowed_scopes=["local"])
    sig = sign_revocation_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(
            sig, **{**kw, "origin_allowed_scopes": ["local", "public"]}, allowed_pubkeys={pub}
        )


# (e) missing/empty origin_entity_uri -----------------------------------------


def test_sign_rejects_missing_origin_entity_uri() -> None:
    priv, _ = _keypair()
    kw = _kwargs(origin_entity_uri="")
    with pytest.raises(OriginSignatureError):
        sign_revocation_origin(priv, **kw)


def test_verify_rejects_missing_origin_entity_uri() -> None:
    """ANTI-DOWNGRADE: an empty origin_entity_uri is rejected, never silently verified."""
    priv, pub = _keypair()
    kw = _kwargs()
    sig = sign_revocation_origin(priv, **kw)
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(
            sig, **{**kw, "origin_entity_uri": ""}, allowed_pubkeys={pub}
        )


# (f) rotation window ---------------------------------------------------------


def test_verify_accepts_any_key_in_rotation_set() -> None:
    priv_a, pub_a = _keypair()
    _, pub_b = _keypair()
    kw = _kwargs()
    sig = sign_revocation_origin(priv_a, **kw)
    verify_revocation_origin_signature(sig, **kw, allowed_pubkeys={pub_b, pub_a})


def test_verify_rejects_when_key_not_in_set() -> None:
    priv_a, _ = _keypair()
    _, pub_b = _keypair()
    kw = _kwargs()
    sig = sign_revocation_origin(priv_a, **kw)
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(sig, **kw, allowed_pubkeys={pub_b})


# (g) domain separation from FACT and TOMBSTONE origin sigs --------------------


def test_revocation_origin_sig_does_not_verify_as_tombstone_or_fact_origin_sig() -> None:
    """tv="r2.1" domain separation: a revocation origin sig must NOT verify under the
    TOMBSTONE or FACT verifier, and neither of those verifies as a revocation origin sig.
    """
    priv, pub = _keypair()
    rkw = _kwargs()
    rsig = sign_revocation_origin(priv, **rkw)

    # A tombstone origin sig built so its scalar fields line up where they can.
    tkw = {
        "tombstone_id": rkw["tombstone_id"],
        "entity_uri": _ENTITY_URI,
        "scope": "local",
        "origin_node_id": rkw["origin_node_id"],
        "origin_tenant": rkw["origin_tenant"],
        "origin_allowed_scopes": rkw["origin_allowed_scopes"],
        "origin_allowed_tenants": rkw["origin_allowed_tenants"],
        "origin_entity_uri": rkw["origin_entity_uri"],
    }
    tsig = sign_tombstone_origin(priv, **tkw)

    # A fact origin sig.
    fact_origin = {
        "tenant": rkw["origin_tenant"],
        "node_id": rkw["origin_node_id"],
        "allowed_scopes": rkw["origin_allowed_scopes"],
        "allowed_tenants": rkw["origin_allowed_tenants"],
        "entity_uri": rkw["origin_entity_uri"],
    }
    fsig = sign_origin(priv, fact_id=_FID, cid=_CID, origin=fact_origin, valid_until=None)

    # The revocation sig must NOT verify as a tombstone or fact origin sig.
    with pytest.raises(OriginSignatureError):
        verify_tombstone_origin_signature(rsig, **tkw, allowed_pubkeys={pub})
    with pytest.raises(OriginSignatureError):
        verify_origin_signature(
            rsig,
            fact_id=_FID,
            cid=_CID,
            origin=fact_origin,
            valid_until=None,
            allowed_pubkeys={pub},
        )

    # And neither a tombstone sig nor a fact sig verifies as a revocation origin sig.
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(tsig, **rkw, allowed_pubkeys={pub})
    with pytest.raises(OriginSignatureError):
        verify_revocation_origin_signature(fsig, **rkw, allowed_pubkeys={pub})
