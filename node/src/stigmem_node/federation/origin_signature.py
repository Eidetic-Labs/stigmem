"""Phase 2b — per-fact origin signature (design §2.2).

The origin node signs the JCS-canonical tuple
(fact_id, cid, origin_tenant, origin_node_id, origin_allowed_scopes, origin_allowed_tenants,
valid_until) with its Ed25519 federation key (== its manifest key after Phase 2a unification).
Receivers verify against the pubkey set from resolve_origin_key(). CID binds content; this
signature binds content <-> origin identity <-> tenant <-> authorization <-> visibility window,
and the fact_id (F-1: fact_id is NOT in the CID, so binding it here makes the wire id
tamper-evident — dedup and the received_from/conflict graph key on it). valid_until is included
because it is excluded from the CID and is authorization-relevant. Verification runs regardless of
trust_mode (including 'off') — it is the hard gate.
"""

from __future__ import annotations

import base64
from typing import Any

import canonicaljson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class OriginSignatureError(ValueError):
    """Origin signature missing, malformed, or failed verification (fail-closed)."""


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def canonical_origin_tuple(
    *,
    fact_id: str,
    cid: str,
    origin_tenant: str,
    origin_node_id: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    valid_until: str | None,
) -> bytes:
    """RFC 8785 JCS bytes of the signed origin tuple (sets sorted for determinism)."""
    return canonicaljson.encode_canonical_json(
        {
            "cid": cid,
            "fact_id": fact_id,
            "origin_allowed_scopes": sorted(origin_allowed_scopes),
            "origin_allowed_tenants": sorted(origin_allowed_tenants),
            "origin_node_id": origin_node_id,
            "origin_tenant": origin_tenant,
            "valid_until": valid_until,
        }
    )


def sign_origin(
    private_key: Ed25519PrivateKey,
    *,
    fact_id: str,
    cid: str,
    origin: dict[str, Any],
    valid_until: str | None,
) -> str:
    """Sign the origin tuple; returns base64url signature (no padding)."""
    body = canonical_origin_tuple(
        fact_id=fact_id,
        cid=cid,
        origin_tenant=origin["tenant"],
        origin_node_id=origin["node_id"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        valid_until=valid_until,
    )
    return base64.urlsafe_b64encode(private_key.sign(body)).decode().rstrip("=")


def verify_origin_signature(
    sig_b64: str,
    *,
    fact_id: str,
    cid: str,
    origin: dict[str, Any],
    valid_until: str | None,
    allowed_pubkeys: set[str],
) -> None:
    """Verify sig against ANY key in allowed_pubkeys (current + rotation window).

    Raises OriginSignatureError on any failure. Returning None == verified.
    """
    if not sig_b64 or not allowed_pubkeys:
        raise OriginSignatureError("origin signature or key set missing")
    try:
        body = canonical_origin_tuple(
            fact_id=fact_id,
            cid=cid,
            origin_tenant=origin["tenant"],
            origin_node_id=origin["node_id"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            valid_until=valid_until,
        )
        sig = base64.urlsafe_b64decode(_pad(sig_b64))
    except (KeyError, TypeError, ValueError) as exc:
        raise OriginSignatureError(f"malformed origin block or signature: {exc}") from exc
    for pub_b64 in allowed_pubkeys:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_pad(pub_b64)))
            pub.verify(sig, body)
            return
        except (InvalidSignature, ValueError):
            continue
    raise OriginSignatureError("origin signature did not verify against any allowed key")
