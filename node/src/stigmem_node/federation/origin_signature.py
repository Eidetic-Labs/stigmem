"""Phase 2b/2c — per-fact origin signature (design §2.2, §2c W3.1).

The origin node signs the JCS-canonical tuple
(tv, fact_id, cid, origin_tenant, origin_node_id, origin_allowed_scopes,
origin_allowed_tenants, origin_entity_uri, valid_until) with its Ed25519 federation key
(== its manifest key after Phase 2a unification). Receivers verify against the pubkey set
from resolve_origin_key(). CID binds content; this signature binds content <-> origin
identity <-> tenant <-> authorization <-> visibility window, and the fact_id (F-1: fact_id
is NOT in the CID, so binding it here makes the wire id tamper-evident — dedup and the
received_from/conflict graph key on it). valid_until is included because it is excluded
from the CID and is authorization-relevant. Verification runs regardless of trust_mode
(including 'off') — it is the hard gate.

Phase 2c W3.1 — HARD CUTOVER to v2.1: the tuple now ALSO binds the origin's ``entity_uri``
(so a relay cannot lie about which origin a relayed fact came from — the receiver fetches
and verifies the origin's manifest by this entity_uri) and a hardcoded in-body tuple
version ``tv = "2.1"`` (forward-proofing: the signature commits to its exact field set).
``entity_uri`` is MANDATORY — there is NO legacy 6-field verify path. An origin block whose
``entity_uri`` is missing or empty is REJECTED, never silently verified under the old 2b
tuple (anti-downgrade: a 6-field fallback would let an attacker strip ``entity_uri`` and
defeat the binding). Facts signed under old 2b (no entity_uri) are simply not relayable;
that is acceptable and fail-safe.
"""

from __future__ import annotations

import base64
from typing import Any

import canonicaljson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class OriginSignatureError(ValueError):
    """Origin signature missing, malformed, or failed verification (fail-closed)."""


# Hardcoded in-body tuple version (Phase 2c W3.1). Committing it INTO the signed bytes makes
# the signature pin its exact field set, so a future 2.2 (different fields) can never be
# confused with a 2.1 signature. Bump in lockstep with any change to the signed field set.
_TUPLE_VERSION = "2.1"


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _require_entity_uri(origin: dict[str, Any]) -> str:
    """Return a non-empty origin ``entity_uri`` or raise (anti-downgrade, W3.1).

    ``entity_uri`` is MANDATORY in the v2.1 tuple. A missing or empty value is a
    hard rejection — never a fall-through to a legacy 6-field tuple.
    """
    entity_uri = origin.get("entity_uri")
    if not entity_uri:
        raise OriginSignatureError("origin entity_uri missing or empty (v2.1 requires it)")
    return str(entity_uri)


def canonical_origin_tuple(
    *,
    fact_id: str,
    cid: str,
    origin_tenant: str,
    origin_node_id: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    valid_until: str | None,
    entity_uri: str,
) -> bytes:
    """RFC 8785 JCS bytes of the signed v2.1 origin tuple (sets sorted for determinism).

    ``entity_uri`` and the hardcoded ``tv`` constant are bound INTO the tuple (W3.1).
    """
    return canonicaljson.encode_canonical_json(
        {
            "cid": cid,
            "entity_uri": entity_uri,
            "fact_id": fact_id,
            "origin_allowed_scopes": sorted(origin_allowed_scopes),
            "origin_allowed_tenants": sorted(origin_allowed_tenants),
            "origin_node_id": origin_node_id,
            "origin_tenant": origin_tenant,
            "tv": _TUPLE_VERSION,
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
        entity_uri=_require_entity_uri(origin),
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
    # Anti-downgrade (W3.1): require entity_uri BEFORE building the tuple. A missing/empty
    # value raises here — there is NO 6-field legacy reconstruction to fall back to, so a
    # relay cannot strip entity_uri to defeat the origin->entity binding.
    entity_uri = _require_entity_uri(origin)
    try:
        body = canonical_origin_tuple(
            fact_id=fact_id,
            cid=cid,
            origin_tenant=origin["tenant"],
            origin_node_id=origin["node_id"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            valid_until=valid_until,
            entity_uri=entity_uri,
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
