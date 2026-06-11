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

# Hardcoded in-body tuple version for the TOMBSTONE origin-attestation tuple (Phase 2c W6.3).
# DISTINCT from the fact tuple's "2.1" so a tombstone origin signature can NEVER be confused
# with / replayed as a fact origin signature (domain separation is a security property — the
# two tuples share the same private key and base64url framing, only the signed bytes differ).
_TOMBSTONE_TUPLE_VERSION = "t2.1"

# Hardcoded in-body tuple version for the REVOCATION origin-attestation tuple (Phase 2c Rev-1).
# DISTINCT from both the fact tuple's "2.1" and the tombstone tuple's "t2.1" so a revocation
# origin signature can NEVER be confused with / replayed as a tombstone or fact origin
# signature (domain separation — all three share the same key and base64url framing, only the
# signed bytes differ).
_REVOCATION_TUPLE_VERSION = "r2.1"


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


# ---------------------------------------------------------------------------
# Tombstone origin-attestation signature (Phase 2c W6.3)
#
# SEPARATE from the existing tombstone issuer-signer signature
# (lifecycle/tombstone_signing.py). That one says "this org issued this RTBF tombstone"; this
# one says "this ORIGIN node relayed this tombstone under THIS propagation grant". Binding the
# tombstone ``id``, ``entity_uri`` and ``scope`` into the signed tuple is the anti-relaunder
# property: a relay that widens ``scope`` ("local" -> "*"), retargets ``entity_uri``, or lies
# about its grant invalidates the signature. ``tv = "t2.1"`` (distinct from the fact tuple's
# "2.1") gives hard domain separation so the two origin signatures are never interchangeable.
# ---------------------------------------------------------------------------


def canonical_tombstone_origin_tuple(
    *,
    tombstone_id: str,
    entity_uri: str,
    scope: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
) -> bytes:
    """RFC 8785 JCS bytes of the signed tombstone origin tuple (sets sorted for determinism).

    Binds the tombstone ``id`` (as ``tid``), subject ``entity_uri`` and ``scope`` so a relay
    cannot relaunder or re-scope the suppression. ``tv`` is the hardcoded constant ``"t2.1"``,
    distinct from the fact tuple's ``"2.1"`` (domain separation, W6.3).
    """
    return canonicaljson.encode_canonical_json(
        {
            "entity_uri": entity_uri,
            "origin_allowed_scopes": sorted(origin_allowed_scopes),
            "origin_allowed_tenants": sorted(origin_allowed_tenants),
            "origin_entity_uri": origin_entity_uri,
            "origin_node_id": origin_node_id,
            "origin_tenant": origin_tenant,
            "scope": scope,
            "tid": tombstone_id,
            "tv": _TOMBSTONE_TUPLE_VERSION,
        }
    )


def _require_value(value: str, name: str) -> str:
    """Return a non-empty value or raise (anti-downgrade, W6.3)."""
    if not value:
        raise OriginSignatureError(f"tombstone origin {name} missing or empty")
    return value


def sign_tombstone_origin(
    private_key: Ed25519PrivateKey,
    *,
    tombstone_id: str,
    entity_uri: str,
    scope: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
) -> str:
    """Sign the tombstone origin tuple; returns base64url signature (no padding)."""
    body = canonical_tombstone_origin_tuple(
        tombstone_id=tombstone_id,
        entity_uri=_require_value(entity_uri, "entity_uri"),
        scope=scope,
        origin_node_id=origin_node_id,
        origin_tenant=origin_tenant,
        origin_allowed_scopes=origin_allowed_scopes,
        origin_allowed_tenants=origin_allowed_tenants,
        origin_entity_uri=_require_value(origin_entity_uri, "entity_uri"),
    )
    return base64.urlsafe_b64encode(private_key.sign(body)).decode().rstrip("=")


def verify_tombstone_origin_signature(
    sig_b64: str,
    *,
    tombstone_id: str,
    entity_uri: str,
    scope: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
    allowed_pubkeys: set[str],
) -> None:
    """Verify a tombstone origin sig against ANY key in allowed_pubkeys (rotation window).

    Raises OriginSignatureError on any failure. Returning None == verified. Requires both the
    subject ``entity_uri`` and the ``origin_entity_uri`` to be present/non-empty BEFORE building
    the tuple (anti-downgrade: there is no legacy field-stripped path to fall back to).
    """
    if not sig_b64 or not allowed_pubkeys:
        raise OriginSignatureError("tombstone origin signature or key set missing")
    # Anti-downgrade (W6.3): require both entity_uri fields before building the tuple.
    entity_uri = _require_value(entity_uri, "entity_uri")
    origin_entity_uri = _require_value(origin_entity_uri, "entity_uri")
    try:
        body = canonical_tombstone_origin_tuple(
            tombstone_id=tombstone_id,
            entity_uri=entity_uri,
            scope=scope,
            origin_node_id=origin_node_id,
            origin_tenant=origin_tenant,
            origin_allowed_scopes=origin_allowed_scopes,
            origin_allowed_tenants=origin_allowed_tenants,
            origin_entity_uri=origin_entity_uri,
        )
        sig = base64.urlsafe_b64decode(_pad(sig_b64))
    except (KeyError, TypeError, ValueError) as exc:
        raise OriginSignatureError(
            f"malformed tombstone origin block or signature: {exc}"
        ) from exc
    for pub_b64 in allowed_pubkeys:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_pad(pub_b64)))
            pub.verify(sig, body)
            return
        except (InvalidSignature, ValueError):
            continue
    raise OriginSignatureError(
        "tombstone origin signature did not verify against any allowed key"
    )


# ---------------------------------------------------------------------------
# Revocation origin-attestation signature (Phase 2c Rev-1)
#
# SEPARATE from the existing revocation issuer-signer signature
# (sign_revocation/verify_revocation_signature). That one says "this org issued this tombstone
# REVERSAL"; this one says "this ORIGIN node relayed this revocation under THIS propagation
# grant". A revocation has no entity_uri/scope of its own — it references a tombstone by id —
# so the tuple binds the revocation ``id`` (as ``rid``) and the referenced ``tombstone_id``
# instead. Binding both is the anti-relaunder property: a relay that retargets which revocation
# or which tombstone it carries, or lies about its grant, invalidates the signature.
# ``tv = "r2.1"`` (distinct from the fact tuple's "2.1" and the tombstone tuple's "t2.1") gives
# hard domain separation so the three origin signatures are never interchangeable.
# ---------------------------------------------------------------------------


def canonical_revocation_origin_tuple(
    *,
    revocation_id: str,
    tombstone_id: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
) -> bytes:
    """RFC 8785 JCS bytes of the signed revocation origin tuple (sets sorted for determinism).

    Binds the revocation ``id`` (as ``rid``) and the referenced ``tombstone_id`` so a relay
    cannot retarget the reversal. ``tv`` is the hardcoded constant ``"r2.1"``, distinct from
    the fact tuple's ``"2.1"`` and the tombstone tuple's ``"t2.1"`` (domain separation, Rev-1).
    """
    return canonicaljson.encode_canonical_json(
        {
            "origin_allowed_scopes": sorted(origin_allowed_scopes),
            "origin_allowed_tenants": sorted(origin_allowed_tenants),
            "origin_entity_uri": origin_entity_uri,
            "origin_node_id": origin_node_id,
            "origin_tenant": origin_tenant,
            "rid": revocation_id,
            "tombstone_id": tombstone_id,
            "tv": _REVOCATION_TUPLE_VERSION,
        }
    )


def sign_revocation_origin(
    private_key: Ed25519PrivateKey,
    *,
    revocation_id: str,
    tombstone_id: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
) -> str:
    """Sign the revocation origin tuple; returns base64url signature (no padding)."""
    body = canonical_revocation_origin_tuple(
        revocation_id=revocation_id,
        tombstone_id=tombstone_id,
        origin_node_id=origin_node_id,
        origin_tenant=origin_tenant,
        origin_allowed_scopes=origin_allowed_scopes,
        origin_allowed_tenants=origin_allowed_tenants,
        origin_entity_uri=_require_value(origin_entity_uri, "entity_uri"),
    )
    return base64.urlsafe_b64encode(private_key.sign(body)).decode().rstrip("=")


def verify_revocation_origin_signature(
    sig_b64: str,
    *,
    revocation_id: str,
    tombstone_id: str,
    origin_node_id: str,
    origin_tenant: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    origin_entity_uri: str,
    allowed_pubkeys: set[str],
) -> None:
    """Verify a revocation origin sig against ANY key in allowed_pubkeys (rotation window).

    Raises OriginSignatureError on any failure. Returning None == verified. Requires
    ``origin_entity_uri`` to be present/non-empty BEFORE building the tuple (anti-downgrade:
    there is no legacy field-stripped path to fall back to).
    """
    if not sig_b64 or not allowed_pubkeys:
        raise OriginSignatureError("revocation origin signature or key set missing")
    # Anti-downgrade (Rev-1): require origin_entity_uri before building the tuple.
    origin_entity_uri = _require_value(origin_entity_uri, "entity_uri")
    try:
        body = canonical_revocation_origin_tuple(
            revocation_id=revocation_id,
            tombstone_id=tombstone_id,
            origin_node_id=origin_node_id,
            origin_tenant=origin_tenant,
            origin_allowed_scopes=origin_allowed_scopes,
            origin_allowed_tenants=origin_allowed_tenants,
            origin_entity_uri=origin_entity_uri,
        )
        sig = base64.urlsafe_b64decode(_pad(sig_b64))
    except (KeyError, TypeError, ValueError) as exc:
        raise OriginSignatureError(
            f"malformed revocation origin block or signature: {exc}"
        ) from exc
    for pub_b64 in allowed_pubkeys:
        try:
            pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_pad(pub_b64)))
            pub.verify(sig, body)
            return
        except (InvalidSignature, ValueError):
            continue
    raise OriginSignatureError(
        "revocation origin signature did not verify against any allowed key"
    )
