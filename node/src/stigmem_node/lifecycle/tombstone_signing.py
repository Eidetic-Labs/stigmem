"""Tombstone signing and verification — spec §23.2.4, rev 14.

Signing body: JCS over TombstoneRecord with "signature" and "reason" excluded
(field-exclusion pattern per §19.1.3).  This allows reason redaction before
federation rebroadcast without invalidating the signature.

Public surface:
    sign_tombstone(record) -> TombstoneRecord
    verify_tombstone_signature(record, public_key_b64) -> None  (raises on fail)
    get_node_key_id() -> str | None
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import canonicaljson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..models.tombstones import TombstoneRecord, TombstoneRevocationRecord

logger = logging.getLogger("stigmem.tombstone")


def _pad(b64url: str) -> str:
    return b64url + "=" * (-len(b64url) % 4)


def _pubkey_from_b64(b64: str) -> Ed25519PublicKey:
    raw = base64.urlsafe_b64decode(_pad(b64))
    return Ed25519PublicKey.from_public_bytes(raw)


def _signing_body(record: TombstoneRecord) -> bytes:
    """JCS-canonical bytes over TombstoneRecord with 'signature' and 'reason' excluded (§23.2.4).

    F-12 §23.2.3: scope arrays are sorted lexicographically before canonicalization
    to prevent interop failures from array-order differences across JSON implementations.
    """
    scope_val: Any = record.scope
    if isinstance(scope_val, list):
        scope_val = sorted(scope_val)
    doc: dict[str, Any] = {
        "id": record.id,
        "entity_uri": record.entity_uri,
        "scope": scope_val,
        "signed_by": record.signed_by,
        "key_id": record.key_id,
        "created_at": record.created_at,
        "legal_hold": record.legal_hold,
    }
    return canonicaljson.encode_canonical_json(doc)


def get_node_key_id() -> str | None:
    """Return the node's current signing key_id (SHA-256 hex, 16-char prefix), or None."""
    from ..identity.capability import load_node_private_key
    from ..identity.key_rotation import generate_key_id

    priv = load_node_private_key()
    if priv is None:
        return None
    pub = priv.public_key()
    return generate_key_id(pub)


def sign_tombstone(record: TombstoneRecord) -> TombstoneRecord:
    """Sign *record* with the node's active private key. Returns a new record with signature set."""
    from ..identity.capability import load_node_private_key
    from ..identity.key_rotation import generate_key_id

    priv = load_node_private_key()
    if priv is None:
        raise RuntimeError("STIGMEM_NODE_PRIVATE_KEY not configured; cannot sign tombstones")

    pub = priv.public_key()
    key_id = generate_key_id(pub)
    record = record.model_copy(update={"key_id": key_id})
    body = _signing_body(record)
    sig_bytes = priv.sign(body)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
    return record.model_copy(update={"signature": sig_b64})


def verify_tombstone_signature(record: TombstoneRecord, public_key_b64: str) -> None:
    """Verify tombstone signature against *public_key_b64* (base64url Ed25519).

    Raises ValueError on failure.  Per §23.4.2.1 the caller must resolve the
    signing key from the org manifest independently of the relaying peer.
    """
    try:
        pub = _pubkey_from_b64(public_key_b64)
        body = _signing_body(record)
        sig_bytes = base64.urlsafe_b64decode(_pad(record.signature))
        pub.verify(sig_bytes, body)
    except InvalidSignature as exc:
        raise ValueError("tombstone signature verification failed") from exc
    except Exception as exc:
        raise ValueError(f"tombstone signature error: {exc}") from exc


class IssuerVerificationError(ValueError):
    """The tombstone/revocation ISSUER-signer signature could not be verified (fail-closed).

    ``reason`` is a short machine-stable code so callers (push route HTTP wrapper, pull
    client log line) can branch / report consistently without parsing the message.
    """

    def __init__(self, reason: str, message: str | None = None) -> None:
        self.reason = reason
        super().__init__(message or reason)


def _resolve_pubkey_for_key_id(manifest: Any, key_id: str) -> str | None:
    """Return base64url public key from *manifest* matching *key_id*, or None.

    Matches the manifest's current key, else scans rotation_events for a matching
    ``new_key_id`` (dual-trust rotation window). Shared by the push route and the pull
    client so both resolve the issuer key identically.
    """
    if manifest.key_id == key_id:
        pk: str = manifest.public_key
        return pk
    for evt in getattr(manifest, "rotation_events", []):
        if getattr(evt, "new_key_id", None) == key_id:
            new_pk: str | None = getattr(evt, "new_public_key", None)
            return new_pk
    return None


def resolve_and_verify_tombstone_issuer(
    record: Any,
    *,
    key_id: str,
    signer_uri: str,
    verifier: Any,
) -> None:
    """Resolve the signer manifest, pick the signing key, and verify the issuer signature.

    The single shared issuer-signer verification used by BOTH the push ingest route
    (``routes/_federation_impl._verify_signed_artifact_or_400`` wraps this into HTTP
    errors + audit) and the pull client (``federation_pull.pull_tombstones_from_peer_once``,
    which closes the W6.1 gap where pull did NOT verify the issuer). Keeping it in one place
    means push and pull can never drift.

    Raises ``IssuerVerificationError(reason=...)`` on any failure. ``reason`` is one of:
    ``missing_key_id`` / ``signer_manifest_missing`` / ``key_id_not_in_signer_manifest`` /
    a verifier ValueError string (signature mismatch). Returns None == verified.
    """
    from ..identity.trust_store import get_peer_manifest

    if not key_id:
        raise IssuerVerificationError("missing_key_id", "tombstone missing key_id")
    manifest = get_peer_manifest(signer_uri)
    if manifest is None:
        raise IssuerVerificationError(
            "signer_manifest_missing", f"no manifest for signer {signer_uri!r}"
        )
    pubkey_b64 = _resolve_pubkey_for_key_id(manifest, key_id)
    if pubkey_b64 is None:
        raise IssuerVerificationError(
            "key_id_not_in_signer_manifest", "key_id not in signer manifest"
        )
    try:
        verifier(record, pubkey_b64)
    except ValueError as exc:
        raise IssuerVerificationError(str(exc), str(exc)) from exc


def _revocation_signing_body(record: TombstoneRevocationRecord) -> bytes:
    """JCS-canonical bytes over TombstoneRevocationRecord with 'signature' and 'reason' excluded."""
    doc: dict[str, Any] = {
        "id": record.id,
        "tombstone_id": record.tombstone_id,
        "signed_by": record.signed_by,
        "key_id": record.key_id,
        "created_at": record.created_at,
    }
    return canonicaljson.encode_canonical_json(doc)


def sign_revocation(record: TombstoneRevocationRecord) -> TombstoneRevocationRecord:
    """Sign *record* with the node's active private key. Returns a new record with signature set."""
    from ..identity.capability import load_node_private_key
    from ..identity.key_rotation import generate_key_id

    priv = load_node_private_key()
    if priv is None:
        raise RuntimeError("STIGMEM_NODE_PRIVATE_KEY not configured; cannot sign revocations")

    pub = priv.public_key()
    key_id = generate_key_id(pub)
    record = record.model_copy(update={"key_id": key_id})
    body = _revocation_signing_body(record)
    sig_bytes = priv.sign(body)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
    return record.model_copy(update={"signature": sig_b64})


def verify_revocation_signature(record: TombstoneRevocationRecord, public_key_b64: str) -> None:
    """Verify revocation signature against *public_key_b64* (base64url Ed25519).

    Raises ValueError on failure.
    """
    try:
        pub = _pubkey_from_b64(public_key_b64)
        body = _revocation_signing_body(record)
        sig_bytes = base64.urlsafe_b64decode(_pad(record.signature))
        pub.verify(sig_bytes, body)
    except InvalidSignature as exc:
        raise ValueError("revocation signature verification failed") from exc
    except Exception as exc:
        raise ValueError(f"revocation signature error: {exc}") from exc
