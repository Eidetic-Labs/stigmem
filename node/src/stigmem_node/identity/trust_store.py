"""Peer trust store — reads/writes federation_manifests table (spec §19.8).

Public surface:
    store_peer_manifest(entity_uri, manifest, log_entry) -> None
    get_peer_manifest(entity_uri) -> OrgManifest | None
    refresh_peer_manifests() -> None  (periodic task)
    cleanup_expired_tokens() -> int   (background cleanup, run opportunistically)

Security requirements:
    H1 mitigation: when resolving a peer manifest for token verification,
    check manifest.expires_at > now; attempt refresh; reject if still expired.
    Rotation chain invariant 4: reject any update that would regress key_id.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..net_util import resolve_pinned_address
from ..settings import settings
from .manifest import (
    ManifestError,
    OrgManifest,
    manifest_from_dict,
    manifest_to_dict,
    verify_manifest,
    verify_rotation_chain,
)
from .transparency_log import LogEntry

if TYPE_CHECKING:
    pass

logger = logging.getLogger("stigmem.identity.trust_store")


def store_peer_manifest(
    entity_uri: str,
    manifest: OrgManifest,
    log_entry: LogEntry | None = None,
    *,
    trust_mode: str = "relaxed",
) -> None:
    """Upsert a peer manifest with rotation-chain regression check.

    Raises ManifestError if the update would regress to a previously-used key
    (§19.1.4 invariant 4) or if the manifest fails self-verification.
    """
    from ..db import db

    # Verify the manifest before storing
    verify_manifest(manifest, trust_mode=trust_mode)

    now = datetime.now(UTC).isoformat()
    log_entry_json = (
        json.dumps(
            {
                "log_id": log_entry.log_id,
                "leaf_hash": log_entry.leaf_hash,
                "log_index": log_entry.log_index,
                "integrated_time": log_entry.integrated_time,
                "inclusion_proof": log_entry.inclusion_proof,
            }
        )
        if log_entry is not None
        else None
    )

    manifest_json = json.dumps(manifest_to_dict(manifest), separators=(",", ":"))

    with db() as conn:
        existing = conn.execute(
            "SELECT id, manifest_json, key_id FROM federation_manifests WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchone()

        if existing is not None:
            # Rotation chain regression check: verify that the new manifest's chain
            # connects to (or continues from) the previously-accepted key.
            prev_manifest = manifest_from_dict(json.loads(existing["manifest_json"]))
            if manifest.key_id != prev_manifest.key_id:
                try:
                    verify_rotation_chain(
                        manifest,
                        previous_key_id=prev_manifest.key_id,
                        previous_pubkey_b64=prev_manifest.public_key,
                    )
                except ManifestError as exc:
                    raise ManifestError(f"manifest update rejected: {exc}") from exc

            conn.execute(
                """UPDATE federation_manifests
                   SET manifest_json   = ?,
                       signature       = ?,
                       key_id          = ?,
                       issued_at       = ?,
                       expires_at      = ?,
                       log_entry_json  = ?,
                       updated_at      = ?
                   WHERE entity_uri = ?""",
                (
                    manifest_json,
                    manifest.signature,
                    manifest.key_id,
                    manifest.issued_at,
                    manifest.expires_at,
                    log_entry_json,
                    now,
                    entity_uri,
                ),
            )
        else:
            conn.execute(
                """INSERT INTO federation_manifests
                   (id, entity_uri, manifest_json, signature, key_id,
                    issued_at, expires_at, log_entry_json, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    entity_uri,
                    manifest_json,
                    manifest.signature,
                    manifest.key_id,
                    manifest.issued_at,
                    manifest.expires_at,
                    log_entry_json,
                    now,
                    now,
                ),
            )

    logger.info("stored manifest for %s (key_id=%s)", entity_uri, manifest.key_id)


def get_peer_manifest(
    entity_uri: str,
    *,
    refresh_if_expired: bool = True,
    trust_mode: str = "relaxed",
) -> OrgManifest | None:
    """Return the stored manifest for *entity_uri*, or None if unknown.

    H1 mitigation: if the stored manifest is expired and refresh_if_expired is True,
    we attempt an HTTP fetch from /.well-known/stigmem-manifest.json.
    Returns None (reject) if the manifest is expired and cannot be refreshed.
    """
    from ..db import db

    with db() as conn:
        row = conn.execute(
            "SELECT manifest_json, log_entry_json, expires_at FROM federation_manifests "
            "WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchone()

    if row is None:
        return None

    manifest = manifest_from_dict(json.loads(row["manifest_json"]))

    # H1: expiry check
    now = datetime.now(UTC)
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))

    if expires_at <= now:
        if not refresh_if_expired:
            logger.warning("manifest for %s is expired; rejecting", entity_uri)
            return None  # caller must treat as rejection
        # Attempt refresh
        refreshed = _try_fetch_manifest(entity_uri)
        if refreshed is None:
            logger.warning("manifest for %s expired; refresh failed; rejecting", entity_uri)
            return None
        try:
            store_peer_manifest(entity_uri, refreshed, trust_mode=trust_mode)
        except ManifestError as exc:
            logger.warning("refreshed manifest for %s failed validation: %s", entity_uri, exc)
            return None
        return refreshed

    return manifest


def refresh_peer_manifests() -> None:
    """Periodic task: refresh all active peer manifests from their well-known endpoints.

    Alerts (logs warnings) on rotation events.
    Also runs opportunistic cleanup of expired capability tokens.
    """
    from ..db import db

    with db() as conn:
        rows = conn.execute("SELECT entity_uri, manifest_json FROM federation_manifests").fetchall()

    for row in rows:
        entity_uri: str = row["entity_uri"]
        prev_manifest = manifest_from_dict(json.loads(row["manifest_json"]))
        refreshed = _try_fetch_manifest(entity_uri)
        if refreshed is None:
            continue
        if refreshed.key_id != prev_manifest.key_id:
            logger.warning(
                "key rotation detected for %s: %s -> %s",
                entity_uri,
                prev_manifest.key_id,
                refreshed.key_id,
            )
        try:
            store_peer_manifest(entity_uri, refreshed)
        except ManifestError as exc:
            logger.warning("skipping refresh for %s: %s", entity_uri, exc)

    cleanup_expired_tokens()


def _try_fetch_manifest(entity_uri: str) -> OrgManifest | None:
    """Fetch /.well-known/stigmem-manifest.json from the peer's origin."""
    # Derive base URL from entity_uri (strip scheme-specific parts if needed)
    # entity_uri is expected to be an https:// URI or stigmem:// URI
    if entity_uri.startswith("https://") or entity_uri.startswith("http://"):
        from urllib.parse import urlparse

        parsed = urlparse(entity_uri)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    else:
        return None  # can't derive URL from non-HTTP URI

    try:
        # R-5 / F-SSRF1 anti-rebind pin. This manifest is re-fetched on the recurring
        # ``refresh_peer_manifests`` loop over every stored peer's entity_uri, so a
        # peer-controlled host that passed validation can later DNS-rebind to an
        # internal/IMDS address — the same resolve-then-reconnect TOCTOU the recurring
        # pull path closes via ``federation_pull._pinned_get``. ``_pinned_manifest_get``
        # resolves the host ONCE (https-only, rejecting the whole URL on any private
        # record) BEFORE opening the client and connects to that exact pinned IP, so an
        # ``http://`` entity_uri or a rebind target fails closed with no GET. The dev
        # bypass is ``federation_insecure`` alone, matching the recurring-pull path.
        resp = _pinned_manifest_get(
            f"{base_url}/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=settings.federation_insecure,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        manifest = manifest_from_dict(data)
        verify_manifest(manifest)
        return manifest
    except Exception as exc:
        logger.debug("failed to fetch manifest for %s: %s", entity_uri, exc)
        return None


def _pinned_manifest_get(
    url: str,
    *,
    timeout: float,
    skip_pin: bool,
) -> httpx.Response:
    """GET *url* with the a11 anti-rebind DNS pin (R-5 / F-SSRF1), unless *skip_pin*.

    Synchronous sibling of ``federation_pull._pinned_get``. Resolves the host ONCE
    via ``resolve_pinned_address`` (https-only — rejects the whole URL if ANY resolved
    record is private/loopback/IMDS, and rejects a non-https scheme), connecting to the
    EXACT pinned IP literal while preserving the ``Host`` header + TLS SNI + cert
    verification against the original hostname. The pin is resolved BEFORE the client is
    opened, so a blocked/rebind target fails closed (``ValueError``) without ever issuing
    a request. ``follow_redirects=False`` blocks a redirect from re-introducing a
    rebindable hop. Under *skip_pin* (``federation_insecure``) the original-hostname URL
    is passed straight through with no pin extensions (dev/test escape).
    """
    if skip_pin:
        return httpx.get(url, timeout=timeout, follow_redirects=False)

    pinned_ip = resolve_pinned_address(url, allow_schemes=frozenset({"https"}))
    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = parts.port
    ip_authority = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    if port is not None:
        netloc = f"{ip_authority}:{port}"
        host_header = f"{hostname}:{port}"
    else:
        netloc = ip_authority
        host_header = hostname
    pinned_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    # extensions={"sni_hostname": ...} runs TLS SNI + cert verification against the
    # original hostname while the socket connects to the pinned IP literal (the webhook
    # pin shape). httpx.get forwards it to the transient Client; the type stub omits the
    # kwarg, so the runtime-valid call needs an ignore.
    return httpx.get(  # type: ignore[call-arg]
        pinned_url,
        timeout=timeout,
        follow_redirects=False,
        headers={"Host": host_header},
        extensions={"sni_hostname": hostname},
    )


def cleanup_expired_tokens() -> int:
    """Delete capability tokens expired more than 24 hours ago. Returns count deleted."""
    from datetime import timedelta

    from ..db import db

    cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    with db() as conn:
        cur = conn.execute(
            "DELETE FROM capability_tokens WHERE expiry < ?",
            (cutoff,),
        )
        deleted: int = cur.rowcount or 0
    if deleted:
        logger.info("cleaned up %d expired capability tokens", deleted)
    return deleted
