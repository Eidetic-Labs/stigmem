"""Phase 2a — resolve an origin node_id to the verified pubkey(s) it may sign with.

Chain: node_id → peers.entity_uri (verified at registration) → stored OrgManifest →
self-verify (+ rotation-window prior key). Fail-closed: any missing/invalid link raises.
The consumer (origin_sig verification) lands in Phase 2b.
"""

from __future__ import annotations

from ..db import db
from ..identity.manifest import ManifestError, verify_manifest
from ..identity.trust_store import get_peer_manifest
from ..settings import settings


class OriginIdentityError(ValueError):
    """Origin identity could not be verified (fail-closed)."""


def resolve_origin_key(node_id: str) -> set[str]:
    """Return the base64url pubkeys *node_id*'s origin may sign with.

    Includes the manifest's current key plus the prior key inside the most
    recent rotation window (dual-trust). Raises OriginIdentityError on any
    missing or invalid link in the chain.
    """
    with db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ? AND status = 'active'",
            (node_id,),
        ).fetchone()
    if row is None or not row["entity_uri"]:
        raise OriginIdentityError(f"no verified entity_uri bound to node_id {node_id!r}")

    manifest = get_peer_manifest(row["entity_uri"], trust_mode=settings.trust_mode)
    if manifest is None:
        raise OriginIdentityError(f"no stored manifest for entity_uri {row['entity_uri']!r}")
    try:
        verify_manifest(manifest, trust_mode=settings.trust_mode)
    except ManifestError as exc:
        raise OriginIdentityError(f"manifest verification failed: {exc}") from exc

    keys = {manifest.public_key}
    if manifest.rotation_events:
        last = manifest.rotation_events[-1]
        if getattr(last, "previous_public_key", ""):
            keys.add(last.previous_public_key)
    return keys
