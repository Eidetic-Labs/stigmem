"""Phase 2a — resolve an origin node_id to the verified pubkey(s) it may sign with.

Chain: node_id → peers.entity_uri (verified at registration) → stored OrgManifest →
self-verify (+ rotation-window prior key). Fail-closed: any missing/invalid link raises.
The consumer (origin_sig verification) lands in Phase 2b.

Phase 2c W3.2 — for a RELAYED fact the origin is NOT a direct peer, so the 2a chain
(which needs a stored peer manifest + active peer row) cannot resolve it. The receiver
instead establishes trust in the origin's key by FETCHING the origin's manifest from the
``entity_uri`` that W3.1 bound into the signed origin block, verifying it, and binding
``node_id ↔ entity_uri`` under a fail-closed uniqueness rule (``resolve_origin_key_for_relay``).
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from ..db import db
from ..identity.manifest import (
    ManifestError,
    OrgManifest,
    manifest_from_dict,
    verify_manifest,
)
from ..identity.trust_store import get_peer_manifest, store_peer_manifest
from ..net_util import assert_safe_url, node_url_is_loopback
from ..settings import settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger("stigmem.federation.origin_identity")


class OriginIdentityError(ValueError):
    """Origin identity could not be verified (fail-closed)."""


def _keys_from_manifest(manifest: OrgManifest) -> set[str]:
    """Current key plus the prior key inside the most recent rotation window."""
    keys = {manifest.public_key}
    if manifest.rotation_events:
        last = manifest.rotation_events[-1]
        if last.previous_public_key:
            keys.add(last.previous_public_key)
    return keys


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
    if row is None or not (row["entity_uri"] or "").strip():
        raise OriginIdentityError(f"no verified entity_uri bound to node_id {node_id!r}")

    manifest = get_peer_manifest(row["entity_uri"], trust_mode=settings.trust_mode)
    if manifest is None:
        raise OriginIdentityError(f"no stored manifest for entity_uri {row['entity_uri']!r}")
    try:
        verify_manifest(manifest, trust_mode=settings.trust_mode)
    except ManifestError as exc:
        raise OriginIdentityError(f"manifest verification failed: {exc}") from exc

    return _keys_from_manifest(manifest)


def _existing_entity_uri_for_node(node_id: str) -> str | None:
    """Return the entity_uri already locally bound to *node_id*, or None.

    A ``node_id ↔ entity_uri`` binding is UNIQUE. We read both sources of truth:

    * ``peers.entity_uri`` — the binding established at peer approval (2a), and
    * ``federation_manifests`` — any stored manifest that LISTS *node_id* in its
      ``entities`` (a relay first-contact binding stores the origin's manifest, so a
      later relay claiming the same node_id under a different entity_uri must be caught).

    The peers binding wins when present (it is the operator-approved authority). If the
    peers table has no binding, a stored manifest that vouches for *node_id* fixes the
    entity_uri. Returns None when *node_id* is genuinely unseen (first-contact TOFU).
    """
    with db() as conn:
        peer = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ? AND status = 'active' "
            "AND entity_uri IS NOT NULL AND entity_uri != ''",
            (node_id,),
        ).fetchone()
        if peer is not None and (peer["entity_uri"] or "").strip():
            return str(peer["entity_uri"])

        # No approved peer binding — scan stored manifests for one vouching for node_id.
        rows = conn.execute(
            "SELECT entity_uri, manifest_json FROM federation_manifests"
        ).fetchall()
    import json as _json

    for row in rows:
        m = None
        with contextlib.suppress(Exception):  # a malformed stored manifest cannot vouch
            m = manifest_from_dict(_json.loads(row["manifest_json"]))
        if m is not None and node_id in m.entities:
            return str(row["entity_uri"])
    return None


def _fetch_relay_manifest(entity_uri: str) -> OrgManifest | None:
    """Fetch + self-verify the origin's manifest from *entity_uri*, HTTPS-ONLY.

    Distinct from ``trust_store._try_fetch_manifest`` (which allows http) because the
    relay path resolves an attacker-CHOSEN entity_uri carried on the wire: it could
    point at an internal host or a plaintext endpoint. We therefore enforce
    ``assert_safe_url`` with ``allow_schemes={"https"}`` and ``follow_redirects=False``.
    The loopback-dev exception mirrors the 2a approval-time fetch: the SSRF/scheme guard
    is skipped ONLY under the conjunction ``federation_insecure AND a literal loopback
    host`` so a loopback dev cluster can still relay-resolve.
    """
    if not (entity_uri.startswith("https://") or entity_uri.startswith("http://")):
        return None  # cannot derive a fetch URL from a non-HTTP entity_uri
    parsed = urlparse(entity_uri)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        loopback_dev = settings.federation_insecure and node_url_is_loopback(base_url)
        if not loopback_dev:
            # HTTPS-ONLY: a wire-carried entity_uri must be https in production.
            assert_safe_url(base_url, allow_schemes=frozenset({"https"}))
        resp = httpx.get(
            f"{base_url}/.well-known/stigmem-manifest.json",
            timeout=10.0,
            follow_redirects=False,
        )
        if resp.status_code != 200:
            return None
        manifest = manifest_from_dict(resp.json())
        verify_manifest(manifest, trust_mode=settings.trust_mode)
        return manifest
    except Exception as exc:
        logger.debug("relay manifest fetch failed for %s: %s", entity_uri, exc)
        return None


def resolve_origin_key_for_relay(
    node_id: str,
    entity_uri: str,
    *,
    cache: dict[str, set[str]],
) -> set[str]:
    """Resolve the signing key set for a RELAYED origin (fetch-on-first).

    Resolution order (fail-closed at every step):

    1. **Peer path first.** If *node_id* is already a bound, active peer,
       ``resolve_origin_key(node_id)`` resolves it with NO network fetch.
    2. **Fetch-on-first.** Otherwise FETCH the origin's manifest from *entity_uri*
       (HTTPS-only, ``_fetch_relay_manifest``), verify its self-signature + expiry +
       rotation chain (``verify_manifest`` inside the fetch), and require
       ``node_id ∈ manifest.entities`` (the manifest must vouch for the node).
    3. **Entity-authority / uniqueness.** If *node_id* is ALREADY bound locally to a
       DIFFERENT entity_uri, REJECT — a registered-but-hostile org cannot vouch for a
       node_id owned by a different entity (anti-substitution). For a never-seen
       node_id this is first-contact TOFU: accept, store the manifest, and emit a
       ``relay_origin_first_contact`` audit event so an operator sees the new origin.

    *cache* is a per-request dict threaded through the page loop, keyed by *entity_uri*
    → verified key set, so the fetch + rotation check happen ONCE per page rather than
    once per fact. It MUST be a local threaded through calls — a module-level global
    would persist a stale binding across requests and defeat rotation/revocation.

    Returns ``{current_key} ∪ rotation-window keys`` (same shape as
    ``resolve_origin_key``). Raises OriginIdentityError on any failure.
    """
    # 1. Peer path: an already-bound active peer resolves without any fetch.
    try:
        return resolve_origin_key(node_id)
    except OriginIdentityError:
        pass

    if not (entity_uri or "").strip():
        raise OriginIdentityError(f"relayed origin {node_id!r} carries no entity_uri")

    # Cache hit: this entity_uri was already fetched + verified earlier this page.
    cached = cache.get(entity_uri)
    if cached is not None:
        return cached

    # 3a. Entity-authority uniqueness: enforce BEFORE the fetch so a hostile manifest
    # cannot even be fetched/stored under a node_id owned by a different entity.
    existing = _existing_entity_uri_for_node(node_id)
    if existing is not None and existing != entity_uri:
        raise OriginIdentityError(
            f"node_id {node_id!r} already bound to entity_uri {existing!r}; "
            f"a relayed manifest from {entity_uri!r} may not re-claim it"
        )

    # 2. Fetch-on-first: pull + verify the origin's manifest from its entity_uri.
    manifest = _fetch_relay_manifest(entity_uri)
    if manifest is None:
        raise OriginIdentityError(
            f"could not fetch/verify relay origin manifest from {entity_uri!r}"
        )
    if node_id not in manifest.entities:
        raise OriginIdentityError(
            f"relay origin manifest {entity_uri!r} does not list node_id {node_id!r}"
        )

    keys = _keys_from_manifest(manifest)

    # First-contact TOFU bind: persist the manifest + emit an audit event so the new
    # (node_id, entity_uri) origin is operator-visible. Best-effort store/audit must
    # not block a verified resolution.
    is_first_contact = existing is None
    try:
        store_peer_manifest(entity_uri, manifest, trust_mode=settings.trust_mode)
    except ManifestError as exc:
        logger.debug("relay first-contact manifest store rejected for %s: %s", entity_uri, exc)
    if is_first_contact:
        from ..observability.audit_event import emit_nofail

        emit_nofail(
            "relay_origin_first_contact",
            entity_uri=entity_uri,
            source="federation_relay",
            detail={"node_id": node_id, "entity_uri": entity_uri},
        )

    cache[entity_uri] = keys
    return keys
