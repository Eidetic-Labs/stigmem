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
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse, urlsplit, urlunsplit

import httpx

from ..db import db
from ..identity.manifest import (
    ManifestError,
    OrgManifest,
    manifest_from_dict,
    verify_manifest,
)
from ..identity.trust_store import get_peer_manifest, store_peer_manifest
from ..net_util import resolve_pinned_address
from ..settings import settings
from .origin_pins import fingerprint_from_pubkey, get_origin_pin

if TYPE_CHECKING:
    # Type-only import of the DNSSEC resolver Protocol (Rev 6 I11): never imported
    # at runtime, so importing this module on a default node loads no DNSSEC code.
    from .dnssec.resolver import Resolver

logger = logging.getLogger("stigmem.federation.origin_identity")


class OriginIdentityError(ValueError):
    """Origin identity could not be verified (fail-closed)."""


def _now() -> datetime:
    """Current UTC time. Indirected through a module function so tests own the clock."""
    return datetime.now(UTC)


def _make_dnssec_resolver() -> Resolver:
    """Construct the DNSSEC validating resolver for the first-trust tier (Rev 6 I11).

    Indirected through a module function so (a) the dnspython-backed
    ``LiveResolver`` is imported ONLY here, function-locally, on the flag-on path
    — importing this module on a default node never loads the ``[federation-dnssec]``
    extra (I11) — and (b) tests can inject an offline ``FixtureResolver`` by
    patching this single seam.
    """
    from .dnssec.resolver import LiveResolver

    return LiveResolver()


def _dnssec_first_trust_keys(
    conn: Any,
    *,
    node_id: str,
    entity_uri: str,
    candidate: OrgManifest | None,
    candidate_fp: str | None,
    relay_peer: str | None,
) -> set[str] | None:
    """Phase-3 DNSSEC first-trust tier at the relay fail-closed terminals (Rev 6).

    Strictly ADDITIVE at ``relay_origin_unanchored`` (I8): reached only after
    operator-pin -> stored-binding -> fetch-on-first TOFU have all declined and the
    origin is unknown + unreachable. Gated on ``federation_dnssec_trust_enabled``;
    when the flag is OFF this is a no-op (returns None) and the caller raises the
    unchanged ``relay_origin_unanchored`` — byte-identical to today, with no ladder
    call and no DNSSEC resolver constructed.

    When ON, the disposition depends on whether a candidate key exists:

      * **No candidate key** (``candidate is None`` — the no-candidate terminal):
        the DNSSEC record binds ``entity_uri -> fingerprint`` but yields NO key
        BYTES, and a relayed fact cannot be signature-verified without the key.
        The DNSSEC tier can therefore neither anchor (no bytes to return) nor
        route-to-confirm (no candidate fingerprint to quarantine) a key that does
        not exist. The terminal stays fail-closed — but it is now FLAG-AWARE
        (consulted + short-circuited here, never silently bypassed), satisfying
        plan TB-2. Returns None -> the caller raises ``relay_origin_unanchored``.

      * **Candidate exists** (the candidate-exists terminal): run the first-trust
        ladder against the candidate's fingerprint.
          - TRUSTED   -> the ladder validated + pinned the binding, BUT a relayed
            DNSSEC key is honored only after the I5 recency/revocation re-check,
            which is build-phase 3c. Call the ``recheck`` seam BEFORE returning a
            key; in 3b it raises ``RecheckNotImplemented`` -> fail-closed (plan
            TB-4: a 3b node cannot honor a DNSSEC first-trust key with no
            revocation path, even with the flag flipped on). 3c will make TRUSTED
            return the verified key set.
          - PENDING_CONFIRM -> the ladder quarantined the binding; the fact cannot
            be trusted until an operator confirms the fingerprint out-of-band.
            Raise (operator-confirm pending).
          - REJECTED  -> raise (revoked / rollback / bogus / unvalidatable / queue
            full — every reject branch of the I10 outcome lattice).

    Raises ``OriginIdentityError`` on any non-trust verdict (or the 3b recheck
    fail-closed). Returns the verified key set ONLY when a future 3c recheck
    succeeds; in 3b it never returns a key set.
    """
    if not settings.federation_dnssec_trust_enabled:
        return None  # flag OFF — no ladder, no resolver; caller fails closed as today

    from .dnssec.ladder import TrustDecision, resolve_first_trust
    from .dnssec.recheck import RecheckNotImplemented, recheck_relay_binding

    if candidate is None or not candidate_fp:
        # No-candidate terminal: no key bytes exist to anchor, no candidate fpr to
        # confirm. DNSSEC cannot help here (it binds a fingerprint, never key
        # bytes). Flag-aware fail-closed (TB-2): the caller raises unanchored.
        return None

    from .dnssec.host import host_from_entity_uri

    host = host_from_entity_uri(entity_uri)
    _audit_relay(
        "relay_origin_dnssec_first_trust_attempt",
        node_id=node_id,
        entity_uri=entity_uri,
        detail_host=host or "",
    )

    decision = resolve_first_trust(
        conn,
        entity_uri=entity_uri,
        node_id=node_id,
        candidate_key_fpr=candidate_fp,
        resolver=_make_dnssec_resolver(),
        settings=settings,
        now=_now(),
        relay_peer=relay_peer,
        source="relay",
    )

    if decision.outcome is TrustDecision.Outcome.TRUSTED:
        # TB-4 / I5: a relayed DNSSEC key is not honored without the 3c recency
        # re-check. The seam raises RecheckNotImplemented in 3b; map it to the
        # fail-closed ``OriginIdentityError`` the relay caller already handles, so a
        # 3b node refuses the key (with the validated pin persisted for 3c). The
        # ladder already committed the pin via ``conn``; commit again is harmless.
        try:
            recheck_relay_binding(
                conn,
                host=host or "",
                entity_uri=entity_uri,
                node_id=node_id,
                key_fpr=candidate_fp,
                resolver=_make_dnssec_resolver(),
                settings=settings,
                now=_now(),
            )
        except RecheckNotImplemented as exc:
            if conn is not None:
                conn.commit()  # persist the ladder's validated pin for the 3c re-check
            raise OriginIdentityError(
                f"relayed origin {node_id!r} ({entity_uri!r}) dnssec-trusted but the "
                f"relay-path recency re-check is not yet wired (3c); failing closed"
            ) from exc
        # 3c only: reached after a successful re-check.
        keys = _keys_from_manifest(candidate)
        return keys

    if decision.outcome is TrustDecision.Outcome.PENDING_CONFIRM:
        # The ladder quarantined the binding on ``conn`` (the operator-confirm
        # queue, I9). Commit BEFORE raising so the queue row survives — otherwise
        # the caller's ``with db()`` block rolls it back when this raise unwinds.
        if conn is not None:
            conn.commit()
        raise OriginIdentityError(
            f"relayed origin {node_id!r} ({entity_uri!r}) pending operator confirmation "
            f"({decision.reason})"
        )

    # REJECTED (revoked / rollback / bogus / unvalidatable / queue full). The ladder
    # may have stamped epoch/sticky markers on ``conn``; commit them before raising.
    if conn is not None:
        conn.commit()
    raise OriginIdentityError(
        f"relayed origin {node_id!r} ({entity_uri!r}) rejected by dnssec first-trust "
        f"({decision.reason})"
    )


def _prior_key_within_grace(rotated_at: str) -> bool:
    """True iff a rotation at *rotated_at* is still inside the configured grace window.

    Fail-closed: a missing/unparseable/future ``rotated_at`` (or any age beyond the
    grace) returns False, so the prior key is DROPPED rather than trusted indefinitely.
    """
    grace = timedelta(hours=settings.federation_key_rotation_grace_hours)
    try:
        rotated = datetime.fromisoformat((rotated_at or "").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False  # indeterminate age ⇒ fail closed on the prior key
    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=UTC)
    return _now() - rotated <= grace


def _keys_from_manifest(manifest: OrgManifest) -> set[str]:
    """Current key plus the prior key — but ONLY while inside the rotation grace window.

    The current ``public_key`` is ALWAYS accepted. The prior (retiring) key from the
    most recent rotation event is accepted as a dual-trust key ONLY while
    ``now - rotated_at <= federation_key_rotation_grace_hours``; once that window
    elapses the retired key is dropped, so a stale/compromised prior key can no longer
    forge origin signatures (direct or relayed). Fail-closed on an unparseable
    ``rotated_at`` (see ``_prior_key_within_grace``).
    """
    keys = {manifest.public_key}
    if manifest.rotation_events:
        last = manifest.rotation_events[-1]
        if last.previous_public_key and _prior_key_within_grace(last.rotated_at):
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
    """Fetch + self-verify the origin's manifest from *entity_uri*, HTTPS-ONLY + pinned.

    This resolves an attacker-CHOSEN entity_uri carried on the wire, so it is the
    sharpest SSRF surface: the host could point at an internal/IMDS address or a
    plaintext endpoint, and could DNS-rebind between validation and connect. We close
    that with the R-5 / F-SSRF1 anti-rebind pin (``resolve_pinned_address``, https-only
    — rejecting the whole URL on any private record or non-https scheme) resolved BEFORE
    the client is opened, connecting to the EXACT pinned IP while preserving the ``Host``
    header + TLS SNI, ``follow_redirects=False``. This matches the now-pinned trust_store
    sibling ``_try_fetch_manifest`` (which is also https-only after R-5's F-SSRF2 change).
    The dev bypass is ``federation_insecure`` alone, matching the recurring-pull path.
    """
    if not (entity_uri.startswith("https://") or entity_uri.startswith("http://")):
        return None  # cannot derive a fetch URL from a non-HTTP entity_uri
    parsed = urlparse(entity_uri)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        resp = _pinned_relay_manifest_get(
            f"{base_url}/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=settings.federation_insecure,
        )
        if resp.status_code != 200:
            return None
        manifest = manifest_from_dict(resp.json())
        verify_manifest(manifest, trust_mode=settings.trust_mode)
        return manifest
    except Exception as exc:
        logger.debug("relay manifest fetch failed for %s: %s", entity_uri, exc)
        return None


def _pinned_relay_manifest_get(
    url: str,
    *,
    timeout: float,
    skip_pin: bool,
) -> httpx.Response:
    """GET *url* with the a11 anti-rebind DNS pin (R-5 / F-SSRF1), unless *skip_pin*.

    Synchronous sibling of ``federation_pull._pinned_get`` /
    ``trust_store._pinned_manifest_get``. Resolves the host ONCE via
    ``resolve_pinned_address`` (https-only) BEFORE opening the client, connecting to the
    EXACT pinned IP literal with ``Host`` header + TLS SNI + cert verification preserved
    against the original hostname and ``follow_redirects=False``. A blocked/rebind/non-
    https target fails closed (``ValueError``) with no request issued. Under *skip_pin*
    (``federation_insecure``) the original-hostname URL is passed through unpinned.
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


def _audit_relay(event_type: str, *, node_id: str, entity_uri: str, **detail: object) -> None:
    """Best-effort relay-origin audit emit (never blocks resolution)."""
    from ..observability.audit_event import emit_nofail

    emit_nofail(
        event_type,
        entity_uri=entity_uri,
        source="federation_relay",
        detail={"node_id": node_id, "entity_uri": entity_uri, **detail},
    )


def _candidate_manifest_from_carried(
    origin_manifest: dict[str, object] | None,
) -> OrgManifest | None:
    """Parse + self-verify a CARRIED origin manifest body, or return None if unusable.

    The carried manifest is OPTIONAL and is only a manifest BODY — parsing + self-sig
    verification here is the same W3.2 self-verify gate the fetch path applies; it does
    NOT confer trust (that requires a first-party anchor match in the tier logic).
    """
    if not isinstance(origin_manifest, dict):
        return None
    try:
        m = manifest_from_dict(origin_manifest)
        verify_manifest(m, trust_mode=settings.trust_mode)
        return m
    except Exception as exc:  # noqa: BLE001 — a malformed/invalid body is simply unusable
        logger.debug("carried relay origin manifest unusable: %s", exc)
        return None


def resolve_origin_key_for_relay(
    node_id: str,
    entity_uri: str,
    *,
    cache: dict[tuple[str, str], set[str]],
    origin_manifest: dict[str, object] | None = None,
) -> set[str]:
    """Resolve the signing key set for a RELAYED origin (offline-safe, zero transitive trust).

    Precedence (fail-closed at every step):

    1. **Peer path** — if the origin is an active bound peer, ``resolve_origin_key`` resolves
       it with NO fetch (a first-party verified 2a binding, the highest tier).
    2. **Candidate manifest** — obtain a candidate from: a fetch-on-first (HTTPS-only,
       ``fetched`` — may be None if unreachable), the carried ``origin_manifest`` body, or a
       stored manifest for ``entity_uri``. The candidate MUST pass the W3.2 checks (self-sig,
       ``node_id ∈ entities``, entity-authority/uniqueness) before ANY acceptance.
    3. **Anchor + cross-check** (the offline core, by descending anchor strength):

       * **Tier 1 — operator pin** (W4.1 ``get_origin_pin``): the candidate fingerprint MUST
         equal the pin, ELSE reject (``relay_origin_pin_mismatch``). If the origin is also
         REACHABLE (``fetched`` not None) the fetched key must ALSO equal the pin, ELSE reject
         (``relay_origin_fetch_disagrees_pin`` — a reachable fetch that disagrees with the human
         anchor is a MITM/compromise signal). On match → accept.
       * **Tier 2 — stored binding** (``get_peer_manifest``): the candidate fingerprint MUST
         equal the stored manifest's key, ELSE reject (``relay_origin_key_changed`` — never a
         silent key update). On match → accept.
       * **Tier 3 — fetch-on-first TOFU**: reachable, never-seen, unpinned — the EXISTING W3.2
         behaviour: store the manifest + emit ``relay_origin_first_contact`` + accept.
       * **Fail-closed**: no pin, no stored binding, not reachable → raise
         (``relay_origin_unanchored``). The unknown-AND-unreachable case is correctly refused.

    *cache* is a per-request dict threaded through the page loop, keyed by the
    ``(entity_uri, node_id)`` PAIR → verified key set, so the fetch + rotation check happen
    ONCE per (origin, node) rather than once per fact. The key MUST include ``node_id``:
    every check after the cache short-circuit (entity-authority/uniqueness, ``node_id ∈
    entities``, the operator-pin lookup) is node_id-scoped, so an ``entity_uri``-only key
    would let a SECOND node_id carried with the same ``entity_uri`` inherit the first one's
    key set and bypass those checks (entity-authority + per-node pin bypass). It MUST be a
    local threaded through calls — a module-level global would persist a stale binding
    across requests and defeat rotation/revocation.

    Returns ``{current_key} ∪ rotation-window keys`` (same shape as
    ``resolve_origin_key``). Raises OriginIdentityError on any failure.
    """
    # 1. Peer path: an already-bound active peer resolves without any fetch.
    try:
        return resolve_origin_key(node_id)
    except OriginIdentityError:
        # Not an already-bound peer — fall through to the relay-resolution path below.
        pass

    if not (entity_uri or "").strip():
        raise OriginIdentityError(f"relayed origin {node_id!r} carries no entity_uri")

    # Cache hit: this (entity_uri, node_id) pair was already anchored + verified earlier
    # this page. Keyed on the PAIR — see the node_id-scoped-checks note in the docstring.
    cached = cache.get((entity_uri, node_id))
    if cached is not None:
        return cached

    # Entity-authority uniqueness: enforce BEFORE anything else so a hostile manifest
    # cannot be considered under a node_id owned by a different entity.
    existing = _existing_entity_uri_for_node(node_id)
    if existing is not None and existing != entity_uri:
        raise OriginIdentityError(
            f"node_id {node_id!r} already bound to entity_uri {existing!r}; "
            f"a relayed manifest from {entity_uri!r} may not re-claim it"
        )

    # 2. Obtain a CANDIDATE manifest. Try a fetch-on-first (https-only; None if unreachable);
    # the fetched manifest, if any, doubles as the strongest candidate AND the reachable
    # cross-check key for tier 1. Else fall back to the carried body, else a stored manifest.
    fetched = _fetch_relay_manifest(entity_uri)
    candidate = (
        fetched
        or _candidate_manifest_from_carried(origin_manifest)
        or get_peer_manifest(entity_uri, refresh_if_expired=False, trust_mode=settings.trust_mode)
    )
    if candidate is None:
        # No candidate from any source AND no stored binding ⇒ unknown + unreachable.
        # Phase-3 DNSSEC first-trust (flag-gated, strictly additive at this terminal,
        # Rev 6 I8 / plan TB-2). With NO candidate key bytes the DNSSEC tier can
        # neither anchor (it yields a fingerprint, never key bytes) nor route-to-
        # confirm (no candidate fpr to quarantine), so it short-circuits to None and
        # this terminal stays fail-closed — but it is now flag-AWARE (consulted here,
        # never silently bypassed). When the flag is OFF this is a no-op.
        dnssec_keys = _dnssec_first_trust_keys(
            None,
            node_id=node_id,
            entity_uri=entity_uri,
            candidate=None,
            candidate_fp=None,
            relay_peer=None,
        )
        if dnssec_keys is not None:  # 3c only; in 3b this branch is unreachable.
            cache[(entity_uri, node_id)] = dnssec_keys
            return dnssec_keys
        _audit_relay("relay_origin_unanchored", node_id=node_id, entity_uri=entity_uri)
        raise OriginIdentityError(
            f"relayed origin {node_id!r} ({entity_uri!r}) is unanchored and unreachable"
        )

    # 3. W3.2 self-verify gate: the candidate must vouch for node_id. (verify_manifest already
    # ran on the fetch/carried/stored paths; node_id ∈ entities is the remaining W3.2 check.)
    if node_id not in candidate.entities:
        raise OriginIdentityError(
            f"relay origin manifest {entity_uri!r} does not list node_id {node_id!r}"
        )

    candidate_fp = fingerprint_from_pubkey(candidate.public_key)

    # 4. ANCHOR + CROSS-CHECK, by descending anchor strength.
    with db() as conn:
        pin = get_origin_pin(conn, entity_uri=entity_uri, node_id=node_id)

    if pin is not None:
        # Tier 1 — operator pin (human anchor). Two checks, both required:
        # Cross-check FIRST: a REACHABLE fetch that disagrees with the pin is a MITM /
        # compromise signal (the live endpoint serves a key the operator never confirmed).
        # This is the strongest attack signal, so it is reported ahead of a stale candidate.
        if fetched is not None and fingerprint_from_pubkey(fetched.public_key) != pin[
            "key_fingerprint"
        ]:
            _audit_relay(
                "relay_origin_fetch_disagrees_pin", node_id=node_id, entity_uri=entity_uri
            )
            raise OriginIdentityError(
                f"relayed origin {node_id!r} reachable fetch disagrees with the operator pin"
            )
        # The candidate (fetched / carried / stored) MUST itself match the pin.
        if candidate_fp != pin["key_fingerprint"]:
            _audit_relay("relay_origin_pin_mismatch", node_id=node_id, entity_uri=entity_uri)
            raise OriginIdentityError(
                f"relayed origin {node_id!r} candidate key does not match the operator pin"
            )
        keys = _keys_from_manifest(candidate)
        cache[(entity_uri, node_id)] = keys
        return keys

    stored = get_peer_manifest(
        entity_uri, refresh_if_expired=False, trust_mode=settings.trust_mode
    )
    if stored is not None:
        # Tier 2 — stored first-party binding. The candidate MUST match the stored key.
        if candidate_fp != fingerprint_from_pubkey(stored.public_key):
            _audit_relay("relay_origin_key_changed", node_id=node_id, entity_uri=entity_uri)
            raise OriginIdentityError(
                f"relayed origin {node_id!r} candidate key differs from the stored binding"
            )
        keys = _keys_from_manifest(candidate)
        cache[(entity_uri, node_id)] = keys
        return keys

    if fetched is not None:
        # Tier 3 — fetch-on-first TOFU (reachable, never-seen, unpinned): the EXISTING W3.2
        # first-contact behaviour. Persist the manifest + emit the first-contact audit.
        try:
            store_peer_manifest(entity_uri, fetched, trust_mode=settings.trust_mode)
        except ManifestError as exc:
            logger.debug("relay first-contact manifest store rejected for %s: %s", entity_uri, exc)
        _audit_relay("relay_origin_first_contact", node_id=node_id, entity_uri=entity_uri)
        keys = _keys_from_manifest(fetched)
        cache[(entity_uri, node_id)] = keys
        return keys

    # Phase-3 DNSSEC first-trust (flag-gated, strictly additive at this terminal,
    # Rev 6 I8 / plan TB-2). A candidate self-verified + lists node_id (the W3.2
    # gate above passed) but there is no pin, no stored binding, and the origin is
    # unreachable. The DNSSEC tier runs the first-trust ladder against the
    # candidate's fingerprint. It writes (pins / epoch / quarantine), so it owns a
    # live transaction here. When the flag is OFF this is a no-op and the unchanged
    # ``relay_origin_unanchored`` raise below fires (byte-identical to today).
    with db() as conn:
        dnssec_keys = _dnssec_first_trust_keys(
            conn,
            node_id=node_id,
            entity_uri=entity_uri,
            candidate=candidate,
            candidate_fp=candidate_fp,
            relay_peer=None,
        )
        if dnssec_keys is not None:  # 3c only; in 3b TRUSTED fails closed at recheck.
            conn.commit()
            cache[(entity_uri, node_id)] = dnssec_keys
            return dnssec_keys
        # The ladder may have pinned/quarantined as a side effect even on a verdict
        # that does not yield a key here (e.g. PENDING_CONFIRM raises before this
        # point). On the flag-OFF no-op path there is nothing to commit; commit is
        # harmless and persists any quarantine row written before a raise is caught
        # upstream. (Reached only when _dnssec_first_trust_keys returned None.)
        conn.commit()

    # Fail-closed: a candidate existed (carried/stored) but there is no pin, no stored binding,
    # and the origin is unreachable ⇒ no first-party anchor to accept it against.
    _audit_relay("relay_origin_unanchored", node_id=node_id, entity_uri=entity_uri)
    raise OriginIdentityError(
        f"relayed origin {node_id!r} ({entity_uri!r}) is unanchored and unreachable"
    )
