"""Pull replication background task (spec §6.3).

The pull loop runs as an asyncio task in the app lifespan.
It is also callable directly for testing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..db import db
from ..models.constants import VALID_SCOPES
from ..net_util import resolve_pinned_address
from ..observability.metrics import FEDERATION_INGRESS, REPLICATION_LAG
from ..settings import settings
from .federation_ingest import (
    FederationIntegrityError,
    ingest_fact,
    write_audit_log,
)
from .origin_identity import (
    OriginIdentityError,
    resolve_origin_key,
    resolve_origin_key_for_relay,
)
from .origin_signature import OriginSignatureError, verify_origin_signature
from .peer_policy import (
    PeerPolicyError,
    resolve_ingest_tenant_for_peer,
    resolve_origin_tenant_for_peer,
)
from .peer_token import create_peer_token
from .tls import check_peer_san

logger = logging.getLogger("stigmem.federation.pull")

_MAX_BACKOFF_S = 300.0  # 5 minutes
_BASE_BACKOFF_S = 1.0


def _jitter(base: float) -> float:
    return base * (1 + random.uniform(-0.2, 0.2))  # noqa: S311  # nosec B311 — retry jitter, not crypto


def _build_pinned_request(url: str, pinned_ip: str) -> tuple[str, str]:
    """Return ``(pinned_url, host_header)`` for connecting to *pinned_ip*.

    Mirrors ``subscription_delivery._build_pinned_request`` (the a11 webhook pin):
    swap the original hostname for the validated *pinned_ip* literal (IPv6 bracketed)
    while preserving scheme/port/path/query, so the socket connects to the pinned IP
    and cannot be re-resolved by a rebinder. ``host_header`` carries the ORIGINAL
    hostname (+ explicit port). The caller also passes
    ``extensions={"sni_hostname": <hostname>}`` so TLS SNI + cert verification run
    against the original hostname, NOT the IP literal.
    """
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
    return pinned_url, host_header


async def _pinned_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> Any:
    """Issue ``client.get`` against *url* with the a11 anti-rebind DNS pin (R-5 / F-SSRF1).

    The recurring federation pull fetches re-resolve a peer-controlled ``node_url`` on a
    loop; without pinning, a peer can pass approval-time validation and then DNS-rebind
    the host to an internal address (IMDS / RFC1918) for these fetches. We resolve the
    host ONCE (``resolve_pinned_address``, https-only by default — rejects the whole URL
    if ANY resolved record is private), connect to that EXACT pinned IP literal, and
    preserve the ``Host`` header + TLS SNI + cert verification against the original
    hostname (async adaptation of the webhook ``_build_pinned_request`` shape).

    Dev bypass (TA-6): the pin is SKIPPED whenever ``federation_insecure`` is set —
    the dev/test escape for the RECURRING federation fetch, matching the registration
    well-known fetch guard (NF-2, ``_federation_impl.register_peer_impl``), which is
    gated on ``federation_insecure`` ALONE (not flag+loopback). This is deliberately
    broader than the approval-time manifest fetch's ``federation_insecure AND loopback``
    conjunction: a loopback dev cluster IS the primary case, but the federation test
    suite also drives this path with fake in-process clients whose peer ``node_url`` is
    a NON-loopback, non-resolving placeholder (e.g. ``http://relay-b``). Gating on the
    loopback conjunction alone would pin+resolve those placeholders and break the suite.
    Under the skip, the original-hostname URL is passed straight through with no pin
    extensions (preserving today's exact call shape). In production
    (``federation_insecure`` off) the pin is ALWAYS enforced.
    """
    if settings.federation_insecure:
        return await client.get(url, params=params, headers=headers, timeout=timeout)

    # Pin: resolve once, reject private/rebind targets, connect to the pinned IP.
    # https-only matches the production federation transport (peer URLs are https).
    pinned_ip = resolve_pinned_address(url, allow_schemes=frozenset({"https"}))
    pinned_url, host_header = _build_pinned_request(url, pinned_ip)
    hostname = urlsplit(url).hostname or ""
    merged_headers = dict(headers or {})
    merged_headers["Host"] = host_header
    return await client.get(
        pinned_url,
        params=params,
        headers=merged_headers,
        timeout=timeout,
        extensions={"sni_hostname": hostname},
    )


def load_cursor(peer_id: str) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT cursor FROM replication_cursors WHERE peer_id = ? AND direction = 'inbound'",
            (peer_id,),
        ).fetchone()
    return row["cursor"] if row else None


def save_cursor(peer_id: str, cursor: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO replication_cursors (peer_id, direction, cursor, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(peer_id, direction)
               DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at""",
            (peer_id, "inbound", cursor, datetime.now(UTC).isoformat()),
        )


async def pull_from_peer_once(
    peer: dict[str, Any],
    client: httpx.AsyncClient,
    cursor: str | None,
) -> str | None:
    """Pull one page of facts from the peer. Returns the new cursor (or same if no more)."""
    allowed_scopes: list[str] = json.loads(peer["allowed_scopes"])
    token = create_peer_token(peer["node_id"], allowed_scopes)

    params: dict[str, Any] = {"limit": 100}
    if cursor:
        params["cursor"] = cursor

    backoff = _BASE_BACKOFF_S
    while True:
        try:
            resp = await _pinned_get(
                client,
                f"{peer['node_url']}/v1/federation/facts",
                params=params,
                headers={"Authorization": f"Bearer {token}", "Stigmem-Verify": "full"},
                timeout=30.0,
            )
        except ValueError as exc:
            # Anti-rebind pin refused the peer's node_url at FETCH time (R-5 / F-SSRF1):
            # the host resolved to a private/internal/IMDS address. Fail closed — retain
            # the old cursor; an unsafe address can never become safe by retrying.
            logger.warning(
                "Pull from %s blocked: unsafe node_url (%s)", peer["node_id"], exc
            )
            return cursor
        except httpx.RequestError as exc:
            logger.warning("Pull network error from %s: %s", peer["node_id"], exc)
            return cursor  # retain old cursor; will retry next cycle

        if resp.status_code == 429:
            backoff = min(backoff * 2, _MAX_BACKOFF_S)
            delay = _jitter(backoff)
            logger.info("429 from %s — backing off %.1fs", peer["node_id"], delay)
            await asyncio.sleep(delay)
            token = create_peer_token(peer["node_id"], allowed_scopes)  # refresh token after sleep
            continue

        if resp.status_code != 200:
            logger.warning("Pull from %s returned %s", peer["node_id"], resp.status_code)
            return cursor

        # §22.1.2.4 — validate server cert URI SAN before consuming any data.
        if settings.mtls_enabled:
            ssl_obj = resp.extensions.get("ssl_object")
            peer_cert: dict[str, Any] = ssl_obj.getpeercert() if ssl_obj is not None else {}
            if peer_cert and not check_peer_san(peer_cert, peer["node_id"]):
                logger.warning(
                    "Client-side SAN mismatch from peer %s — cert URI SAN does not "
                    "match node_id; discarding response",
                    peer["node_id"],
                )
                write_audit_log(
                    peer["node_id"],
                    "san_mismatch",
                    {"peer_node_id": peer["node_id"], "direction": "pull"},
                )
                return cursor  # fail-closed: no data ingested from identity-mismatched peer
            if not peer_cert:
                logger.warning(
                    "mTLS peer certificate from %s was not exposed by httpx; "
                    "falling back to TLS-layer certificate verification",
                    peer["node_id"],
                )

        data = resp.json()

        # F-FED-2b: clean break — only the v2 signed-origin envelope is consumed
        # (no v1 interop). A non-v2 page is dropped wholesale; advance no cursor.
        if data.get("v") != 2:
            logger.warning(
                "Pull from %s returned non-v2 envelope (v=%r); dropping page",
                peer["node_id"],
                data.get("v"),
            )
            return cursor

        # §3.1 (Phase 2b rewrite): origin fields (origin_tenant, origin_allowed_scopes,
        # origin_allowed_tenants, origin_node_id) now arrive ON THE WIRE rather than being
        # derived from the local peer registry. This is safe because each entry carries an
        # origin signature that is cryptographically verified below — trust in these fields
        # moved from "registry-derived (the receiver guesses)" to "verified (the origin
        # asserts and signs)". The per-fact ordered checks mirror the push path exactly:
        # cid → origin==sender → resolve key → verify sig → scope-in-grant → resolve tenant.
        sender_node_id = peer["node_id"]
        # F-FED-2c W3.2: per-PAGE relay key cache, threaded into resolve_origin_key_for_relay
        # so a relayed-origin manifest fetch + rotation check runs once per page, not per
        # fact. A local (not a module global) so no stale binding persists across pages.
        relay_cache: dict[tuple[str, str], set[str]] = {}
        relay_enabled = settings.federation_relay_enabled
        try:
            sender_relay_trusted = bool(peer["relay_trusted"])
        except (KeyError, IndexError, TypeError):
            sender_relay_trusted = bool(dict(peer).get("relay_trusted"))
        ingested = 0
        for entry in data.get("facts", []):
            if not isinstance(entry, dict):
                logger.warning("Pull from %s: malformed entry (not an object)", sender_node_id)
                continue
            fact = entry.get("fact")
            origin = entry.get("origin")
            origin_sig = entry.get("origin_sig")
            # W4.2: OPTIONAL carried origin manifest body — lets an unreachable receiver
            # anchor-match a relayed origin against its operator pin / stored binding.
            origin_manifest = entry.get("origin_manifest")
            if not isinstance(origin_manifest, dict):
                origin_manifest = None
            if not isinstance(fact, dict) or not isinstance(origin, dict) or not origin_sig:
                logger.warning(
                    "Pull from %s: entry missing fact/origin/origin_sig", sender_node_id
                )
                continue
            fact_scope = fact.get("scope", "")

            # 0. fact id present (later steps sign over / index by it)
            if not fact.get("id"):
                logger.warning("Pull from %s: skip fact (id_required)", sender_node_id)
                continue
            # 1. cid present
            if not fact.get("cid"):
                logger.warning("Pull from %s: skip fact (cid_required)", sender_node_id)
                continue
            # 2. origin node_id vs authenticated sender — direct (==) vs relayed (!=).
            #    F-FED-2c W3.2: relay OFF ⇒ origin==sender is mandatory (unchanged 2b).
            #    Relay ON ⇒ a relayed fact is admitted only if the SENDER peer is
            #    relay_trusted (fail-closed); the origin itself is independently verified
            #    below via the fetch-on-first resolver.
            is_relayed = origin.get("node_id") != sender_node_id
            if is_relayed:
                if not relay_enabled:
                    logger.warning("Pull from %s: skip fact (origin_not_sender)", sender_node_id)
                    continue
                if not sender_relay_trusted:
                    logger.warning(
                        "Pull from %s: skip relayed fact (relay_sender_not_trusted)",
                        sender_node_id,
                    )
                    continue
            # 3. resolve the origin's signing key set (regardless of trust_mode).
            #    Direct: 2a peer chain. Relayed: fetch-on-first from the signed entity_uri.
            try:
                if is_relayed:
                    keys = resolve_origin_key_for_relay(
                        origin["node_id"],
                        origin.get("entity_uri", ""),
                        cache=relay_cache,
                        origin_manifest=origin_manifest,
                    )
                else:
                    keys = resolve_origin_key(origin["node_id"])
            except OriginIdentityError as exc:
                logger.warning(
                    "Pull from %s: skip fact (origin_unresolvable): %s", sender_node_id, exc
                )
                continue
            # 4. verify origin signature
            try:
                verify_origin_signature(
                    origin_sig,
                    fact_id=fact["id"],
                    cid=fact["cid"],
                    origin=origin,
                    valid_until=fact.get("valid_until"),
                    allowed_pubkeys=keys,
                )
            except OriginSignatureError as exc:
                logger.warning(
                    "Pull from %s: skip fact (origin_sig_invalid): %s", sender_node_id, exc
                )
                continue
            # 5. fact scope must be inside the origin's granted scopes
            if fact_scope not in origin.get("allowed_scopes", []):
                logger.warning(
                    "Pull from %s: skip fact (scope_not_in_origin_grant)", sender_node_id
                )
                continue
            # 5a. fact scope must be a CANONICAL enum value (F-2c-MED-2). The origin-grant
            #     check above is satisfiable self-consistently by a malicious origin
            #     (scope="a_b" + allowed_scopes=["a_b"]), so validate against VALID_SCOPES
            #     fail-closed BEFORE ingest — a non-enum/wildcard scope can never be stored.
            if fact_scope not in VALID_SCOPES:
                logger.warning("Pull from %s: skip fact (invalid_scope)", sender_node_id)
                continue
            # 5b. origin.tenant must be inside the origin's OWN signed allowed_tenants
            #     (ingest/egress symmetry — F-2c-MED-1). The signed origin tuple binds both,
            #     so a relay can't forge them; the receiver ENFORCES the signed invariant
            #     fail-closed before mapping the tenant through this relay's tenant_map.
            if origin["tenant"] not in origin.get("allowed_tenants", []):
                logger.warning(
                    "Pull from %s: skip fact (tenant_not_in_origin_grant)", sender_node_id
                )
                continue
            # 6. resolve the wire-carried origin tenant to a local tenant (default-deny)
            try:
                with db() as conn:
                    local_tenant = resolve_origin_tenant_for_peer(peer, origin["tenant"], conn)
            except PeerPolicyError as exc:
                logger.warning(
                    "Pull from %s: skip fact (tenant policy unsafe): %s", sender_node_id, exc
                )
                write_audit_log(
                    sender_node_id,
                    "federation_tenant_policy_rejected",
                    {"reason": str(exc)},
                )
                continue
            # 7. ingest only after every check passed
            try:
                ingest_fact(
                    fact,
                    sender_node_id,
                    tenant_id=local_tenant,
                    origin_node_id=origin["node_id"],
                    origin_allowed_scopes=origin["allowed_scopes"],
                    origin_tenant=origin["tenant"],
                    origin_allowed_tenants=origin["allowed_tenants"],
                    origin_sig=origin_sig,
                    origin_entity_uri=origin["entity_uri"],
                )
            except FederationIntegrityError as exc:
                logger.warning(
                    "Rejected federated fact %s from %s: %s",
                    exc.fact_id,
                    sender_node_id,
                    exc.reason,
                )
                write_audit_log(
                    sender_node_id,
                    "federation_integrity_rejected",
                    {
                        "fact_id": exc.fact_id,
                        "reason": exc.reason,
                        "stored_cid": exc.stored_cid,
                        "computed_cid": exc.computed_cid,
                    },
                )
                continue
            ingested += 1

        if ingested:
            FEDERATION_INGRESS.labels(peer_id=peer["node_id"], status="ok").inc(ingested)

        new_cursor: str | None = data.get("cursor")

        # Replication-lag gauge: difference between now and the cursor HLC timestamp.
        # The HLC is an ISO timestamp string; if parsing fails we leave the gauge unchanged.
        try:
            if new_cursor:
                from datetime import UTC, datetime

                cursor_ts = datetime.fromisoformat(new_cursor.split("_")[0].replace("Z", "+00:00"))
                if cursor_ts.tzinfo is None:
                    cursor_ts = cursor_ts.replace(tzinfo=UTC)
                lag_s = max(0.0, (datetime.now(UTC) - cursor_ts).total_seconds())
                REPLICATION_LAG.labels(peer_id=peer["node_id"]).set(lag_s)
        except Exception as exc:  # noqa: BLE001  # nosec B110 — best-effort lag metric
            logger.debug("replication lag metric update failed: %s", exc)

        return new_cursor


def _make_pull_client() -> httpx.AsyncClient:
    """Return an httpx client configured for mTLS when STIGMEM_TLS_* are set."""
    if settings.mtls_enabled:
        from .tls import build_client_ssl_context

        ssl_ctx = build_client_ssl_context(
            settings.tls_cert_path,
            settings.tls_key_path,
            settings.tls_ca_bundle,
        )
        return httpx.AsyncClient(verify=ssl_ctx)
    return httpx.AsyncClient()


@dataclass(frozen=True)
class TombstoneEntryResult:
    """Outcome of verifying + applying ONE inbound tombstone envelope entry.

    ``applied`` is True iff the tombstone passed the full secure chain and
    ``apply_inbound_tombstone`` was invoked. ``reason`` is a stable machine code for
    the skip/reject cause (None on success). The PULL path logs + continues on a
    skip; the PUSH route maps ``reason`` to an HTTP status (W6.8) — the SINGLE shared
    code path means push and pull can never diverge on what they accept.
    """

    applied: bool
    reason: str | None = None


@dataclass(frozen=True)
class RevocationEntryResult:
    """Outcome of verifying + applying ONE inbound revocation envelope entry.

    ``applied`` is True iff the revocation passed the full secure chain and
    ``apply_inbound_revocation`` was invoked. ``reason`` is a stable machine code for the
    skip/reject cause (None on success). The PULL path logs + continues on a skip; the PUSH
    route maps ``reason`` to an HTTP status (Rev-3) — the SINGLE shared code path means push
    and pull can never diverge on what they accept. Mirrors :class:`TombstoneEntryResult`.
    """

    applied: bool
    reason: str | None = None


def ingest_tombstone_entry(
    *,
    entry: dict[str, Any],
    sender_node_id: str,
    peer: dict[str, Any],
    relay_enabled: bool,
    relay_trusted: bool,
    direct_tenant_id: str,
    relay_cache: dict[tuple[str, str], set[str]],
) -> TombstoneEntryResult:
    """Verify + apply ONE v2 tombstone envelope entry through the full secure chain.

    Extracted from ``pull_tombstones_from_peer_once`` (W6.8) so the PULL loop and the
    PUSH ingest route share ONE verify+apply path and can never diverge. The ordered
    chain mirrors the fact relay ingest exactly:

      parse entry → parse record → DIRECT (origin==sender) vs RELAYED (origin!=sender)
      → [relayed] relay ON + sender relay_trusted gate (fail-closed)
      → resolve origin key (direct: 2a peer chain; relayed: W4.2 secure relay resolver)
      → verify ORIGIN-attestation signature (anti-relaunder: scope is bound in the tuple)
      → verify ISSUER-signer signature (BOTH required)
      → [relayed] scope ∈ origin.allowed_scopes (ingest scope gate)
      → [relayed] resolve_origin_tenant_for_peer (default-deny)
      → apply_inbound_tombstone (relayed: + origin cols + received_from; direct: tenant only)

    Returns a :class:`TombstoneEntryResult`; never raises HTTPException (the push route
    owns the HTTP mapping). ``direct_tenant_id`` is the page-resolved ingest tenant used
    only on the DIRECT branch (relayed entries resolve their own tenant per-origin).
    """
    from ..lifecycle.tombstone_signing import (
        IssuerVerificationError,
        resolve_and_verify_tombstone_issuer,
        verify_tombstone_signature,
    )
    from ..lifecycle.tombstones import apply_inbound_tombstone
    from ..models.tombstones import TombstoneRecord
    from .origin_identity import (
        OriginIdentityError,
        resolve_origin_key,
        resolve_origin_key_for_relay,
    )
    from .origin_signature import (
        OriginSignatureError,
        verify_tombstone_origin_signature,
    )

    if not isinstance(entry, dict):
        return TombstoneEntryResult(False, "malformed_entry")
    tomb = entry.get("tombstone")
    origin = entry.get("origin")
    origin_sig = entry.get("origin_sig")
    if not isinstance(tomb, dict) or not isinstance(origin, dict) or not origin_sig:
        return TombstoneEntryResult(False, "missing_tombstone_origin_or_sig")
    try:
        record = TombstoneRecord(**tomb)
    except Exception as exc:
        logger.warning("Tombstone ingest from %s: malformed tombstone: %s", sender_node_id, exc)
        return TombstoneEntryResult(False, "malformed_tombstone")

    is_relayed = origin.get("node_id") != sender_node_id
    origin_manifest = entry.get("origin_manifest")
    if not isinstance(origin_manifest, dict):
        origin_manifest = None

    if is_relayed:
        if not relay_enabled:
            logger.warning(
                "Tombstone ingest from %s: skip relayed tombstone %s (origin_not_sender; "
                "relay disabled)",
                sender_node_id,
                record.id,
            )
            return TombstoneEntryResult(False, "origin_not_sender")
        if not relay_trusted:
            logger.warning(
                "Tombstone ingest from %s: skip relayed tombstone %s (relay_sender_not_trusted)",
                sender_node_id,
                record.id,
            )
            return TombstoneEntryResult(False, "relay_sender_not_trusted")

    # Resolve the ORIGIN's verified key set. Direct: 2a peer chain. Relayed: the W4.2
    # secure relay resolver (fetch-on-first / pin / stored / fail-closed).
    try:
        if is_relayed:
            keys = resolve_origin_key_for_relay(
                origin["node_id"],
                origin.get("entity_uri", ""),
                cache=relay_cache,
                origin_manifest=origin_manifest,
            )
        else:
            keys = resolve_origin_key(sender_node_id)
    except OriginIdentityError as exc:
        logger.warning(
            "Tombstone ingest from %s: skip %s (origin_unresolvable): %s",
            sender_node_id,
            record.id,
            exc,
        )
        return TombstoneEntryResult(False, "origin_unresolvable")

    # Verify the ORIGIN-attestation signature (binds tombstone id/entity_uri/scope +
    # the origin's propagation grant — anti-relaunder: a widened scope invalidates it).
    try:
        verify_tombstone_origin_signature(
            origin_sig,
            tombstone_id=record.id,
            entity_uri=record.entity_uri,
            scope=record.scope,
            origin_node_id=origin["node_id"],
            origin_tenant=origin.get("tenant", ""),
            origin_allowed_scopes=origin.get("allowed_scopes", []),
            origin_allowed_tenants=origin.get("allowed_tenants", []),
            origin_entity_uri=origin.get("entity_uri", ""),
            allowed_pubkeys=keys,
        )
    except OriginSignatureError as exc:
        logger.warning(
            "Tombstone ingest from %s: skip %s (origin_sig_invalid): %s",
            sender_node_id,
            record.id,
            exc,
        )
        return TombstoneEntryResult(False, "origin_sig_invalid")

    # ALSO verify the ISSUER-signer signature (both required): a relayed tombstone must
    # ALSO be a real suppression order. Same shared helper the push direct path uses.
    try:
        resolve_and_verify_tombstone_issuer(
            record,
            key_id=record.key_id or "",
            signer_uri=record.signed_by,
            verifier=verify_tombstone_signature,
        )
    except IssuerVerificationError as exc:
        logger.warning(
            "Tombstone ingest from %s: skip %s (issuer_sig_invalid): %s",
            sender_node_id,
            record.id,
            exc.reason,
        )
        return TombstoneEntryResult(False, "issuer_sig_invalid")

    if is_relayed:
        # Ingest-side scope gate: the tombstone's scope must be inside the origin's
        # granted scopes — a relay can't widen the scope a tombstone travels under.
        if record.scope not in origin.get("allowed_scopes", []):
            logger.warning(
                "Tombstone ingest from %s: skip relayed tombstone %s (scope_not_in_origin_grant)",
                sender_node_id,
                record.id,
            )
            return TombstoneEntryResult(False, "scope_not_in_origin_grant")
        # Ingest-side tenant gate (ingest/egress symmetry — F-2c-MED-1): origin.tenant must be
        # inside the origin's OWN signed allowed_tenants. Both are bound in the signed origin
        # tuple, so a relay can't forge them; the receiver ENFORCES the signed invariant
        # fail-closed before mapping the tenant through this relay's tenant_map.
        if origin.get("tenant", "") not in origin.get("allowed_tenants", []):
            logger.warning(
                "Tombstone ingest from %s: skip relayed tombstone %s (tenant_not_in_origin_grant)",
                sender_node_id,
                record.id,
            )
            return TombstoneEntryResult(False, "tenant_not_in_origin_grant")
        # Resolve the wire-carried origin tenant to a LOCAL tenant (default-deny).
        try:
            with db() as conn:
                relay_tenant = resolve_origin_tenant_for_peer(
                    peer, origin.get("tenant", ""), conn
                )
        except PeerPolicyError as exc:
            logger.warning(
                "Tombstone ingest from %s: skip relayed tombstone %s (tenant policy unsafe): %s",
                sender_node_id,
                record.id,
                exc,
            )
            write_audit_log(
                sender_node_id,
                "federation_tenant_policy_rejected",
                {"reason": str(exc), "surface": "tombstones_relay"},
            )
            return TombstoneEntryResult(False, "tenant_policy_unsafe")
        # All checks passed — apply + PERSIST the verified origin block + received_from so
        # this node can itself relay it onward (the egress gate W6.6 reads these columns).
        apply_inbound_tombstone(
            record,
            tenant_id=relay_tenant,
            origin_node_id=origin["node_id"],
            origin_tenant=origin.get("tenant", ""),
            origin_entity_uri=origin.get("entity_uri", ""),
            origin_allowed_scopes=origin.get("allowed_scopes", []),
            origin_allowed_tenants=origin.get("allowed_tenants", []),
            origin_sig=origin_sig,
            received_from=sender_node_id,
        )
        return TombstoneEntryResult(True, None)

    # DIRECT: both signatures verified — apply (origin columns None for direct/self).
    apply_inbound_tombstone(record, tenant_id=direct_tenant_id)
    return TombstoneEntryResult(True, None)


async def pull_tombstones_from_peer_once(
    peer: dict[str, Any],
    client: httpx.AsyncClient,
    cursor: str | None,
) -> str | None:
    """Pull one page of tombstones from the peer (§23.4.3). Returns the new cursor."""
    allowed_scopes: list[str] = json.loads(peer["allowed_scopes"])
    token = create_peer_token(peer["node_id"], allowed_scopes)

    params: dict[str, Any] = {"limit": 200}
    if cursor:
        params["since"] = cursor

    try:
        resp = await _pinned_get(
            client,
            f"{peer['node_url']}/v1/federation/tombstones",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
    except ValueError as exc:
        # Anti-rebind pin refused the peer's node_url at FETCH time (R-5 / F-SSRF1).
        logger.warning(
            "Tombstone pull from %s blocked: unsafe node_url (%s)", peer["node_id"], exc
        )
        return cursor
    except httpx.RequestError as exc:
        logger.warning("Tombstone pull network error from %s: %s", peer["node_id"], exc)
        return cursor

    if resp.status_code != 200:
        logger.warning("Tombstone pull from %s returned %s", peer["node_id"], resp.status_code)
        return cursor

    data = resp.json()

    # F-FED-2c W6.5: clean break — only the v2 signed-origin tombstone envelope is consumed
    # (mirrors the fact pull's body.get("v") != 2 handling). A non-v2 page is dropped
    # wholesale; advance no cursor.
    if data.get("v") != 2:
        logger.warning(
            "Tombstone pull from %s returned non-v2 envelope (v=%r); dropping page",
            peer["node_id"],
            data.get("v"),
        )
        return cursor

    tombstones = data.get("tombstones", [])
    new_cursor: str | None = data.get("cursor")

    # F-13 §23.4.3: emit tombstone_sync_gap when result set is non-empty and cursor
    # indicates skipped pages (more results available beyond this batch)
    if tombstones and new_cursor is not None:
        from ..observability.audit_event import emit_nofail

        emit_nofail(
            "tombstone_sync_gap",
            entity_uri=peer["node_id"],
            tenant_id="default",
            source=f"federation_pull:{peer['node_id']}",
            detail={
                "peer_node_id": peer["node_id"],
                "tombstones_in_batch": len(tombstones),
                "cursor": new_cursor,
            },
        )

    # F-FED-TOMBSTONE-TENANT: resolve the local tenant this peer's inbound data
    # lands in (fail-closed per peer policy — same helper as fact ingest in
    # Task 3). The recall-time suppression filter keys on (entity_uri, tenant_id),
    # so an inbound tombstone MUST be stamped with the peer's tenant rather than
    # the hardcoded 'default'; otherwise a peer's RTBF tombstone could suppress a
    # different tenant's facts. A mis-pinned peer yields PeerPolicyError — skip the
    # whole page rather than land tombstones in the wrong tenant.
    try:
        with db() as conn:
            tenant_id = resolve_ingest_tenant_for_peer(peer, conn)
    except PeerPolicyError as exc:
        logger.warning(
            "Skipping tombstone pull from %s: peer tenant policy unsafe: %s",
            peer["node_id"],
            exc,
        )
        write_audit_log(
            peer["node_id"],
            "federation_tenant_policy_rejected",
            {"reason": str(exc), "surface": "tombstones"},
        )
        return cursor  # fail-closed: apply nothing from a mis-pinned peer

    # Ingest tombstones and revocations (both v2-enveloped; the revocation chain runs in
    # ``ingest_revocation_entry`` below, mirroring ``ingest_tombstone_entry``).
    sender_node_id = peer["node_id"]
    # W6.7: per-PAGE relay key cache, threaded into resolve_origin_key_for_relay so a relayed-
    # origin manifest fetch + rotation check runs ONCE per page, not per tombstone. A local (not
    # a module global) so no stale binding persists across pages — mirrors the fact pull loop.
    relay_cache: dict[tuple[str, str], set[str]] = {}
    relay_enabled = settings.federation_relay_enabled
    try:
        sender_relay_trusted = bool(peer["relay_trusted"])
    except (KeyError, IndexError, TypeError):
        sender_relay_trusted = bool(dict(peer).get("relay_trusted"))
    for entry in tombstones:
        # W6.8: the per-tombstone secure chain (DIRECT vs RELAYED, both signatures, scope/tenant
        # gate, fail-closed, apply) lives in the SHARED ``ingest_tombstone_entry`` so the PUSH
        # /ingest route runs byte-identical verification. The pull loop logs + continues on any
        # skip; the push route maps the same reasons to HTTP statuses.
        if not isinstance(entry, dict):
            logger.warning(
                "Tombstone pull from %s: malformed entry (not an object)", sender_node_id
            )
            continue
        try:
            ingest_tombstone_entry(
                entry=entry,
                sender_node_id=sender_node_id,
                peer=peer,
                relay_enabled=relay_enabled,
                relay_trusted=sender_relay_trusted,
                direct_tenant_id=tenant_id,
                relay_cache=relay_cache,
            )
        except Exception as exc:
            logger.warning("Tombstone ingest from %s failed: %s", peer["node_id"], exc)

    # Rev-2/Rev-3: revocations are ENVELOPED on the wire (RevocationEnvelopeEntry). The per-
    # revocation secure chain (DIRECT vs RELAYED, both signatures, relay_trusted gate, tenant
    # gate, fail-closed, apply) lives in the SHARED ``ingest_revocation_entry`` so the PUSH
    # /ingest route runs byte-identical verification (Rev-3). The pull loop logs + continues on
    # any skip; the push route maps the same reasons to HTTP statuses. The per-PAGE relay_cache
    # is shared with the tombstone loop above so a relayed-origin manifest fetch + rotation check
    # runs ONCE per page across both tombstones and revocations.
    for entry in data.get("revocations", []):
        try:
            ingest_revocation_entry(
                entry=entry,
                sender_node_id=sender_node_id,
                peer=peer,
                relay_enabled=relay_enabled,
                relay_trusted=sender_relay_trusted,
                relay_cache=relay_cache,
            )
        except Exception as exc:
            logger.warning("Tombstone revocation ingest from %s failed: %s", peer["node_id"], exc)

    return new_cursor


def ingest_revocation_entry(
    *,
    entry: dict[str, Any],
    sender_node_id: str,
    peer: dict[str, Any],
    relay_enabled: bool,
    relay_trusted: bool,
    relay_cache: dict[tuple[str, str], set[str]],
) -> RevocationEntryResult:
    """Verify + apply ONE v2 revocation envelope entry through the full secure chain (Rev-3).

    Mirrors ``ingest_tombstone_entry`` but for tombstone REVOCATIONS, which have no
    entity_uri/scope of their own (they reference a tombstone by ``tombstone_id``) — so there
    is NO scope gate, only a tenant gate. Extracted so the PULL loop and the PUSH ingest route
    share ONE verify+apply path and can never diverge. The ordered chain mirrors the tombstone
    relay ingest exactly:

      parse entry → parse record → DIRECT (origin==sender) vs RELAYED (origin!=sender)
      → [relayed] relay ON + sender relay_trusted gate (fail-closed)
      → resolve origin key (direct: 2a peer chain; relayed: W4.2 secure relay resolver)
      → verify revocation ORIGIN signature (anti-relaunder: rid+tombstone_id bound in the tuple)
      → verify ISSUER-signer signature (BOTH required)
      → [relayed] resolve_origin_tenant_for_peer (default-deny; no scope gate)
      → apply_inbound_revocation (relayed: + origin cols + received_from; direct: bare)

    Returns a :class:`RevocationEntryResult`; never raises HTTPException (the push route owns
    the HTTP mapping). Direct (origin==sender) + relay-OFF are byte-identical to Rev-2.
    """
    from ..lifecycle.tombstone_signing import (
        IssuerVerificationError,
        resolve_and_verify_tombstone_issuer,
        verify_revocation_signature,
    )
    from ..lifecycle.tombstones import RevocationAuthorityMismatch, apply_inbound_revocation
    from ..models.tombstones import TombstoneRevocationRecord
    from .origin_identity import (
        OriginIdentityError,
        resolve_origin_key,
        resolve_origin_key_for_relay,
    )
    from .origin_signature import (
        OriginSignatureError,
        verify_revocation_origin_signature,
    )

    if not isinstance(entry, dict):
        logger.warning("Revocation ingest from %s: malformed entry (not an object)", sender_node_id)
        return RevocationEntryResult(False, "malformed_entry")
    rev = entry.get("revocation")
    origin = entry.get("origin")
    origin_sig = entry.get("origin_sig")
    if not isinstance(rev, dict) or not isinstance(origin, dict) or not origin_sig:
        logger.warning(
            "Revocation ingest from %s: entry missing revocation/origin/origin_sig",
            sender_node_id,
        )
        return RevocationEntryResult(False, "missing_revocation_origin_or_sig")
    try:
        record = TombstoneRevocationRecord(**rev)
    except Exception as exc:
        logger.warning("Revocation ingest from %s: malformed revocation: %s", sender_node_id, exc)
        return RevocationEntryResult(False, "malformed_revocation")

    is_relayed = origin.get("node_id") != sender_node_id
    origin_manifest = entry.get("origin_manifest")
    if not isinstance(origin_manifest, dict):
        origin_manifest = None

    if is_relayed:
        if not relay_enabled:
            logger.warning(
                "Revocation ingest from %s: skip relayed revocation %s (origin_not_sender; "
                "relay disabled)",
                sender_node_id,
                record.id,
            )
            return RevocationEntryResult(False, "origin_not_sender")
        if not relay_trusted:
            logger.warning(
                "Revocation ingest from %s: skip relayed revocation %s "
                "(relay_sender_not_trusted)",
                sender_node_id,
                record.id,
            )
            return RevocationEntryResult(False, "relay_sender_not_trusted")

    # Resolve the ORIGIN's verified key set. Direct: 2a peer chain (sender IS the origin).
    # Relayed: the W4.2 secure relay resolver (fetch-on-first / pin / stored / fail-closed).
    try:
        if is_relayed:
            keys = resolve_origin_key_for_relay(
                origin["node_id"],
                origin.get("entity_uri", ""),
                cache=relay_cache,
                origin_manifest=origin_manifest,
            )
        else:
            keys = resolve_origin_key(sender_node_id)
    except OriginIdentityError as exc:
        logger.warning(
            "Revocation ingest from %s: skip %s (origin_unresolvable): %s",
            sender_node_id,
            record.id,
            exc,
        )
        return RevocationEntryResult(False, "origin_unresolvable")

    # Verify the revocation ORIGIN-attestation signature (binds rid + tombstone_id + grant —
    # anti-relaunder: a relay that retargets which revocation/tombstone it carries invalidates it).
    try:
        verify_revocation_origin_signature(
            origin_sig,
            revocation_id=record.id,
            tombstone_id=record.tombstone_id,
            origin_node_id=origin["node_id"],
            origin_tenant=origin.get("tenant", ""),
            origin_allowed_scopes=origin.get("allowed_scopes", []),
            origin_allowed_tenants=origin.get("allowed_tenants", []),
            origin_entity_uri=origin.get("entity_uri", ""),
            allowed_pubkeys=keys,
        )
    except OriginSignatureError as exc:
        logger.warning(
            "Revocation ingest from %s: skip %s (origin_sig_invalid): %s",
            sender_node_id,
            record.id,
            exc,
        )
        return RevocationEntryResult(False, "origin_sig_invalid")

    # ALSO verify the ISSUER-signer signature (both required): a revocation must ALSO be a real
    # tombstone REVERSAL. Same shared helper the tombstone direct path uses, with the revocation
    # verifier injected.
    try:
        resolve_and_verify_tombstone_issuer(
            record,
            key_id=record.key_id or "",
            signer_uri=record.signed_by,
            verifier=verify_revocation_signature,
        )
    except IssuerVerificationError as exc:
        logger.warning(
            "Revocation ingest from %s: skip %s (issuer_sig_invalid): %s",
            sender_node_id,
            record.id,
            exc.reason,
        )
        return RevocationEntryResult(False, "issuer_sig_invalid")

    if is_relayed:
        # Ingest-side tenant gate (ingest/egress symmetry — F-2c-MED-1): origin.tenant must be
        # inside the origin's OWN signed allowed_tenants. A revocation has no scope, but it DOES
        # carry origin.tenant + origin.allowed_tenants in the signed tuple — so a relay can't
        # forge them; the receiver ENFORCES the signed invariant fail-closed before the
        # default-deny tenant resolve below.
        if origin.get("tenant", "") not in origin.get("allowed_tenants", []):
            logger.warning(
                "Revocation ingest from %s: skip relayed revocation %s "
                "(tenant_not_in_origin_grant)",
                sender_node_id,
                record.id,
            )
            return RevocationEntryResult(False, "tenant_not_in_origin_grant")
        # Tenant gate (default-deny): the wire-carried origin tenant must resolve to a LOCAL
        # tenant under this peer's policy or the relay is refused. There is NO scope gate — a
        # revocation has no scope of its own. The resolver's value is discarded: the revocation
        # row has no tenant_id column; the call is run purely for its fail-closed side effect.
        try:
            with db() as conn:
                resolve_origin_tenant_for_peer(peer, origin.get("tenant", ""), conn)
        except PeerPolicyError as exc:
            logger.warning(
                "Revocation ingest from %s: skip relayed revocation %s (tenant policy unsafe): %s",
                sender_node_id,
                record.id,
                exc,
            )
            write_audit_log(
                sender_node_id,
                "federation_tenant_policy_rejected",
                {"reason": str(exc), "surface": "revocations_relay"},
            )
            return RevocationEntryResult(False, "tenant_policy_unsafe")
        # All checks passed — apply + PERSIST the verified origin block + received_from so this
        # node can itself relay it onward (the egress gate Rev-2 reads these columns). The shared
        # sink enforces SAME-ISSUER binding (revocation.signed_by == held tombstone's issuer);
        # a cross-issuer revocation is rejected fail-closed (RTBF integrity).
        try:
            apply_inbound_revocation(
                record,
                origin_node_id=origin["node_id"],
                origin_tenant=origin.get("tenant", ""),
                origin_entity_uri=origin.get("entity_uri", ""),
                origin_allowed_scopes=origin.get("allowed_scopes", []),
                origin_allowed_tenants=origin.get("allowed_tenants", []),
                origin_sig=origin_sig,
                received_from=sender_node_id,
            )
        except RevocationAuthorityMismatch:
            logger.warning(
                "Revocation ingest from %s: skip relayed revocation %s "
                "(revocation_authority_mismatch)",
                sender_node_id,
                record.id,
            )
            return RevocationEntryResult(False, RevocationAuthorityMismatch.reason)
        return RevocationEntryResult(True, None)

    # DIRECT: both signatures verified — apply (origin columns None for direct/self). The shared
    # sink still enforces SAME-ISSUER binding: a direct revocation whose signer != the held
    # tombstone's issuer is rejected fail-closed.
    try:
        apply_inbound_revocation(record)
    except RevocationAuthorityMismatch:
        logger.warning(
            "Revocation ingest from %s: skip direct revocation %s "
            "(revocation_authority_mismatch)",
            sender_node_id,
            record.id,
        )
        return RevocationEntryResult(False, RevocationAuthorityMismatch.reason)
    return RevocationEntryResult(True, None)


def _load_tombstone_cursor(peer_id: str) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT cursor FROM replication_cursors"
            " WHERE peer_id = ? AND direction = 'tombstone_inbound'",
            (peer_id,),
        ).fetchone()
    return row["cursor"] if row else None


def _save_tombstone_cursor(peer_id: str, cursor: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO replication_cursors (peer_id, direction, cursor, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(peer_id, direction)
               DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at""",
            (peer_id, "tombstone_inbound", cursor, datetime.now(UTC).isoformat()),
        )


async def pull_all_peers_once() -> None:
    """Pull one batch from every active peer. Called by the loop and by tests."""
    with db() as conn:
        peers = conn.execute(
            "SELECT id, node_id, node_url, allowed_scopes, ingest_tenant, pull_tenant, "
            "relay_trusted "
            "FROM peers WHERE status = 'active'"
        ).fetchall()

    if not peers:
        return

    async with _make_pull_client() as client:
        for peer in peers:
            peer_dict = dict(peer)
            cursor = load_cursor(peer_dict["id"])
            new_cursor = await pull_from_peer_once(peer_dict, client, cursor)
            if new_cursor != cursor:
                save_cursor(peer_dict["id"], new_cursor)

            # §23.4.3: pull tombstones from peers
            tomb_cursor = _load_tombstone_cursor(peer_dict["id"])
            new_tomb_cursor = await pull_tombstones_from_peer_once(peer_dict, client, tomb_cursor)
            if new_tomb_cursor != tomb_cursor:
                _save_tombstone_cursor(peer_dict["id"], new_tomb_cursor)


async def pull_loop_task() -> None:
    """Background asyncio task: pull from all active peers every pull_interval_s."""
    while True:
        await asyncio.sleep(settings.federation_pull_interval_s)
        try:
            await pull_all_peers_once()
        except Exception:
            logger.exception("Unexpected error in pull loop")
