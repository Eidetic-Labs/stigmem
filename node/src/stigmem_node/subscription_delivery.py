"""Subscription delivery engine — spec §20.4.

Responsibilities:
1. ``fan_out`` — when a fact is written, find matching subscriptions and insert
   pending ``subscription_events`` rows (fast; called synchronously on every write).
2. ``deliver_pending`` — sweep: attempt delivery for all pending/due-for-retry events.
3. ``sweep_loop`` — asyncio task run in the app lifespan; calls deliver_pending periodically.

Delivery types:
- ``webhook`` — HTTP POST to delivery_address with exponential backoff (1 s, 2 s, 4 s … ≤ 300 s).
- ``wake``    — structured JSON emitted to stderr; platform-specific integration hook.

Garden ACL (§17) and content sanitizer (§19) are applied at delivery time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import settings as _settings_pkg
from .auth import Identity
from .db import db
from .garden_acl import get_member_role
from .lifecycle.tombstone_cache import is_tombstoned as _is_tombstoned
from .memory_garden_acl_gate import garden_acl_enforced
from .net_util import resolve_pinned_address
from .recall.recall_pipeline import apply_recall_pipeline

logger = logging.getLogger("stigmem.subscriptions")
_DELIVER_PENDING_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Fan-out — called from routes/facts.py after each successful fact write
# ---------------------------------------------------------------------------


def fan_out(
    fact_id: str,
    entity: str,
    scope: str,
    garden_id: str | None,
    tenant_id: str,
    fact_payload_json: str,
) -> None:
    """Find subscriptions matching this fact and create pending delivery events."""
    now = datetime.now(UTC).isoformat()

    with db() as conn:
        scope_subs = conn.execute(
            """SELECT * FROM subscriptions
               WHERE target_kind='scope' AND target=? AND tenant_id=? AND circuit_open=0""",
            (scope, tenant_id),
        ).fetchall()

        entity_subs = conn.execute(
            """SELECT * FROM subscriptions
               WHERE target_kind='entity' AND target=? AND tenant_id=? AND circuit_open=0""",
            (entity, tenant_id),
        ).fetchall()

        for sub in list(scope_subs) + list(entity_subs):
            event_id = str(uuid.uuid4())
            conn.execute(
                """INSERT INTO subscription_events
                   (id, subscription_id, event_type, entity_uri, fact_id,
                    payload, created_at, delivery_status)
                   VALUES (?,?,?,?,?,?,?,'pending')""",
                (event_id, sub["id"], "fact_asserted", entity, fact_id, fact_payload_json, now),
            )


# ---------------------------------------------------------------------------
# Delivery sweep — called by sweep_loop every N seconds
# ---------------------------------------------------------------------------


def deliver_pending() -> None:
    """Attempt delivery for all pending events that are due.

    Uses an atomic claim (``pending → delivering``) so that the background
    ``sweep_loop`` and any concurrent caller (admin replay endpoints,
    tests, future per-tenant workers) cannot deliver the same event twice.
    See issue #47 and migration 028 for the rationale.

    Concurrency model
    -----------------
    1. Recover stale claims: any row in ``delivering`` with
       ``claimed_at`` older than ``subscription_claim_timeout_s`` is reset
       to ``pending`` so a crashed worker cannot strand events.
    2. Atomically claim up to 100 due rows via
       ``UPDATE … WHERE id IN (SELECT … LIMIT 100) RETURNING …`` — SQLite
       serializes writes, so concurrent claimers see disjoint row sets.
    3. For each claimed row, attempt delivery and transition to
       ``delivered`` (success) or back to ``pending`` with a fresh
       ``next_retry_at`` (failure).
    """
    if not _DELIVER_PENDING_LOCK.acquire(blocking=False):
        logger.debug("subscription delivery already in progress; skipping concurrent drain")
        return

    try:
        now = datetime.now(UTC).isoformat()
        claim_timeout_s = _settings_pkg.settings.subscription_claim_timeout_s
        stale_cutoff = datetime.fromtimestamp(
            time.time() - claim_timeout_s,
            UTC,
        ).isoformat()

        with db() as conn:
            # 1. Recover stale claims left behind by a crashed worker.  We do NOT
            #    reset delivery_attempts — the next attempt counts as a retry.
            conn.execute(
                """UPDATE subscription_events
                      SET delivery_status='pending', claimed_at=NULL
                    WHERE delivery_status='delivering'
                      AND claimed_at IS NOT NULL
                      AND claimed_at < ?""",
                (stale_cutoff,),
            )

            # 2. Atomic claim.  The inner SELECT is the same predicate the old
            #    non-atomic path used, joined to subscriptions for circuit-open
            #    filtering.  The outer UPDATE … RETURNING gives us the claimed
            #    rows in a single round-trip; no other caller can claim them
            #    until we release them.
            claimed = conn.execute(
                """UPDATE subscription_events
                      SET delivery_status='delivering', claimed_at=?
                    WHERE id IN (
                        SELECT e.id
                          FROM subscription_events e
                          JOIN subscriptions s ON e.subscription_id = s.id
                         WHERE e.delivery_status = 'pending'
                           AND s.circuit_open = 0
                           AND (e.next_retry_at IS NULL OR e.next_retry_at <= ?)
                         ORDER BY e.created_at ASC
                         LIMIT 100
                    )
                    RETURNING id""",
                (now, now),
            ).fetchall()

            if not claimed:
                return

            claimed_ids = [row["id"] for row in claimed]
            # ``placeholders`` is a fixed "?,?,?…" string whose length comes from
            # ``claimed_ids`` (UUIDs we just emitted into our own table) — no user
            # input flows into the SQL text, so the f-string interpolation is safe.
            placeholders = ",".join("?" * len(claimed_ids))
            _base = (
                "SELECT e.id, e.subscription_id, e.event_type, e.entity_uri, e.fact_id,"
                " e.payload, e.created_at, e.delivery_attempts,"
                " s.on_change, s.delivery_address, s.subscriber_identity, s.tenant_id,"
                " s.circuit_open"
                " FROM subscription_events e"
                " JOIN subscriptions s ON e.subscription_id = s.id"
                " WHERE e.id IN ("
            )
            select_sql = _base + placeholders + ")"  # noqa: S608 — fixed "?,…" string
            events = conn.execute(select_sql, claimed_ids).fetchall()

        for event in events:
            try:
                payload = json.loads(event["payload"])
                success = _deliver_one(event, payload)
            except Exception as exc:
                logger.error("Delivery error for event %s: %s", event["id"], exc)
                success = False

            _record_result(event, success)
    finally:
        _DELIVER_PENDING_LOCK.release()


# ---------------------------------------------------------------------------
# Delivery helpers
# ---------------------------------------------------------------------------


def _deliver_one(event: Any, payload: dict[str, Any]) -> bool:
    on_change = event["on_change"]
    if on_change == "webhook":
        return _deliver_webhook(event, payload)
    if on_change == "wake":
        return _deliver_wake(event, payload)
    logger.error("Unknown on_change %r for event %s", on_change, event["id"])
    return False


def _subscriber_identity(entity_uri: str, tenant_id: str) -> Identity:
    return Identity(entity_uri=entity_uri, permissions=["read"], tenant_id=tenant_id)


def _subscriber_has_active_key(entity_uri: str, tenant_id: str) -> bool:
    """Return True if at least one non-expired API key exists for this identity.

    Only consulted when STIGMEM_AUTH_REQUIRED=true so that single-operator
    (auth-disabled) nodes are not affected.
    """
    from . import settings as _sp

    if not _sp.settings.auth_required:
        return True
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM api_keys WHERE entity_uri=? AND tenant_id=?"
            " AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
            (entity_uri, tenant_id, now),
        ).fetchone()
    return row is not None


def _sanitize_payload(event: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
    """Apply §17 garden ACL and §19 sanitizer.  Returns None to suppress delivery."""
    from .models.facts import FactRecord, FactValue

    subscriber = event["subscriber_identity"]
    tenant_id = event["tenant_id"]

    # S2 fix: re-check that the subscriber still holds an active read credential.
    # Prevents continued delivery after API key revocation for scope/entity subscriptions.
    if not _subscriber_has_active_key(subscriber, tenant_id):
        return None

    # §17 garden ACL re-check: skip delivery if subscriber no longer a member
    garden_uuid = payload.get("garden_id")
    if garden_uuid and garden_acl_enforced():
        role = get_member_role(garden_uuid, subscriber)
        if role is None:
            return None

    # §23.3.3 r.2: drop event immediately when entity has an active tombstone.
    # Uses the in-process cache (§23.3.3 r.4); 60-second leak window is acceptable.
    entity_for_tombstone = payload.get("entity")
    if entity_for_tombstone and _is_tombstoned(entity_for_tombstone, tenant_id):
        return None

    try:
        record = FactRecord(
            id=payload["id"],
            entity=payload["entity"],
            relation=payload["relation"],
            value=FactValue(type=payload["value_type"], v=payload.get("value_v")),
            source=payload["source"],
            timestamp=payload["timestamp"],
            confidence=float(payload.get("confidence", 1.0)),
            scope=payload.get("scope", "local"),
        )
        identity = _subscriber_identity(subscriber, tenant_id)
        results = apply_recall_pipeline([record], identity=identity, include_low_trust=True)
        if not results:
            return None
        sanitized = results[0]
        if sanitized.sanitizer_redacted:
            return {"fact_id": payload["id"], "redacted": True}
        out = dict(payload)
        out["value_v"] = str(sanitized.value.v) if sanitized.value.v is not None else None
        if sanitized.sanitizer_warnings:
            out["sanitizer_warnings"] = sanitized.sanitizer_warnings
        return out
    except Exception as exc:
        logger.warning("Sanitizer error for fact %s: %s", payload.get("id"), exc)
        return payload


def _build_pinned_request(address: str, pinned_ip: str) -> tuple[str, str]:
    """Return ``(pinned_url, host_header)`` for connecting to *pinned_ip*.

    The returned URL swaps the original hostname for the validated *pinned_ip*
    literal (IPv6 bracketed) while preserving scheme/port/path/query, so the
    socket connects to the pinned IP and cannot be re-resolved by a rebinder.
    The ``host_header`` carries the ORIGINAL hostname (+ explicit port) so the
    webhook receiver still sees the name it was registered under.

    The caller also passes ``extensions={"sni_hostname": <hostname>}`` so the TLS
    SNI and certificate verification run against the original hostname, NOT the
    IP literal (proven against httpx 0.28.1 in test_webhook_dns_rebind.py).
    """
    parts = urlsplit(address)
    hostname = parts.hostname or ""
    port = parts.port
    # Bracket IPv6 literals for a valid authority.
    ip_authority = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    if port is not None:
        netloc = f"{ip_authority}:{port}"
        host_header = f"{hostname}:{port}"
    else:
        netloc = ip_authority
        host_header = hostname
    pinned_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return pinned_url, host_header


def _deliver_webhook(event: Any, payload: dict[str, Any]) -> bool:
    sanitized = _sanitize_payload(event, payload)
    if sanitized is None:
        # ACL/sanitizer blocked — mark delivered, don't retry
        _mark_delivered(event["id"], event["subscription_id"])
        return True

    # SSRF guard (P-CONF-2 + H9/F-SSRF-1): never POST to a private/loopback/
    # link-local/IMDS address. Resolve the hostname ONCE and PIN the connection to
    # that validated IP — assert_safe_url's resolved-then-reconnect pattern left a
    # DNS-rebind TOCTOU window (httpx re-resolved the hostname at connect time).
    # resolve_pinned_address rejects the whole URL if ANY resolved record is
    # private (the rebinder picks which record is served) and returns one safe IP.
    # Unsafe/unresolvable addresses can never become deliverable, so stop retrying.
    # GHSA-5p3m-vhh6-9236: https-only by default; http requires the explicit
    # operator opt-in (STIGMEM_WEBHOOK_ALLOW_INSECURE_HTTP).
    address = event["delivery_address"]
    try:
        pinned_ip = resolve_pinned_address(
            address,
            allow_schemes=_settings_pkg.settings.webhook_allowed_schemes,
        )
    except ValueError as exc:
        logger.warning(
            "Webhook delivery blocked for subscription %s: unsafe delivery_address (%s)",
            event["subscription_id"],
            exc,
        )
        _mark_delivered(event["id"], event["subscription_id"])
        return True

    # Connect to the pinned IP literal (no re-resolution) while verifying the TLS
    # cert against the ORIGINAL hostname via the sni_hostname extension, and carry
    # the original Host header. Proven against httpx 0.28.1 in
    # tests/routes/test_webhook_dns_rebind.py (a real TLS handshake verifies the
    # cert against the hostname, not the IP).
    pinned_url, host_header = _build_pinned_request(address, pinned_ip)
    hostname = urlsplit(address).hostname or ""

    body = {
        "event_id": event["id"],
        "idempotency_key": event["id"],
        "subscription_id": event["subscription_id"],
        "event_type": event["event_type"],
        "fact": sanitized,
    }

    try:
        with httpx.Client(timeout=10.0, follow_redirects=False) as client:
            resp = client.post(
                pinned_url,
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Stigmem-Event-Id": event["id"],
                    "Host": host_header,
                },
                extensions={"sni_hostname": hostname},
            )

        if resp.status_code == 410:
            # Webhook endpoint gone — cancel the subscription
            with db() as conn:
                conn.execute("DELETE FROM subscriptions WHERE id=?", (event["subscription_id"],))
            logger.info("Subscription %s cancelled (410 Gone)", event["subscription_id"])
            return True

        # 5xx / 429 → retry; 2xx/3xx → success; 4xx (except 429) → permanent failure, don't retry
        if resp.status_code >= 500 or resp.status_code == 429:
            return False
        return resp.status_code < 400

    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
        return False


def _deliver_wake(event: Any, payload: dict[str, Any]) -> bool:
    sanitized = _sanitize_payload(event, payload)
    if sanitized is None:
        return True  # ACL blocked; mark delivered

    # P1 note: wake delivery writes sanitized fact payloads to stderr for
    # operator/platform pickup.  Any process with stderr access sees ALL wake
    # events from ALL subscribers.  This is intentional for the operator
    # integration use-case but means the platform operator is implicitly
    # trusted with the content of every wake-delivered fact.  Operators that
    # need per-subscriber isolation should run one node per subscriber.
    print(
        json.dumps(
            {
                "stigmem_wake": {
                    "event_id": event["id"],
                    "subscription_id": event["subscription_id"],
                    "subscriber_identity": event["subscriber_identity"],
                    "delivery_address": event["delivery_address"],
                    "event_type": event["event_type"],
                    "fact": sanitized,
                    "ts": datetime.now(UTC).isoformat(),
                }
            }
        ),
        file=sys.stderr,
    )
    return True


def _record_result(event: Any, success: bool) -> None:
    now = datetime.now(UTC).isoformat()
    new_attempts = (event["delivery_attempts"] or 0) + 1

    if success:
        with db() as conn:
            conn.execute(
                """UPDATE subscription_events
                   SET delivered_at=?, delivery_status='delivered',
                       delivery_attempts=?, claimed_at=NULL
                   WHERE id=?""",
                (now, new_attempts, event["id"]),
            )
            conn.execute(
                "UPDATE subscriptions SET last_delivered_at=?, consecutive_failures=0 WHERE id=?",
                (now, event["subscription_id"]),
            )
        return

    backoff_s = min(2**new_attempts, 300)
    next_retry = datetime.fromtimestamp(time.time() + backoff_s, UTC).isoformat()

    with db() as conn:
        # Release the claim back to 'pending' so the next sweep can retry it.
        # Circuit-breaker logic below may override to 'failed'.
        conn.execute(
            """UPDATE subscription_events
                  SET delivery_status='pending', claimed_at=NULL,
                      delivery_attempts=?, next_retry_at=?
                WHERE id=?""",
            (new_attempts, next_retry, event["id"]),
        )
        conn.execute(
            "UPDATE subscriptions SET consecutive_failures=consecutive_failures+1 WHERE id=?",
            (event["subscription_id"],),
        )
        sub = conn.execute(
            "SELECT consecutive_failures FROM subscriptions WHERE id=?",
            (event["subscription_id"],),
        ).fetchone()
        threshold = _settings_pkg.settings.subscription_circuit_threshold
        if sub and sub["consecutive_failures"] >= threshold:
            conn.execute(
                "UPDATE subscriptions SET circuit_open=1 WHERE id=?",
                (event["subscription_id"],),
            )
            conn.execute(
                "UPDATE subscription_events SET delivery_status='failed' WHERE id=?",
                (event["id"],),
            )
            logger.warning("Circuit breaker opened for subscription %s", event["subscription_id"])


def _mark_delivered(event_id: str, subscription_id: str) -> None:
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        conn.execute(
            """UPDATE subscription_events
               SET delivered_at=?,
                   delivery_status='delivered',
                   delivery_attempts=delivery_attempts+1,
                   claimed_at=NULL
               WHERE id=?""",
            (now, event_id),
        )
        conn.execute(
            "UPDATE subscriptions SET last_delivered_at=?, consecutive_failures=0 WHERE id=?",
            (now, subscription_id),
        )


# ---------------------------------------------------------------------------
# Background sweep loop
# ---------------------------------------------------------------------------


async def sweep_loop() -> None:
    """Long-running asyncio task: runs deliver_pending() every N seconds."""
    while True:
        await asyncio.sleep(_settings_pkg.settings.subscription_delivery_sweep_s)
        try:
            await asyncio.to_thread(deliver_pending)
        except Exception as exc:
            logger.exception("subscription delivery sweep failed: %s", exc)
