"""Subscription CRUD and replay-window routes — spec §20.3, §20.5.

POST   /v1/subscriptions                       — create (subscriber_identity = caller; BOLA §20.3.2)
GET    /v1/subscriptions                       — list caller's subscriptions
GET    /v1/subscriptions/{id}                  — get one (BOLA: 404 if not owner)
DELETE /v1/subscriptions/{id}                  — cancel (BOLA: 404 if not owner)
GET    /v1/subscriptions/{id}/events           — replay window (§20.5)
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import settings as _settings_pkg
from ..auth import Identity, resolve_identity
from ..db import db
from ..garden_acl import get_garden_by_garden_uri, require_garden_read
from ..models.constants import VALID_SCOPES
from ..models.subscriptions import (
    SubscriptionCreateRequest,
    SubscriptionEventRecord,
    SubscriptionEventsResponse,
    SubscriptionListResponse,
    SubscriptionRecord,
)
from ..net_util import assert_safe_url
from ..subscription_delivery import _sanitize_payload as _sanitize_event_payload

router = APIRouter(prefix="/v1/subscriptions", tags=["subscriptions"])


def _target_kind(target: str) -> str:
    return "scope" if target in VALID_SCOPES else "entity"


def _row_to_record(row: Any) -> SubscriptionRecord:
    return SubscriptionRecord(
        id=row["id"],
        subscriber_identity=row["subscriber_identity"],
        target=row["target"],
        target_kind=row["target_kind"],
        on_change=row["on_change"],
        delivery_address=row["delivery_address"],
        idempotency_key=row["idempotency_key"],
        created_at=row["created_at"],
        last_delivered_at=row["last_delivered_at"],
        circuit_open=bool(row["circuit_open"]),
        consecutive_failures=row["consecutive_failures"],
    )


def _event_row_to_record(row: Any) -> SubscriptionEventRecord:
    return SubscriptionEventRecord(
        id=row["id"],
        subscription_id=row["subscription_id"],
        event_type=row["event_type"],
        entity_uri=row["entity_uri"],
        fact_id=row["fact_id"],
        payload=json.loads(row["payload"]),
        created_at=row["created_at"],
        delivered_at=row["delivered_at"],
        delivery_status=row["delivery_status"],
        delivery_attempts=row["delivery_attempts"],
    )


def _event_row_to_record_with_payload(row: Any, payload_json: str) -> SubscriptionEventRecord:
    """Like _event_row_to_record but substitutes a pre-sanitized payload JSON string."""
    return SubscriptionEventRecord(
        id=row["id"],
        subscription_id=row["subscription_id"],
        event_type=row["event_type"],
        entity_uri=row["entity_uri"],
        fact_id=row["fact_id"],
        payload=json.loads(payload_json),
        created_at=row["created_at"],
        delivered_at=row["delivered_at"],
        delivery_status=row["delivery_status"],
        delivery_attempts=row["delivery_attempts"],
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=SubscriptionRecord, status_code=status.HTTP_201_CREATED)
def create_subscription(
    req: SubscriptionCreateRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> SubscriptionRecord:
    """Create a subscription (Spec-X7-Subscriptions).

    subscriber_identity is always the caller (BOLA).
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    # §17 garden ACL: if target is a garden URI, caller must be a member
    if req.target.startswith("stigmem://") and "/garden/" in req.target:
        garden = get_garden_by_garden_uri(req.target, tenant_id=identity.tenant_id)
        if garden is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="garden not found")
        require_garden_read(garden, identity)

    # GHSA-5p3m-vhh6-9236: validate a webhook delivery_address BEFORE persisting,
    # so an unsafe URL is rejected (400) rather than stored-then-blocked-at-delivery.
    # https-only by default; http requires the explicit operator opt-in. A `wake`
    # subscription's delivery_address is an identity URI (not a fetchable URL), so
    # it is deliberately NOT subjected to the SSRF guard.
    if req.on_change == "webhook":
        try:
            assert_safe_url(
                req.delivery_address,
                allow_schemes=_settings_pkg.settings.webhook_allowed_schemes,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unsafe webhook delivery_address: {exc}",
            ) from exc

    # Idempotency key: return existing subscription if key matches THIS caller.
    # Scoped to subscriber and tenant to prevent cross-entity metadata leakage (R2).
    if req.idempotency_key:
        with db() as conn:
            existing = conn.execute(
                """SELECT * FROM subscriptions
                   WHERE idempotency_key=? AND tenant_id=? AND subscriber_identity=?""",
                (req.idempotency_key, identity.tenant_id, identity.entity_uri),
            ).fetchone()
        if existing is not None:
            return _row_to_record(existing)

    # Natural dedup: same (subscriber, target, on_change, delivery_address) → return existing
    with db() as conn:
        dupe = conn.execute(
            """SELECT * FROM subscriptions
               WHERE subscriber_identity=? AND target=? AND on_change=?
                 AND delivery_address=? AND tenant_id=?""",
            (
                identity.entity_uri,
                req.target,
                req.on_change,
                req.delivery_address,
                identity.tenant_id,
            ),
        ).fetchone()
        if dupe is not None:
            return _row_to_record(dupe)

    # F-AVAIL-3: cap active subscriptions per principal to bound fan-out/DoS.
    _sub_cap = _settings_pkg.settings.max_subscriptions_per_principal
    if _sub_cap > 0:
        with db() as conn:
            held = conn.execute(
                "SELECT COUNT(*) AS n FROM subscriptions "
                "WHERE subscriber_identity=? AND tenant_id=?",
                (identity.entity_uri, identity.tenant_id),
            ).fetchone()["n"]
        if held >= _sub_cap:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"subscription limit reached ({_sub_cap})",
            )

    sub_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    target_kind = _target_kind(req.target)

    with db() as conn:
        conn.execute(
            """INSERT INTO subscriptions
               (id, subscriber_identity, target, target_kind, on_change,
                delivery_address, idempotency_key, created_at, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                sub_id,
                identity.entity_uri,
                req.target,
                target_kind,
                req.on_change,
                req.delivery_address,
                req.idempotency_key,
                now,
                identity.tenant_id,
            ),
        )
        row = conn.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()

    return _row_to_record(row)


@router.get("", response_model=SubscriptionListResponse)
def list_subscriptions(
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> SubscriptionListResponse:
    """List the authenticated caller's subscriptions (BOLA: own only)."""
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    with db() as conn:
        rows = conn.execute(
            """SELECT * FROM subscriptions
               WHERE subscriber_identity=? AND tenant_id=?
               ORDER BY created_at DESC""",
            (identity.entity_uri, identity.tenant_id),
        ).fetchall()

    return SubscriptionListResponse(
        subscriptions=[_row_to_record(r) for r in rows],
        total=len(rows),
    )


@router.get("/{subscription_id}", response_model=SubscriptionRecord)
def get_subscription(
    subscription_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> SubscriptionRecord:
    """Get a subscription by ID (BOLA: returns 404 if caller does not own it)."""
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM subscriptions WHERE id=? AND tenant_id=?",
            (subscription_id, identity.tenant_id),
        ).fetchone()

    if row is None or row["subscriber_identity"] != identity.entity_uri:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

    return _row_to_record(row)


@router.delete("/{subscription_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_subscription(
    subscription_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> None:
    """Cancel a subscription (BOLA: only the owner may delete)."""
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    with db() as conn:
        row = conn.execute(
            "SELECT id, subscriber_identity FROM subscriptions WHERE id=? AND tenant_id=?",
            (subscription_id, identity.tenant_id),
        ).fetchone()

    if row is None or row["subscriber_identity"] != identity.entity_uri:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

    with db() as conn:
        conn.execute("DELETE FROM subscriptions WHERE id=?", (subscription_id,))


# ---------------------------------------------------------------------------
# Replay window
# ---------------------------------------------------------------------------


@router.get("/{subscription_id}/events", response_model=SubscriptionEventsResponse)
def list_subscription_events(
    subscription_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    since: str | None = Query(
        None,
        description="ISO 8601 timestamp; return events created at or after this time",
    ),
    cursor: str | None = Query(None, description="Opaque pagination cursor (event id)"),
    limit: int = Query(50, ge=1, le=500),
) -> SubscriptionEventsResponse:
    """Replay window: return delivery events for a subscription (Spec-X7-Subscriptions).

    Results are bounded to the configured replay window (default 24 h).
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    with db() as conn:
        sub_row = conn.execute(
            "SELECT id, subscriber_identity FROM subscriptions WHERE id=? AND tenant_id=?",
            (subscription_id, identity.tenant_id),
        ).fetchone()

    if sub_row is None or sub_row["subscriber_identity"] != identity.entity_uri:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="subscription not found")

    replay_s = _settings_pkg.settings.subscription_replay_s
    window_cutoff = (datetime.now(UTC) - timedelta(seconds=replay_s)).isoformat()
    effective_since = max(since, window_cutoff) if since is not None else window_cutoff

    if cursor:
        sql = (
            "SELECT rowid, * FROM subscription_events "
            "WHERE subscription_id = ? AND created_at >= ? AND rowid > ? "
            "ORDER BY rowid ASC LIMIT ?"
        )
        params: list[Any] = [subscription_id, effective_since, int(cursor)]
    else:
        sql = (
            "SELECT rowid, * FROM subscription_events "
            "WHERE subscription_id = ? AND created_at >= ? "
            "ORDER BY rowid ASC LIMIT ?"
        )
        params = [subscription_id, effective_since]
    params.append(limit + 1)

    with db() as conn:
        rows = conn.execute(sql, params).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = str(rows[-1]["rowid"]) if has_more and rows else None

    # S3 fix: re-apply §17 garden ACL and §19 sanitizer at replay time.
    # subscription_events.payload stores the raw pre-delivery payload; without this
    # re-check a subscriber could retrieve garden-scoped facts they've since been
    # removed from, or sanitizer-redacted content, via the replay window.
    event_ctx = {
        "subscriber_identity": sub_row["subscriber_identity"],
        "tenant_id": identity.tenant_id,
    }
    safe_events: list[SubscriptionEventRecord] = []
    for r in rows:
        raw_payload = json.loads(r["payload"])
        sanitized = _sanitize_event_payload(event_ctx, raw_payload)
        if sanitized is None:
            # ACL/sanitizer blocked — return redacted placeholder
            safe_payload = json.dumps({"fact_id": raw_payload.get("id"), "redacted": True})
        else:
            safe_payload = json.dumps(sanitized)
        safe_events.append(_event_row_to_record_with_payload(r, safe_payload))

    return SubscriptionEventsResponse(
        events=safe_events,
        total=len(safe_events),
        cursor=next_cursor,
    )
