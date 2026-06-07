"""Per-principal token-bucket quota middleware — spec §22.4.

Replaces the legacy sliding-window implementation.  Each principal
(entity_uri resolved from the Bearer token) gets one token-bucket per quota
dimension.  Buckets are stored in the ``quota_buckets`` table and refilled
lazily on each request.

Dimension → endpoint mapping (spec §22.4.1):
  fact_write          POST /v1/facts, DELETE /v1/facts/*
  fact_read           GET /v1/facts/*, GET /v1/recall*
  token_issue         POST /v1/federation/capability-tokens
  admin_action        /v1/admin/*
  audit_export        GET /v1/admin/audit*

Exemptions (same as legacy):
  /v1/federation/ peer requests (use peer-token auth, not user API keys)
  Requests without a Bearer token

Backward-compat settings bridges:
  STIGMEM_RATE_LIMIT_WRITE_PER_HOUR → fact_write burst capacity (default 100)
  STIGMEM_RATE_LIMIT_READ_PER_HOUR  → fact_read  burst capacity (default 500)
  0 on either setting disables rate limiting entirely.
"""

from __future__ import annotations

import math
import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .db import db
from .settings import settings

# ---------------------------------------------------------------------------
# Default quota ceilings (spec §22.4.2)
# ---------------------------------------------------------------------------

_SPEC_DEFAULTS: dict[str, tuple[float, float]] = {
    # dimension: (capacity, rate_per_second)
    "fact_write": (100.0, 10.0),
    "fact_read": (500.0, 50.0),
    "token_issue": (20.0, 1 / 3),
    "federation_pull": (30.0, 0.5),
    "admin_action": (10.0, 1 / 6),
    "subscription_event": (200.0, 20.0),
    "audit_export": (10_000.0, 167.0),
}


def _capacity_for(dimension: str) -> float:
    """Return burst capacity, honoring legacy per-hour settings for fact_write/read."""
    if dimension == "fact_write":
        cap = settings.rate_limit_write_per_hour
        return float(cap) if cap > 0 else _SPEC_DEFAULTS["fact_write"][0]
    if dimension == "fact_read":
        cap = settings.rate_limit_read_per_hour
        return float(cap) if cap > 0 else _SPEC_DEFAULTS["fact_read"][0]
    return _SPEC_DEFAULTS.get(dimension, (100.0, 1.0))[0]


def _rate_for(dimension: str) -> float:
    """Return refill rate (tokens/second)."""
    if dimension == "fact_write":
        cap = settings.rate_limit_write_per_hour
        c = float(cap) if cap > 0 else _SPEC_DEFAULTS["fact_write"][0]
        return c / 3600.0
    if dimension == "fact_read":
        cap = settings.rate_limit_read_per_hour
        c = float(cap) if cap > 0 else _SPEC_DEFAULTS["fact_read"][0]
        return c / 3600.0
    return _SPEC_DEFAULTS.get(dimension, (100.0, 1.0))[1]


# ---------------------------------------------------------------------------
# Endpoint → dimension routing
# ---------------------------------------------------------------------------


def _dimension(path: str, method: str) -> str | None:
    """Return the quota dimension for this request, or None to skip quota."""
    m = method.upper()
    if path.startswith("/v1/admin/audit"):
        return "audit_export" if m == "GET" else "admin_action"
    if path.startswith("/v1/admin/"):
        return "admin_action"
    if path.startswith("/v1/federation/capability-tokens") and m == "POST":
        return "token_issue"
    if path.startswith("/v1/recall") or (path.startswith("/v1/facts") and m == "GET"):
        return "fact_read"
    if path.startswith("/v1/facts") and m in {"POST", "PUT", "PATCH", "DELETE"}:
        return "fact_write"
    # F-AVAIL-3: default coverage — every other authenticated API call still
    # counts against a quota dimension so no endpoint is left unbounded.
    if m == "GET":
        return "fact_read"
    if m in {"POST", "PUT", "PATCH", "DELETE"}:
        return "fact_write"
    return None


# ---------------------------------------------------------------------------
# Token-bucket check (SQLite upsert for atomic read-modify-write)
# ---------------------------------------------------------------------------


def _check_and_consume(
    entity_uri: str,
    tenant_id: str,
    dimension: str,
) -> tuple[bool, float]:
    """Refill and consume one token.  Returns (allowed, retry_after_seconds)."""
    now = time.time()
    capacity = _capacity_for(dimension)
    rate = _rate_for(dimension)

    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT tokens, last_refill FROM quota_buckets"
            " WHERE entity_uri=? AND tenant_id=? AND dimension=?",
            (entity_uri, tenant_id, dimension),
        ).fetchone()

        if row is None:
            tokens, last_refill = capacity, now
        else:
            tokens, last_refill = row["tokens"], row["last_refill"]
            elapsed = max(0.0, now - last_refill)
            tokens = min(capacity, tokens + elapsed * rate)
            last_refill = now

        if tokens >= 1.0:
            new_tokens = tokens - 1.0
            conn.execute(
                """INSERT INTO quota_buckets (entity_uri, tenant_id, dimension, tokens, last_refill)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(entity_uri, tenant_id, dimension)
                   DO UPDATE SET tokens=excluded.tokens, last_refill=excluded.last_refill""",
                (entity_uri, tenant_id, dimension, new_tokens, last_refill),
            )
            return True, 0.0

        # Bucket empty — persist refilled (but not consumed) state
        conn.execute(
            """INSERT INTO quota_buckets (entity_uri, tenant_id, dimension, tokens, last_refill)
               VALUES (?,?,?,?,?)
               ON CONFLICT(entity_uri, tenant_id, dimension)
               DO UPDATE SET tokens=excluded.tokens, last_refill=excluded.last_refill""",
            (entity_uri, tenant_id, dimension, tokens, last_refill),
        )
        # retry_after: seconds until one token is earned
        retry_after = (1.0 - tokens) / rate if rate > 0 else 1.0
        return False, retry_after


# ---------------------------------------------------------------------------
# Identity lookup (lightweight — only entity_uri + tenant_id needed)
# ---------------------------------------------------------------------------

_HASH_CACHE: dict[
    str, tuple[tuple[str, str, str | None], float]
] = {}  # raw-key fingerprint → (result, cached_at)
_CACHE_TTL = 60.0


def _lookup_principal(raw_key: str) -> tuple[str, str, str | None] | None:
    """Return (entity_uri, tenant_id, oidc_sub) for the raw Bearer token, or None."""
    import hashlib as _hl

    fingerprint = _hl.sha256(raw_key.encode()).hexdigest()
    if fingerprint in _HASH_CACHE:
        result, cached_at = _HASH_CACHE[fingerprint]
        if time.time() - cached_at < _CACHE_TTL:
            return result
        del _HASH_CACHE[fingerprint]

    from fastapi import HTTPException

    from .auth import lookup_principal

    try:
        principal = lookup_principal(raw_key)
    except HTTPException:
        return None
    if principal is None:
        return None
    _HASH_CACHE[fingerprint] = (principal, time.time())
    return principal


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-principal token-bucket rate limiting (spec §22.4).

    Federation endpoints (/v1/federation/) are exempt — they use peer-token
    auth, not user API keys.  Requests without a Bearer token are also exempt.
    Setting rate_limit_write_per_hour=0 AND rate_limit_read_per_hour=0
    disables quota enforcement entirely (dev/test shortcut).
    """

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if request.method == "OPTIONS":
            return await call_next(request)

        if request.url.path.startswith("/v1/federation/"):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return await call_next(request)

        # Global kill-switch: both limits=0 disables enforcement.
        if settings.rate_limit_write_per_hour == 0 and settings.rate_limit_read_per_hour == 0:
            return await call_next(request)

        raw_key = auth_header[7:]
        principal = _lookup_principal(raw_key)
        if principal is None:
            # Unknown/expired key — let auth middleware reject it properly.
            return await call_next(request)

        entity_uri, tenant_id, oidc_sub = principal
        dimension = _dimension(request.url.path, request.method)
        if dimension is None:
            return await call_next(request)

        allowed, retry_after = _check_and_consume(entity_uri, tenant_id, dimension)
        if not allowed:
            # Write-ahead: emit quota_breach audit event before returning 429.
            from .observability.audit_event import emit_nofail

            emit_nofail(
                "quota_breach",
                entity_uri=entity_uri,
                tenant_id=tenant_id,
                oidc_sub=oidc_sub,
                detail={
                    "dimension": dimension,
                    "path": request.url.path,
                    "method": request.method,
                    "retry_after": retry_after,
                },
            )
            retry_ceil = math.ceil(retry_after)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "quota_exceeded",
                    "dimension": dimension,
                    "principal": entity_uri,
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(max(retry_ceil, 1))},
            )

        return await call_next(request)
