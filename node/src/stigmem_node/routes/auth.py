"""Track B / B3 + C2 — OIDC → scoped API-key exchange bridge.

POST /v1/auth/oidc/exchange   validate id_token, mint/refresh a scoped key
POST /v1/auth/keys            register a caller-provided static API key (admin)
GET  /v1/auth/keys            list caller's own keys
DELETE /v1/auth/keys/{key_id} revoke a specific key

C2 addition: when the experimental memory-garden advanced ACL plugin and its
explicit OIDC ceiling gate are enabled, permissions are capped by the caller's
garden membership role. admin/writer in any garden → up to ["read","write"];
reader/no membership → ["read"].

``POST /v1/auth/keys`` is the supported post-bootstrap path for minting
additional static (non-OIDC) keys.  It mirrors the bootstrap CLI's
caller-generated-key posture: the caller supplies the raw key material;
the node hashes and stores it.  The endpoint requires the caller to
hold the ``admin`` capability.  Spec §3.5.  Closes issue #135.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..audit_event import emit as audit_emit
from ..auth import (
    Identity,
    create_api_key,
    find_api_key_id_by_raw_key,
    register_api_key,
    resolve_identity,
)
from ..db import db
from ..memory_garden_acl_gate import oidc_permission_ceiling_enabled
from ..models.auth import (
    ExchangeRequest,
    ExchangeResponse,
    ExpiringKeyInfo,
    KeyInfo,
    RegisterKeyRequest,
    RegisterKeyResponse,
)
from ..net_util import assert_safe_url
from ..settings import settings
from ..tenant import TenantIdError

logger = logging.getLogger("stigmem.auth")
router = APIRouter(prefix="/v1/auth", tags=["auth"])

# ---------------------------------------------------------------------------
# JWKS cache — keyed by issuer URL, value = (jwks_client, fetched_at_unix)
# ---------------------------------------------------------------------------
_JWKS_CACHE: dict[str, tuple[jwt.PyJWKClient, float]] = {}
_JWKS_CACHE_TTL = 600  # 10 minutes


def _get_jwks_client(issuer_url: str) -> jwt.PyJWKClient:
    entry = _JWKS_CACHE.get(issuer_url)
    now = time.monotonic()
    if entry and (now - entry[1]) < _JWKS_CACHE_TTL:
        return entry[0]

    # Discover JWKS URI from OIDC metadata document
    disco_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    try:
        assert_safe_url(disco_url, allow_schemes=frozenset({"https"}))
        resp = httpx.get(disco_url, timeout=5.0, follow_redirects=False)
        resp.raise_for_status()
        jwks_uri: str = resp.json()["jwks_uri"]
        assert_safe_url(jwks_uri, allow_schemes=frozenset({"https"}))
    except Exception as exc:
        logger.warning("OIDC discovery failed for %s: %s", issuer_url, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider discovery failed",
        ) from exc

    client = jwt.PyJWKClient(jwks_uri)
    _JWKS_CACHE[issuer_url] = (client, now)
    return client


def _verify_id_token(id_token: str) -> dict[str, Any]:
    """Validate the id_token and return decoded claims. Raises HTTPException on failure."""
    jwks_client = _get_jwks_client(settings.oidc_issuer_url)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims: dict[str, Any] = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=settings.oidc_id_token_algorithms,
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer_url,
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="id_token expired",
        ) from exc
    except jwt.InvalidAudienceError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="id_token audience mismatch",
        ) from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"id_token invalid: {exc}",
        ) from exc
    return claims


def _check_domain(email: str | None) -> None:
    """Enforce oidc_allowed_domains if configured."""
    if not settings.oidc_allowed_domains or not email:
        return
    allowed = {d.strip().lower() for d in settings.oidc_allowed_domains.split(",") if d.strip()}
    if not allowed:
        return
    domain = email.split("@", 1)[-1].lower()
    if domain not in allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Email domain '{domain}' is not permitted",
        )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

_ALLOWED_PERMISSIONS = {"read", "write"}
_PERM_ORDER = ["read", "write"]


def _derive_permission_ceiling(entity_uri: str) -> set[str]:
    """Return the max permissions the entity is entitled to via garden membership.

    admin/writer role in any garden → {"read","write"}
    reader role only, or no membership → {"read"}
    """
    with db() as conn:
        rows = conn.execute(
            "SELECT role FROM garden_members WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchall()
    roles = {r["role"] for r in rows}
    if "admin" in roles or "writer" in roles:
        return {"read", "write"}
    return {"read"}


# ---------------------------------------------------------------------------
# Static key registration (POST /v1/auth/keys) — issue #135
#
# Permission vocabulary kept narrow to the §3.5 set the auth module already
# defines.  Source-attestation-specific fields (``allowed_source_entities``,
# attestation-mode binding) are deferred to §18 per ADR-002 and are NOT
# accepted here.  See spec/EVOLUTION.md § §18 for the deferred surface.
# ---------------------------------------------------------------------------

_STATIC_KEY_ALLOWED_PERMISSIONS: frozenset[str] = frozenset(
    {"read", "write", "instruction:write", "federate", "admin", "audit.read"}
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/oidc/exchange", response_model=ExchangeResponse)
def oidc_exchange(body: ExchangeRequest) -> ExchangeResponse:
    """Exchange an OIDC id_token for a scoped stigmem API key."""
    if not settings.oidc_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC authentication is not enabled on this node",
        )

    claims = _verify_id_token(body.id_token)
    sub: str = claims["sub"]
    email: str | None = claims.get("email")
    _check_domain(email)

    entity_uri = f"oidc:{sub}"

    # Experimental memory-garden advanced ACL: cap permissions by garden membership
    # only when the plugin and its explicit OIDC ceiling gate are enabled.
    requested = {p for p in body.permissions if p in _ALLOWED_PERMISSIONS}
    if oidc_permission_ceiling_enabled():
        requested &= _derive_permission_ceiling(entity_uri)
    if not requested:
        requested = {"read"}
    permissions = sorted(requested, key=lambda p: _PERM_ORDER.index(p))

    expires_at = (datetime.now(UTC) + timedelta(hours=settings.oidc_token_ttl_hours)).isoformat()

    # Rotate: revoke all previous OIDC-issued keys for this sub before minting
    # a new one.  This ensures a single valid session per sub so that IdP
    # session-termination (logout, account suspension) immediately invalidates
    # access — offboarding comes for free from the IdP.
    with db() as conn:
        conn.execute("DELETE FROM api_keys WHERE oidc_sub = ?", (sub,))

    raw_key = create_api_key(
        entity_uri=entity_uri,
        permissions=permissions,
        description=f"OIDC session for {email or sub}",
        expires_at=expires_at,
        oidc_sub=sub,
    )

    logger.info("OIDC exchange: sub=%s entity_uri=%s perms=%s", sub, entity_uri, permissions)
    return ExchangeResponse(
        api_key=raw_key,
        entity_uri=entity_uri,
        permissions=permissions,
        expires_at=expires_at,
    )


@router.post(
    "/keys",
    response_model=RegisterKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a caller-provided static API key (admin only).",
)
def register_static_key(
    body: RegisterKeyRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> RegisterKeyResponse:
    """Register a caller-provided raw API key.

    Mirrors the bootstrap CLI's posture: the caller supplies the raw key
    material; the node hashes and stores it.  The endpoint requires the
    caller to hold the ``admin`` capability — typically the bootstrap
    key, or a previously-minted admin-scoped key.

    The response NEVER echoes the raw key; the caller already has it.
    """
    if not identity.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin permission required to mint API keys",
        )

    # Validate the permission set.  Reject unknown vocabulary up front so a
    # typo (`"writes"`) doesn't silently create an unintentionally-scoped key.
    requested_perms = set(body.permissions)
    invalid = requested_perms - _STATIC_KEY_ALLOWED_PERMISSIONS
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown permissions: {sorted(invalid)}; "
                f"allowed: {sorted(_STATIC_KEY_ALLOWED_PERMISSIONS)}"
            ),
        )
    if not requested_perms:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="permissions list must be non-empty",
        )

    # Refuse duplicate raw credentials before hashing. Argon2id uses a fresh
    # salt for each hash, so duplicate detection must verify existing rows
    # rather than relying on the key_hash unique constraint.
    if find_api_key_id_by_raw_key(body.raw_key) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="raw_key already exists; generate a new key value",
        )

    # Minting a key in a tenant other than the caller's own is a cross-tenant
    # privilege escalation (audit M2): a tenant-scoped admin could otherwise mint
    # an admin key in any other tenant. Require the elevated cross-cutting
    # admin:federation capability to cross the tenant boundary; default same-tenant.
    target_tenant = body.tenant_id or identity.tenant_id
    if target_tenant != identity.tenant_id and not identity.can_admin_federation():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cannot mint keys in a tenant other than your own",
        )

    # Persist via the existing helper.  Caller-provided raw_key, never
    # auto-generated.
    permissions_sorted = sorted(requested_perms)
    # ``registered_id`` is the UUID bookkeeping handle for the new row, NOT
    # credential material.  The raw key value never enters this scope —
    # ``register_api_key`` hashes it inside the helper.  Naming hygiene
    # here keeps CodeQL's ``py/clear-text-logging-sensitive-data`` name
    # heuristic (which matches any variable containing ``key``) from
    # false-flagging the audit log below.  Same precedent as PR #106.
    try:
        registered_id = register_api_key(
            raw_key=body.raw_key,
            entity_uri=body.entity_uri,
            permissions=permissions_sorted,
            description=body.description,
            expires_at=body.expires_at,
            tenant_id=target_tenant,
        )
    except TenantIdError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        if "max age" in str(exc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="raw_key already exists; generate a new key value",
        ) from exc

    # Read back canonical values so audit and response use normalized tenant ID.
    with db() as conn:
        row = conn.execute(
            "SELECT created_at, expires_at, tenant_id FROM api_keys WHERE id = ?",
            (registered_id,),
        ).fetchone()
    normalized_tenant = row["tenant_id"] or "default"

    # Audit: spec §22.3.1 maps lifecycle ops on admin surfaces to
    # ``admin_action``.  Detail captures the new key's identity and the
    # caller's identity for accountability.
    audit_emit(
        "admin_action",
        entity_uri=identity.entity_uri,
        tenant_id=normalized_tenant,
        detail={
            "action": "api_key_register",
            "new_key_id": registered_id,
            "target_entity_uri": body.entity_uri,
            "permissions": permissions_sorted,
            "has_expiry": body.expires_at is not None,
        },
    )

    # Deliberately no ``logger.info`` here.  The ``audit_emit`` above is
    # the authoritative record (event_type=admin_action), and a structured
    # log line is operator-grep convenience at best.  CodeQL's
    # ``py/clear-text-logging-sensitive-data`` taints any value that
    # transitively flows from the request body's ``raw_key`` field —
    # including the UUID returned by ``register_api_key`` (which takes
    # ``raw_key`` as an argument).  No combination of message wording
    # or local-variable substitution clears the taint while still
    # logging something useful.  Operators query the audit log instead:
    #
    #     SELECT * FROM fact_audit_log
    #      WHERE event_type='admin_action'
    #        AND detail LIKE '%api_key_register%'
    #      ORDER BY ts DESC;
    #
    # Same family as Pattern 4 / Pattern 12 in the lessons file —
    # design-pivot away from the heuristic rather than fight it.

    return RegisterKeyResponse(
        id=registered_id,
        entity_uri=body.entity_uri,
        permissions=permissions_sorted,
        description=body.description,
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        tenant_id=normalized_tenant,
    )


@router.get("/keys", response_model=list[KeyInfo])
def list_keys(identity: Annotated[Identity, Depends(resolve_identity)]) -> list[KeyInfo]:
    """List all non-expired API keys belonging to the caller's entity_uri."""
    with db() as conn:
        rows = conn.execute(
            """SELECT id, entity_uri, permissions, description, created_at, expires_at, oidc_sub
               FROM api_keys
               WHERE entity_uri = ?
                 AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY created_at DESC""",
            (identity.entity_uri, datetime.now(UTC).isoformat()),
        ).fetchall()
    return [
        KeyInfo(
            id=r["id"],
            entity_uri=r["entity_uri"],
            permissions=json.loads(r["permissions"]),
            description=r["description"],
            created_at=r["created_at"],
            expires_at=r["expires_at"],
            oidc_sub=r["oidc_sub"],
        )
        for r in rows
    ]


@router.get("/keys/expiring-soon", response_model=list[ExpiringKeyInfo])
def list_expiring_keys(
    identity: Annotated[Identity, Depends(resolve_identity)],
    within_days: Annotated[
        int,
        Query(
            ge=1,
            le=365,
            description="Return active keys expiring within this many days.",
        ),
    ] = settings.api_key_expiring_soon_days,
) -> list[ExpiringKeyInfo]:
    """List active API keys approaching expiry (admin only)."""
    if not identity.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin permission required to list expiring API keys",
        )

    now = datetime.now(UTC)
    cutoff = now + timedelta(days=within_days)
    with db() as conn:
        rows = conn.execute(
            """SELECT id, entity_uri, permissions, description, created_at,
                      expires_at, oidc_sub, tenant_id
               FROM api_keys
               WHERE expires_at IS NOT NULL
                 AND expires_at > ?
                 AND expires_at <= ?
               ORDER BY expires_at ASC, created_at DESC""",
            (now.isoformat(), cutoff.isoformat()),
        ).fetchall()

    result: list[ExpiringKeyInfo] = []
    for r in rows:
        expires_at = datetime.fromisoformat(r["expires_at"].replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        days_remaining = (expires_at.astimezone(UTC) - now).total_seconds() / 86_400
        result.append(
            ExpiringKeyInfo(
                id=r["id"],
                entity_uri=r["entity_uri"],
                permissions=json.loads(r["permissions"]),
                description=r["description"],
                created_at=r["created_at"],
                expires_at=r["expires_at"],
                oidc_sub=r["oidc_sub"],
                tenant_id=r["tenant_id"] or "default",
                days_remaining=max(days_remaining, 0.0),
            )
        )
    return result


@router.delete("/keys/{key_id}", status_code=204)
def revoke_key(
    key_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> None:
    """Revoke a specific API key. Callers may only revoke their own keys."""
    with db() as conn:
        row = conn.execute("SELECT entity_uri FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
        if row["entity_uri"] != identity.entity_uri:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot revoke another entity's key",
            )
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
    logger.info("Key revoked: id=%s by entity=%s", key_id, identity.entity_uri)
