"""Org-identity API routes — spec §19.1–§19.3, §19.5.

Routes:
  PUT  /v1/federation/manifest                        — publish/update org manifest
  GET  /v1/federation/manifest/{entity_uri_encoded}   — resolve manifest
  POST /v1/federation/capability-tokens               — issue capability token
  POST /v1/federation/capability-tokens/verify        — verify a capability token (CLI + peers)
  POST /v1/federation/capability-tokens/{token_id}/revoke — revoke token
  POST /v1/gardens/{id}/promote                       — quarantine moderation (garden-scoped)
  POST /v1/gardens/{id}/reject                        — quarantine moderation (garden-scoped)

Security requirements enforced here:
  C1: token subject MUST appear in issuer's manifest entities list.
  H1: expired manifest → reject token issuance (handled via get_peer_manifest).
  H2: TL unavailable in strict mode → HTTP 503 (not silent fallback).
  Rate-limit manifest PUT: ≤ 10 per entity_uri per hour.
  Nonce: 64-char lowercase hex (secrets.token_hex(32)).
  Cleanup: expired tokens pruned opportunistically on issuance.
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import unquote

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import Identity, resolve_identity
from ..db import db
from ..identity.capability import (
    CapabilityTokenError,
    load_node_private_key,
    sign_revocation_event,
    sign_token,
    verify_token,
)
from ..identity.manifest import (
    ManifestError,
    manifest_from_dict,
    manifest_to_dict,
    verify_manifest,
)
from ..identity.transparency_log import TransparencyLogUnavailable, make_transparency_log
from ..identity.trust_store import (
    cleanup_expired_tokens,
    get_peer_manifest,
    store_peer_manifest,
)
from ..settings import settings

router = APIRouter(tags=["identity"])
logger = logging.getLogger("stigmem.routes.identity")

# ---------------------------------------------------------------------------
# Manifest-PUT rate limiter: { entity_uri: [epoch_s, ...] } (in-process)
# ---------------------------------------------------------------------------

_MANIFEST_SUBMIT_WINDOW_S = 3600
_MANIFEST_SUBMIT_LIMIT = 10
_manifest_submit_log: dict[str, list[float]] = {}


def _check_manifest_rate_limit(entity_uri: str) -> None:
    now = time.monotonic()
    window_start = now - _MANIFEST_SUBMIT_WINDOW_S
    timestamps = [t for t in _manifest_submit_log.get(entity_uri, []) if t > window_start]
    if len(timestamps) >= _MANIFEST_SUBMIT_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"manifest PUT rate limit: max {_MANIFEST_SUBMIT_LIMIT} per hour per entity_uri",
        )
    timestamps.append(now)
    _manifest_submit_log[entity_uri] = timestamps


# ---------------------------------------------------------------------------
# PUT /v1/federation/manifest
# ---------------------------------------------------------------------------


@router.put("/v1/federation/manifest", status_code=status.HTTP_200_OK)
async def put_manifest(
    body: dict[str, Any],
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Publish or update an org manifest.

    Rate-limited to 10 submissions per entity_uri per hour.
    rotation_events arrays with > 100 entries are rejected.
    TL submission is attempted; in strict mode TL failure → 503.
    """
    if not identity.can_write():
        raise HTTPException(status_code=403, detail="write permission required")

    entity_uri = body.get("entity_uri", "")
    if not entity_uri:
        raise HTTPException(status_code=422, detail="entity_uri is required")

    _check_manifest_rate_limit(entity_uri)

    rotation_events = body.get("rotation_events", [])
    if len(rotation_events) > 100:
        raise HTTPException(
            status_code=422,
            detail="rotation_events must not exceed 100 entries",
        )

    try:
        manifest = manifest_from_dict(body)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid manifest: {exc}") from exc

    try:
        verify_manifest(manifest, trust_mode=settings.trust_mode)
    except ManifestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Phase 2a — key unification: a node may only publish its OWN manifest, signed by its
    # federation/peer-token key. Reject a manifest whose public_key diverges from this node's
    # federation pubkey (prevents an independent manifest key, the laundering precondition).
    from ..federation.peer_token import get_local_pubkey

    if manifest.public_key != get_local_pubkey():
        raise HTTPException(
            status_code=422,
            detail=(
                "manifest public_key must equal this node's federation key "
                "(Phase 2a unification)"
            ),
        )

    # Attempt transparency-log submission
    tl = make_transparency_log()
    log_entry = None
    tl_error: str | None = None

    try:
        log_entry = tl.submit(manifest_to_dict(manifest))
    except TransparencyLogUnavailable as exc:
        tl_error = str(exc)
        if settings.trust_mode == "strict":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"transparency log unavailable (strict mode rejects): {exc}",
            ) from exc
        logger.warning("TL unavailable during manifest PUT (warn mode): %s", exc)

    try:
        store_peer_manifest(entity_uri, manifest, log_entry, trust_mode=settings.trust_mode)
    except ManifestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    result: dict[str, Any] = {
        "entity_uri": entity_uri,
        "key_id": manifest.key_id,
        "issued_at": manifest.issued_at,
        "expires_at": manifest.expires_at,
    }
    if log_entry is not None:
        result["log_entry"] = {
            "log_id": log_entry.log_id,
            "log_index": log_entry.log_index,
            "leaf_hash": log_entry.leaf_hash,
            "integrated_time": log_entry.integrated_time,
        }
    if tl_error is not None:
        result["tl_warning"] = tl_error
    return result


# ---------------------------------------------------------------------------
# GET /v1/federation/manifest/{entity_uri_encoded}
# ---------------------------------------------------------------------------


@router.get("/v1/federation/manifest/{entity_uri_encoded:path}")
def get_manifest(
    entity_uri_encoded: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Resolve a peer manifest by entity_uri (URL-encoded or raw path)."""
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")

    entity_uri = unquote(entity_uri_encoded)
    manifest = get_peer_manifest(
        entity_uri, refresh_if_expired=True, trust_mode=settings.trust_mode
    )
    if manifest is None:
        raise HTTPException(status_code=404, detail="manifest not found or expired")

    with db() as conn:
        row = conn.execute(
            "SELECT log_entry_json FROM federation_manifests WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchone()

    result = manifest_to_dict(manifest)
    if row and row["log_entry_json"]:
        result["log_entry"] = json.loads(row["log_entry_json"])
    return result


# ---------------------------------------------------------------------------
# POST /v1/federation/capability-tokens
# ---------------------------------------------------------------------------


@router.post(
    "/v1/federation/capability-tokens",
    status_code=status.HTTP_201_CREATED,
)
def issue_capability_token(
    body: dict[str, Any],
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Issue a capability token.

    C1: token subject must appear in the issuer's manifest entities list.
    H1: issuer manifest must not be expired.
    Nonce: 64-char lowercase hex enforced by DB CHECK constraint.
    """
    if not identity.can_write():
        raise HTTPException(status_code=403, detail="write permission required")

    issuer = body.get("issuer", "")
    subject = body.get("subject", "")
    verb = body.get("verb", "")
    obj = body.get("object", "")
    ttl_seconds: int = int(body.get("ttl_seconds", 3600))

    if not all([issuer, subject, verb, obj]):
        raise HTTPException(
            status_code=422, detail="issuer, subject, verb, and object are required"
        )

    # M-SEC-1: enforce 90-day maximum TTL (spec §19.3.2)
    _MAX_TOKEN_TTL_SECONDS = 90 * 86400
    if ttl_seconds > _MAX_TOKEN_TTL_SECONDS:
        raise HTTPException(
            status_code=422,
            detail=f"ttl_seconds exceeds 90-day maximum ({_MAX_TOKEN_TTL_SECONDS}s)",
        )

    # BOLA guard (H-SEC-1): prevent a caller from forging tokens under a different org's identity
    if issuer != identity.entity_uri:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="issuer must match the authenticated caller entity_uri",
        )

    # H1: resolve issuer manifest (checks expiry, refreshes if needed)
    issuer_manifest = get_peer_manifest(
        issuer, refresh_if_expired=True, trust_mode=settings.trust_mode
    )
    if issuer_manifest is None:
        raise HTTPException(
            status_code=422,
            detail=f"issuer manifest not found or expired for {issuer!r} "
            "(H1: cannot issue tokens from expired manifests)",
        )

    # C1: subject must be in issuer's entities list
    if subject not in issuer_manifest.entities:
        raise HTTPException(
            status_code=403,
            detail=f"subject {subject!r} is not in issuer {issuer!r} entities list "
            "(C1: external-entity delegation not permitted)",
        )

    now = datetime.now(UTC)
    issued_at = now.isoformat()
    expiry = datetime.fromtimestamp(now.timestamp() + ttl_seconds, tz=UTC).isoformat()
    token_id = str(uuid.uuid4())
    nonce = secrets.token_hex(32)  # 64 lowercase hex chars — satisfies DB CHECK

    token_body: dict[str, Any] = {
        "token_id": token_id,
        "token_version": 1,  # nosec B105 — integer version field, not a password
        "issuer": issuer,
        "subject": subject,
        "verb": verb,
        "object": obj,
        "issued_at": issued_at,
        "expiry": expiry,
        "nonce": nonce,
    }

    # Sign token body if node_private_key is configured (C-SEC-1 / spec §19.3.2)
    if load_node_private_key() is not None:
        token_body["signature"] = sign_token(token_body)
    else:
        logger.warning(
            "STIGMEM_NODE_PRIVATE_KEY not set; issuing unsigned capability token "
            "(set the env var to enable spec-compliant signing)"
        )

    import canonicaljson

    token_json = canonicaljson.encode_canonical_json(token_body).decode()

    created_at = now.isoformat()
    with db() as conn:
        try:
            conn.execute(
                """INSERT INTO capability_tokens
                   (id, token_json, issuer, subject, verb, object,
                    issued_at, expiry, nonce, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    token_id,
                    token_json,
                    issuer,
                    subject,
                    verb,
                    obj,
                    issued_at,
                    expiry,
                    nonce,
                    created_at,
                ),
            )
        except Exception as exc:
            if "UNIQUE constraint" in str(exc):
                raise HTTPException(status_code=409, detail="nonce collision; retry") from exc
            raise

        # M-SEC-4: audit log entry for token issuance (spec §19.3.2)
        conn.execute(
            """INSERT INTO fact_audit_log
               (id, fact_id, event_type, entity_uri, oidc_sub, source, attested_key_id, detail, ts)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                token_id,  # token_id as surrogate fact_id
                "capability_issued",
                issuer,
                None,
                "system:capability",
                None,
                json.dumps(
                    {
                        "issuer": issuer,
                        "subject": subject,
                        "verb": verb,
                        "object": obj,
                        "expiry": expiry,
                    }
                ),
                created_at,
            ),
        )

    # Opportunistic cleanup of stale tokens
    try:
        cleanup_expired_tokens()
    except Exception:
        logger.exception("Best-effort expired capability token cleanup failed")

    return {
        "token_id": token_id,
        "issuer": issuer,
        "subject": subject,
        "verb": verb,
        "object": obj,
        "issued_at": issued_at,
        "expiry": expiry,
        "nonce": nonce,
        "token_json": token_json,
    }


# ---------------------------------------------------------------------------
# POST /v1/federation/capability-tokens/verify
# ---------------------------------------------------------------------------
# NOTE: this static path MUST be registered before /{token_id}/revoke so that
# FastAPI does not swallow "verify" as a {token_id} capture.


@router.post(
    "/v1/federation/capability-tokens/verify",
    status_code=status.HTTP_200_OK,
)
def verify_capability_token_endpoint(
    body: dict[str, Any],
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Verify a capability token (Spec-06-Capability-Tokens).

    Returns {"valid": true} on success, or {"valid": false, "reason": "..."}
    when the token fails any verification step (expired, bad sig, revoked, etc.).
    HTTP 200 in both cases; 422 only for a missing/malformed request body.
    """
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")

    token_json = body.get("token_json", "")
    if not token_json:
        raise HTTPException(status_code=422, detail="token_json is required")

    try:
        verify_token(
            token_json,
            lambda uri: get_peer_manifest(
                uri, refresh_if_expired=True, trust_mode=settings.trust_mode
            ),
            trust_mode=settings.trust_mode,
        )
        return {"valid": True}
    except CapabilityTokenError as exc:
        err = str(exc)
        if "revoked" in err:
            reason = "token_revoked"
        elif "expired" in err:
            reason = "token_expired"
        else:
            reason = "token_invalid"
        return {"valid": False, "reason": reason}


# ---------------------------------------------------------------------------
# POST /v1/federation/capability-tokens/{token_id}/revoke
# ---------------------------------------------------------------------------


@router.post(
    "/v1/federation/capability-tokens/{token_id}/revoke",
    status_code=status.HTTP_200_OK,
)
async def revoke_capability_token(
    token_id: str,
    body: dict[str, Any],
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Revoke a capability token and submit a revocation notice to the TL."""
    if not identity.can_write():
        raise HTTPException(status_code=403, detail="write permission required")

    now = datetime.now(UTC).isoformat()
    reason = body.get("reason", "")

    with db() as conn:
        row = conn.execute(
            "SELECT id, issuer, subject, revoked_at FROM capability_tokens WHERE id = ?",
            (token_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="capability token not found")
    if row["revoked_at"] is not None:
        raise HTTPException(status_code=409, detail="token already revoked")

    # BOLA guard: only the issuer or subject may revoke their own token.
    if row["issuer"] != identity.entity_uri and row["subject"] != identity.entity_uri:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not authorized to revoke this token: caller is not the issuer or subject",
        )

    revoke_event: dict[str, Any] = {
        "token_id": token_id,
        "revoked_by": identity.entity_uri,
        "revoked_at": now,
        "reason": reason,
    }

    # Sign revocation event (spec §19.3.4 — best-effort when key not configured)
    if load_node_private_key() is not None:
        revoke_event["signature"] = sign_revocation_event(revoke_event)

    # Submit revocation to TL (best-effort; log warning in non-strict mode)
    tl = make_transparency_log()
    tl_error: str | None = None
    tl_entry = None
    try:
        tl_entry = tl.submit(revoke_event)
    except TransparencyLogUnavailable as exc:
        tl_error = str(exc)
        if settings.trust_mode == "strict":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"transparency log unavailable during revocation (strict mode): {exc}",
            ) from exc
        logger.warning("TL unavailable during token revocation (warn mode): %s", exc)

    revoke_log_json = json.dumps(
        {
            **revoke_event,
            **(
                {
                    "tl_entry": {
                        "log_id": tl_entry.log_id,
                        "log_index": tl_entry.log_index,
                        "leaf_hash": tl_entry.leaf_hash,
                    }
                }
                if tl_entry
                else {}
            ),
        }
    )

    with db() as conn:
        conn.execute(
            "UPDATE capability_tokens SET revoked_at = ?, revoke_log = ? WHERE id = ?",
            (now, revoke_log_json, token_id),
        )
        # M-SEC-4: audit log entry for token revocation (spec §19.3.4)
        conn.execute(
            """INSERT INTO fact_audit_log
               (id, fact_id, event_type, entity_uri, oidc_sub, source, attested_key_id, detail, ts)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                token_id,  # token_id as surrogate fact_id
                "capability_revoked",
                identity.entity_uri,
                None,
                "system:capability",
                None,
                json.dumps({"reason": reason}),
                now,
            ),
        )

    result: dict[str, Any] = {"token_id": token_id, "revoked_at": now, "status": "revoked"}
    if tl_error:
        result["tl_warning"] = tl_error
    return result


# Quarantine promote/reject routes live in routes/gardens.py (registered before this
# router). Do NOT add duplicate promote/reject handlers here — gardens.py owns those
# endpoints and enforces the correct quarantine ACL (quarantine-flag check + mandatory
# moderator/admin role, no write-permission bypass).
