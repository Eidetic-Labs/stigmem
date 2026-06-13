"""API-key authentication for the Stigmem reference node.

Auth model (spec §3.5):
  - Callers present `Authorization: Bearer <raw-key>` on every request.
  - Raw keys are never stored; only an Argon2id hash is persisted.
  - Legacy SHA-256 hex digests are accepted during the v0.9.x migration
    window and are opportunistically rehashed to Argon2id on successful use.
  - Each key maps to an entity_uri and a JSON-array of permissions:
    ["read"], ["read","write"], or ["read","write","federate"].
  - `STIGMEM_AUTH_REQUIRED` defaults to **True** — every request must
    present a valid Bearer token. Set `STIGMEM_AUTH_REQUIRED=false` to
    opt into anonymous-mode for single-operator development; this is
    NOT appropriate for any deployment that accepts requests from
    agents you don't fully control. See LIMITATIONS.md §"LLM agents
    holding admin-scope API keys" for context.

Bootstrapping the first key (single-operator install):
  $ KEY=$(openssl rand -hex 32)
  $ stigmem auth bootstrap-key --key "$KEY"
  # then use $KEY as `Authorization: Bearer $KEY` for subsequent requests.

  The system NEVER generates the key — the caller provides the value and
  retains full custody. We hash and store it. This is by design:
  removing the system as the credential-generation surface eliminates
  the "reveal channel" risk entirely. The command refuses to run when
  api_keys is non-empty (bootstrap is one-shot); after bootstrap,
  additional keys go through `POST /v1/auth/keys`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
from argon2.low_level import Type
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .db import db
from .multi_tenant_gate import warn_if_tenant_not_isolatable
from .plugins import Deny, TenantContext, get_registry
from .settings import settings as settings
from .tenant import DEFAULT_TENANT_ID, TenantIdError, validate_tenant_id

_ARGON2_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)
_LEGACY_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

logger = logging.getLogger("stigmem.auth")


def _hash_key(raw: str) -> str:
    """Return the persisted hash format for newly issued API keys."""
    return _ARGON2_HASHER.hash(raw)


def _legacy_sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _is_legacy_sha256_hash(stored_hash: str) -> bool:
    return bool(_LEGACY_SHA256_HEX.fullmatch(stored_hash))


def _legacy_sha256_allowed() -> bool:
    deadline = settings.legacy_sha256_accept_until
    if deadline is None:
        return True
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    return datetime.now(UTC) <= deadline.astimezone(UTC)


def _raise_legacy_sha256_disabled() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Legacy API key hashes are no longer accepted; rotate the key.",
    )


def _verify_key_hash(raw_key: str, stored_hash: str) -> bool:
    """Verify *raw_key* against either current Argon2id or legacy SHA-256."""
    if stored_hash.startswith("$argon2id$"):
        try:
            return _ARGON2_HASHER.verify(stored_hash, raw_key)
        except VerifyMismatchError:
            return False
        except VerificationError:
            return False
        except InvalidHash:
            return False
    if _is_legacy_sha256_hash(stored_hash):
        if not _legacy_sha256_allowed():
            _raise_legacy_sha256_disabled()
        matched = hmac.compare_digest(stored_hash, _legacy_sha256(raw_key))
        if matched:
            # F-SAUTH2: a legacy unsalted SHA-256 key hash was accepted. Emit a
            # per-acceptance deprecation warning so operators see exactly which
            # auth events still rely on the weaker legacy format and can force
            # rotation before setting a cutoff (legacy_sha256_accept_until).
            logger.warning(
                "DEPRECATION: accepted a legacy unsalted SHA-256 API-key hash. "
                "Unsalted SHA-256 is weaker than the Argon2id default; this key "
                "is opportunistically rehashed on success — rotate any keys that "
                "do not rehash, and set STIGMEM_LEGACY_SHA256_ACCEPT_UNTIL to bound "
                "the migration window."
            )
        return matched
    return False


def _row_expired(row: Any, now: str) -> bool:
    expires_at = row["expires_at"]
    return bool(expires_at and expires_at < now)


def _parse_api_key_expiry(expires_at: str) -> datetime:
    normalized = expires_at.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalize_api_key_expiry(
    expires_at: str | None,
    *,
    created_at: datetime,
) -> str | None:
    """Apply static API-key max-age policy and return the persisted expiry."""
    max_age_days = settings.api_key_max_age_days
    if max_age_days <= 0:
        return expires_at

    max_expires_at = created_at + timedelta(days=max_age_days)
    if expires_at is None:
        return max_expires_at.isoformat()

    requested_expires_at = _parse_api_key_expiry(expires_at)
    if requested_expires_at > max_expires_at:
        raise ValueError(
            "expires_at exceeds configured static API key max age "
            f"({max_age_days} days)"
        )
    return requested_expires_at.isoformat()


def _rehash_legacy_key(conn: Any, row: Any, raw_key: str) -> None:
    """Rewrite one verified legacy SHA-256 key row to Argon2id and audit it."""
    new_hash = _hash_key(raw_key)
    conn.execute(
        "UPDATE api_keys SET key_hash = ? WHERE id = ? AND key_hash = ?",
        (new_hash, row["id"], row["key_hash"]),
    )

    from .observability.audit_event import emit

    emit(
        "api_key_rehashed",
        entity_uri=row["entity_uri"],
        tenant_id=row["tenant_id"] or "default",
        oidc_sub=row["oidc_sub"],
        source="system:auth",
        detail={
            "key_id": row["id"],
            "from": "sha256",
            "to": "argon2id",
        },
        conn=conn,
    )


def _select_key_rows(conn: Any) -> list[Any]:
    return list(
        conn.execute(
            "SELECT id, key_hash, entity_uri, permissions, expires_at, oidc_sub, tenant_id"
            " FROM api_keys"
        ).fetchall()
    )


def _find_key_row(
    raw_key: str,
    *,
    include_expired: bool = False,
    rehash_legacy: bool = False,
) -> Any | None:
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        legacy_row = conn.execute(
            "SELECT id, key_hash, entity_uri, permissions, expires_at, oidc_sub, tenant_id"
            " FROM api_keys WHERE key_hash = ?",
            (_legacy_sha256(raw_key),),
        ).fetchone()
        if legacy_row is not None and (include_expired or not _row_expired(legacy_row, now)):
            if not _legacy_sha256_allowed():
                _raise_legacy_sha256_disabled()
            if rehash_legacy:
                _rehash_legacy_key(conn, legacy_row, raw_key)
                legacy_row = conn.execute(
                    "SELECT id, key_hash, entity_uri, permissions, expires_at, oidc_sub, tenant_id"
                    " FROM api_keys WHERE id = ?",
                    (legacy_row["id"],),
                ).fetchone()
            return legacy_row

        for row in _select_key_rows(conn):
            if not include_expired and _row_expired(row, now):
                continue
            if _verify_key_hash(raw_key, row["key_hash"]):
                if rehash_legacy and _is_legacy_sha256_hash(row["key_hash"]):
                    _rehash_legacy_key(conn, row, raw_key)
                    row = conn.execute(
                        "SELECT id, key_hash, entity_uri, permissions, expires_at, oidc_sub,"
                        " tenant_id FROM api_keys WHERE id = ?",
                        (row["id"],),
                    ).fetchone()
                return row
    return None


def find_api_key_id_by_raw_key(raw_key: str) -> str | None:
    """Return the stored key id for *raw_key*, including expired rows."""
    row = _find_key_row(raw_key, include_expired=True, rehash_legacy=False)
    return row["id"] if row is not None else None


def lookup_principal(raw_key: str) -> tuple[str, str, str | None] | None:
    """Return (entity_uri, tenant_id, oidc_sub) for a non-expired raw key."""
    row = _find_key_row(raw_key, include_expired=False, rehash_legacy=False)
    if row is None:
        return None
    return (row["entity_uri"], row["tenant_id"] or "default", row["oidc_sub"])


BEARER = HTTPBearer(auto_error=False)


class Identity:
    """Resolved caller identity (spec §3.5)."""

    def __init__(
        self,
        entity_uri: str,
        permissions: list[str],
        oidc_sub: str | None = None,
        tenant_id: str = "default",
    ) -> None:
        self.entity_uri = entity_uri
        self.permissions = set(permissions)
        self.oidc_sub = oidc_sub
        self.tenant_id = tenant_id

    def can_read(self) -> bool:
        return self._has_capability("read")

    def can_write(self) -> bool:
        return self._has_capability("write")

    def can_write_instruction(self) -> bool:
        return self._has_capability("instruction:write")

    def can_federate(self) -> bool:
        return self._has_capability("federate")

    def can_admin_federation(self) -> bool:
        return self._has_capability("admin:federation")

    def can_audit(self) -> bool:
        """True when the principal holds the audit.read capability (spec §22.3)."""
        return self._has_capability("audit.read")

    def is_admin(self) -> bool:
        """True when the principal holds the admin capability (spec §24.3.2)."""
        return self._has_capability("admin")

    def _has_capability(self, capability: str) -> bool:
        if capability not in self.permissions:
            return False
        decision = get_registry().fire_voting(
            "capability_check",
            identity=self,
            capability=capability,
            tenant=TenantContext(
                tenant_id=self.tenant_id,
                metadata={"tenant_context_source": "hook"},
            ),
        )
        return not isinstance(decision, Deny)


_ANON = Identity("anon:trusted", ["read", "write", "federate"], tenant_id="default")


def resolve_identity(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(BEARER)],
) -> Identity:
    """Dependency: resolve caller identity from Bearer token.

    If auth is disabled, returns a fully-trusted anonymous identity.
    If auth is enabled, the token must match a non-expired api_keys row.
    """
    if not settings.auth_required:
        if creds is not None:
            # Still try to resolve a real identity even in non-required mode
            identity = _lookup(creds.credentials)
            if identity:
                return _apply_identity_hooks(identity, raw_credentials=creds.credentials)
        return _apply_identity_hooks(_ANON, raw_credentials=None)

    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    identity = _lookup(creds.credentials)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _apply_identity_hooks(identity, raw_credentials=creds.credentials)


def resolve_identity_optional(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(BEARER)],
) -> Identity | None:
    """Dependency: resolve identity from Bearer token without the auth_required gate.

    Returns None when no credential is supplied or the credential is invalid/expired.
    Used by routes that handle auth themselves (e.g. /metrics with metrics_require_auth).
    """
    if creds is None:
        return None
    identity = _lookup(creds.credentials)
    if identity is None:
        return None
    return _apply_identity_hooks(identity, raw_credentials=creds.credentials)


def _apply_identity_hooks(identity: Identity, raw_credentials: str | None) -> Identity:
    registry = get_registry()
    resolved = registry.fire_filter_chain(
        "identity_resolve",
        identity,
        raw_credentials=raw_credentials,
    )
    tenant = registry.fire_filter_chain(
        "tenant_resolve",
        TenantContext(
            tenant_id=DEFAULT_TENANT_ID,
            metadata={
                "source_tenant_id": resolved.tenant_id,
                "tenant_context_source": "hook",
            },
        ),
        identity=resolved,
    )
    try:
        resolved_tenant_id = validate_tenant_id(tenant.tenant_id)
    except TenantIdError:
        resolved_tenant_id = DEFAULT_TENANT_ID
    if resolved_tenant_id != resolved.tenant_id:
        return Identity(
            entity_uri=resolved.entity_uri,
            permissions=sorted(resolved.permissions),
            oidc_sub=resolved.oidc_sub,
            tenant_id=resolved_tenant_id,
        )
    return resolved


def _lookup(raw_key: str) -> Identity | None:
    row = _find_key_row(raw_key, include_expired=False, rehash_legacy=True)
    if row is None:
        return None
    perms: list[str] = json.loads(row["permissions"])
    return Identity(
        entity_uri=row["entity_uri"],
        permissions=perms,
        oidc_sub=row["oidc_sub"],
        tenant_id=row["tenant_id"] or "default",
    )


def register_api_key(
    raw_key: str,
    entity_uri: str,
    permissions: list[str] | None = None,
    description: str | None = None,
    expires_at: str | None = None,
    oidc_sub: str | None = None,
    tenant_id: str = "default",
) -> str:
    """Persist the hash of a caller-provided raw API key. Returns the key_id.

    The caller is responsible for generating `raw_key` (e.g., from
    `secrets.token_hex(32)` or `openssl rand -hex 32`) and for storing it
    securely. This function never touches the key after hashing.
    """
    if permissions is None:
        permissions = ["read", "write"]
    if find_api_key_id_by_raw_key(raw_key) is not None:
        raise ValueError("raw API key already exists")
    normalized_tenant_id = validate_tenant_id(tenant_id)
    # F-ID-1: a non-default tenant collapses to the default tenant without the
    # multi-tenant plugin — warn loudly rather than silently mislead the operator.
    warn_if_tenant_not_isolatable(normalized_tenant_id)
    key_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).replace(microsecond=0)
    normalized_expires_at = _normalize_api_key_expiry(
        expires_at,
        created_at=created_at,
    )
    with db() as conn:
        conn.execute(
            """INSERT INTO api_keys
               (id, key_hash, entity_uri, permissions, description,
                created_at, expires_at, oidc_sub, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                key_id,
                _hash_key(raw_key),
                entity_uri,
                json.dumps(permissions),
                description,
                created_at.isoformat(),
                normalized_expires_at,
                oidc_sub,
                normalized_tenant_id,
            ),
        )
    return key_id


def create_api_key(
    entity_uri: str,
    permissions: list[str] | None = None,
    description: str | None = None,
    expires_at: str | None = None,
    oidc_sub: str | None = None,
    tenant_id: str = "default",
) -> str:
    """Mint a new raw API key, persist its hash, and return the raw key.

    Internal/test-only convenience over `register_api_key`. Adopter-facing
    flows should require the caller to provide the key material (see
    `stigmem auth bootstrap-key`) so the system is never the credential
    generation surface.
    """
    raw = str(uuid.uuid4()).replace("-", "")  # 32-char hex
    register_api_key(
        raw_key=raw,
        entity_uri=entity_uri,
        permissions=permissions,
        description=description,
        expires_at=expires_at,
        oidc_sub=oidc_sub,
        tenant_id=tenant_id,
    )
    return raw
