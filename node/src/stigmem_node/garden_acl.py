"""Garden ACL enforcement — spec §17.3, §19.5.3.

Gardens are named, ACL'd partitions above scope (v0.9).
ACL is checked at fact read and write time in addition to scope enforcement.
Quarantine gardens extend this with the quarantine:moderator role (v1.1).
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from .auth import Identity
from .db import db


def get_garden_by_slug_or_id(
    slug_or_id: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Return a garden row by slug or by its UUID id.

    When tenant_id is provided, slug lookups are scoped to that tenant so that
    the same slug used by different tenants resolves to the correct garden.
    UUID lookups are globally unique and do not require tenant scoping.
    """
    with db() as conn:
        if tenant_id is not None:
            # Slug lookup scoped to tenant; UUID lookup is always unique
            row = conn.execute(
                "SELECT * FROM gardens WHERE (slug = ? AND tenant_id = ?) OR id = ?",
                (slug_or_id, tenant_id, slug_or_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM gardens WHERE slug = ? OR id = ?",
                (slug_or_id, slug_or_id),
            ).fetchone()
    return dict(row) if row is not None else None


def get_garden_by_garden_uri(
    garden_uri: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Return a garden row by its stigmem://authority/garden/{slug} URI."""
    # Extract slug from URI: stigmem://authority/garden/{slug}
    parts = garden_uri.split("/garden/", 1)
    if len(parts) != 2 or not parts[1]:
        return None
    slug = parts[1].rstrip("/")
    return get_garden_by_slug_or_id(slug, tenant_id=tenant_id)


def get_member_role(garden_id: str, entity_uri: str) -> str | None:
    """Return the role of entity_uri in the given garden UUID, or None if not a member."""
    with db() as conn:
        row = conn.execute(
            "SELECT role FROM garden_members WHERE garden_id = ? AND entity_uri = ?",
            (garden_id, entity_uri),
        ).fetchone()
    return row["role"] if row is not None else None


def require_garden_write(garden: dict[str, Any], identity: Identity) -> None:
    """Raise 403 if identity cannot write facts into this garden (spec §17.3)."""
    role = get_member_role(garden["id"], identity.entity_uri)
    if role not in ("admin", "writer"):
        if role == "reader":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="write permission required — you are a reader in this garden",
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not a member of this garden",
        )


def require_garden_read(garden: dict[str, Any], identity: Identity) -> None:
    """Raise 403 if identity cannot read facts from this garden (spec §17.3)."""
    role = get_member_role(garden["id"], identity.entity_uri)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="not a member of this garden",
        )


def require_garden_admin(garden: dict[str, Any], identity: Identity) -> None:
    """Raise 403 if identity is not an admin of this garden."""
    role = get_member_role(garden["id"], identity.entity_uri)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="garden admin permission required",
        )


def caller_can_see_garden(garden_id: str, identity: Identity) -> bool:
    """Return True if identity holds any role in the garden (for query-time filtering)."""
    role = get_member_role(garden_id, identity.entity_uri)
    return role is not None


def require_fact_garden_read(conn: Any, fact_id: str, tenant_id: str, identity: Identity) -> None:
    """Raise 404 if a fact-by-id is in a (projected) garden the caller cannot see.

    Shared gate for fact-by-id read surfaces (single get, provenance, cid verify)
    so a restricted-garden fact's existence/content/lineage stays hidden from
    same-tenant non-members (spec §17.3). Uses the PROJECTED garden
    ``COALESCE(fact_garden_membership.garden_id, facts.garden_id)`` — a fact
    promoted into a garden has raw ``garden_id`` NULL. Hides as 404 (not 403) so
    existence is not revealed. No-op for garden-less facts or unknown ids.
    """
    row = conn.execute(
        "SELECT COALESCE(fgm.garden_id, f.garden_id) AS gid FROM facts f"
        " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
        " WHERE f.id = ? AND f.tenant_id = ?",
        (fact_id, tenant_id),
    ).fetchone()
    if row is None or row["gid"] is None:
        return
    if not caller_can_see_garden(row["gid"], identity):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="fact not found")


def is_node_admin(identity: Identity) -> bool:
    """Node admin: any identity with write permission (spec §5.15)."""
    return identity.can_write()


def require_quarantine_moderator_or_admin(garden: dict[str, Any], identity: Identity) -> None:
    """Raise 403 if identity cannot promote/reject quarantined facts (spec §19.5.3).

    This helper checks garden-scoped moderation roles only: 'admin' or
    'quarantine:moderator' in the quarantine garden membership table.
    Route-level callers intentionally allow node admins through before this
    helper runs. Node-admin bypass is intentional because node admins are the
    system's last-resort moderation authority; garden-scoped moderators must
    still be members of the specific quarantine garden.
    """
    role = get_member_role(garden["id"], identity.entity_uri)
    if role not in ("admin", "quarantine:moderator"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="quarantine:moderator or admin role required to promote/reject facts",
        )


def has_elevated_quarantine_role(garden: dict[str, Any], identity: Identity) -> bool:
    """True if identity holds admin or quarantine:moderator in a quarantine garden."""
    role = get_member_role(garden["id"], identity.entity_uri)
    return role in ("admin", "quarantine:moderator")


def quarantine_garden_has_pending_facts(garden_uuid: str) -> bool:
    """True if the quarantine garden holds at least one fact with quarantine_status='pending'."""
    with db() as conn:
        row = conn.execute(
            "SELECT f.id FROM facts f"
            " LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id"
            " WHERE COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id) = ?"
            " AND COALESCE(fqs.quarantine_status, f.quarantine_status) = 'pending'"
            " LIMIT 1",
            (garden_uuid,),
        ).fetchone()
    return row is not None
