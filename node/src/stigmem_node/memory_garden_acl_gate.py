"""Garden ACL recall filtering (graduated to core) + remaining experimental gates."""

from __future__ import annotations

from logging import Logger
from typing import Any

from .db import db


def _live_settings() -> Any:
    import sys

    return sys.modules["stigmem_node.settings"].settings


def oidc_permission_ceiling_enabled() -> bool:
    """Garden-membership-derived OIDC permission ceiling — graduated to core.

    Off by default (see ``settings.oidc_permission_ceiling``): enabling it caps
    OIDC-issued permissions to what the caller's garden memberships grant.
    """
    return bool(_live_settings().oidc_permission_ceiling)


def recall_filter_enabled() -> bool:
    """Cross-surface garden ACL recall filtering — graduated to core (default-on).

    Closes the cross-garden read leak (F-CONF-1): tenant-wide recall, query, graph
    traversal, and subscription delivery are restricted to gardens the caller is a
    member of. Single-tenant installs are unaffected (their facts have
    ``garden_id`` NULL). Opt out via ``STIGMEM_MEMORY_GARDEN_ACL_RECALL_FILTER=false``.
    """
    return bool(_live_settings().memory_garden_acl_recall_filter)


def memory_garden_acl_filtering_state() -> str:
    """Return the operator-visible advanced ACL filtering posture.

    ``disabled`` means default core behavior is active: direct garden reads and
    writes are guarded, but tenant-wide query, recall, graph, OIDC ceiling, and
    subscription-delivery filtering are not all enabled.
    """
    if not garden_acl_enforced():
        return "disabled"
    if oidc_permission_ceiling_enabled():
        return "enabled-full"
    return "enabled-partial"


def gardens_with_members_exist() -> bool:
    """Return True when at least one garden membership row exists."""
    with db() as conn:
        row = conn.execute("SELECT 1 FROM garden_members LIMIT 1").fetchone()
    return row is not None


def garden_acl_enforced() -> bool:
    """True when the garden access boundary must be enforced on read surfaces.

    Fail-closed: enforced when the operator flag is on OR — regardless of the
    flag — whenever any garden-with-members exists. The flag can never *disable*
    the boundary once gardens exist; it can only be a no-op when there is nothing
    to protect (no garden-with-members → every fact's ``garden_id`` is NULL, so
    filtering changes nothing). Call once per request, not per fact.
    """
    if bool(_live_settings().memory_garden_acl_recall_filter):
        return True
    return gardens_with_members_exist()


def caller_visible_gardens(identity: Any) -> frozenset[str]:
    """Garden ids the caller is a member of — one query, for in-memory filtering.

    Lets callers batch the membership check (O(1) per fact against this set)
    instead of one DB lookup per candidate fact, so there is no performance
    reason to ever disable the boundary.
    """
    entity_uri = getattr(identity, "entity_uri", None)
    if entity_uri is None:
        return frozenset()
    with db() as conn:
        rows = conn.execute(
            "SELECT garden_id FROM garden_members WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchall()
    return frozenset(row["garden_id"] for row in rows)


def warn_if_memory_garden_acl_filtering_disabled(logger: Logger) -> None:
    """Inform at startup when the disable flag is set but ACL stays enforced.

    The flag cannot create a leak: once gardens-with-members exist the boundary
    is enforced regardless (see ``garden_acl_enforced``). This logs that the
    operator's opt-out is being overridden for safety, rather than warning of a
    leak that can no longer happen.
    """
    flag_off = not bool(_live_settings().memory_garden_acl_recall_filter)
    if not flag_off or not gardens_with_members_exist():
        return
    logger.warning(
        "Garden ACL recall filtering flag is OFF "
        "(STIGMEM_MEMORY_GARDEN_ACL_RECALL_FILTER=false) but gardens with members "
        "exist, so the garden access boundary remains ENFORCED on recall, query, "
        "graph, and subscription delivery (fail-closed: the flag cannot disable it "
        "once gardens exist). Remove the override to silence this notice."
    )
