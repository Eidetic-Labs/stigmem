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
    if not recall_filter_enabled():
        return "disabled"
    if oidc_permission_ceiling_enabled():
        return "enabled-full"
    return "enabled-partial"


def gardens_with_members_exist() -> bool:
    """Return True when at least one garden membership row exists."""
    with db() as conn:
        row = conn.execute("SELECT 1 FROM garden_members LIMIT 1").fetchone()
    return row is not None


def warn_if_memory_garden_acl_filtering_disabled(logger: Logger) -> None:
    """Warn at startup when gardens exist but recall ACL filtering is disabled."""
    if recall_filter_enabled() or not gardens_with_members_exist():
        return
    logger.warning(
        "SECURITY WARNING: Garden ACL recall filtering is DISABLED "
        "(STIGMEM_MEMORY_GARDEN_ACL_RECALL_FILTER=false) while gardens with "
        "members exist. Restricted gardens will leak into tenant-wide queries, "
        "recall ranking, push subscriptions, and graph traversal. Re-enable it "
        "unless you intend tenant-wide garden visibility."
    )
