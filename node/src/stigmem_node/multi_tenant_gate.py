"""Runtime gate for multi-tenant isolation (experimental plugin).

Without the multi-tenant plugin, the ``tenant_resolve`` hook collapses every
identity to the default tenant, so a key registered under a non-default
``tenant_id`` is NOT actually isolated — it shares the default partition. That
single-partition collapse is an intentional default-install behavior (see
``test_default_install_uses_one_audit_partition``); the F-ID-1 hazard is that it
was *silent*. :func:`warn_if_tenant_not_isolatable` makes it loud.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("stigmem.tenant")

MULTI_TENANT_PLUGIN_NAME = "stigmem-plugin-multi-tenant"


def multi_tenant_plugin_registered() -> bool:
    """Return True when the multi-tenant plugin is active in the registry."""
    from .plugins import get_registry

    return MULTI_TENANT_PLUGIN_NAME in get_registry().registered_plugins()


def warn_if_tenant_not_isolatable(normalized_tenant_id: str) -> bool:
    """Log a SECURITY WARNING when a non-default tenant can't actually be isolated.

    The key is still registered — single-tenant installs intentionally collapse
    non-default tenants into one partition; this only removes the *silence*
    (F-ID-1). Returns True iff a warning was emitted.
    """
    from .tenant import DEFAULT_TENANT_ID

    if normalized_tenant_id == DEFAULT_TENANT_ID:
        return False
    if multi_tenant_plugin_registered():
        return False
    logger.warning(
        "SECURITY WARNING: API key registered under tenant_id=%r, but the "
        "multi-tenant plugin is not active. This key is NOT isolated — its "
        "traffic collapses to the default tenant and shares one partition. "
        "Install/enable stigmem-plugin-multi-tenant for real tenant isolation, "
        "or register under the default tenant.",
        normalized_tenant_id,
    )
    return True
