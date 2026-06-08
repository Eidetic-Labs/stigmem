"""DEPRECATED Memory Garden advanced ACL plugin scaffold.

Its functionality graduated into core: recall filtering is on by default
(``settings.memory_garden_acl_recall_filter``) and the OIDC permission ceiling
is a core setting (``settings.oidc_permission_ceiling``). The node ignores this
package at discovery (graduated-plugin denylist), so installing it is a no-op.
Uninstall it.
"""

from __future__ import annotations

import warnings

from .config import MemoryGardenAclConfig
from .manifest import PLUGIN_NAME, plugin_manifest

warnings.warn(
    "stigmem-plugin-memory-garden-acl is deprecated: its functionality graduated "
    "into core and the node ignores this package. Uninstall it.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "PLUGIN_NAME",
    "MemoryGardenAclConfig",
    "plugin_manifest",
]
