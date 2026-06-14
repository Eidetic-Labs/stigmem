"""Stigmem reference node CLI package."""

from __future__ import annotations

import sys

from ..cli_admin_handlers import (
    _cmd_audit_discovery,
    _cmd_auth_bootstrap_key,
    _cmd_backfill_cids,
    _cmd_identity_rotate_key,
    _cmd_instruction_manifest_generate,
    _cmd_instruction_migrate,
)
from ..cli_federation_handlers import (
    _cmd_federation_cursor_export,
    _cmd_federation_cursor_import,
)
from .capability import (
    _cmd_capability_issue,
    _cmd_capability_revoke,
    _cmd_capability_verify,
)
from .federation import (
    _cmd_federation_dnssec_confirm,
    _cmd_federation_dnssec_pending,
    _cmd_federation_dnssec_reject,
    _cmd_federation_register_peer,
)
from .maintenance import _cmd_decay_sweep, _cmd_migrate_normalize_entities
from .mcp import (
    _cmd_mcp_config,
    _cmd_mcp_detect,
    _cmd_mcp_doctor,
    _cmd_mcp_install,
    _cmd_mcp_smoke,
    _cmd_mcp_status,
)
from .parser import _build_parser
from .plugins import (
    _cmd_doctor,
    _cmd_plugins_describe,
    _cmd_plugins_disable,
    _cmd_plugins_doctor,
    _cmd_plugins_enable,
    _cmd_plugins_list,
    _cmd_plugins_search,
)
from .snapshot import _cmd_snapshot_create, _cmd_snapshot_restore

# Re-export for backward compatibility (tests / docs gen import these names).
__all__ = [
    "_build_parser",
    "_cmd_audit_discovery",
    "_cmd_auth_bootstrap_key",
    "_cmd_backfill_cids",
    "_cmd_capability_issue",
    "_cmd_capability_revoke",
    "_cmd_capability_verify",
    "_cmd_decay_sweep",
    "_cmd_doctor",
    "_cmd_federation_cursor_export",
    "_cmd_federation_cursor_import",
    "_cmd_federation_dnssec_confirm",
    "_cmd_federation_dnssec_pending",
    "_cmd_federation_dnssec_reject",
    "_cmd_federation_register_peer",
    "_cmd_identity_rotate_key",
    "_cmd_instruction_manifest_generate",
    "_cmd_instruction_migrate",
    "_cmd_migrate_normalize_entities",
    "_cmd_mcp_config",
    "_cmd_mcp_detect",
    "_cmd_mcp_doctor",
    "_cmd_mcp_install",
    "_cmd_mcp_smoke",
    "_cmd_mcp_status",
    "_cmd_plugins_describe",
    "_cmd_plugins_disable",
    "_cmd_plugins_doctor",
    "_cmd_plugins_enable",
    "_cmd_plugins_list",
    "_cmd_plugins_search",
    "_cmd_snapshot_create",
    "_cmd_snapshot_restore",
    "main",
]


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))
