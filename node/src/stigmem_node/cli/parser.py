"""Argument parser construction for the Stigmem CLI."""

from __future__ import annotations

import argparse
import os

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
from .federation import _cmd_federation_register_peer
from .maintenance import _cmd_decay_sweep, _cmd_migrate_normalize_entities
from .mcp import (
    _cmd_mcp_config,
    _cmd_mcp_detect,
    _cmd_mcp_doctor,
    _cmd_mcp_install,
    _cmd_mcp_smoke,
    _cmd_mcp_status,
)
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigmem",
        description="Stigmem reference node CLI",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ------------------------------------------------------------------ capability
    cap_p = sub.add_parser(
        "capability",
        help="capability token management (Spec-06-Capability-Tokens)",
    )
    cap_sub = cap_p.add_subparsers(dest="cap_command", metavar="SUBCOMMAND")
    cap_sub.required = True

    _cap_common = argparse.ArgumentParser(add_help=False)
    _cap_common.add_argument(
        "--node-url",
        dest="node_url",
        default="http://localhost:8765",
        metavar="URL",
        help="base URL of the local node (default: http://localhost:8765)",
    )
    _cap_common.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        metavar="KEY",
        help="API key for authentication",
    )
    _cap_common.add_argument(
        "--json",
        action="store_true",
        help="output raw JSON response",
    )

    # capability issue
    ci_p = cap_sub.add_parser(
        "issue",
        parents=[_cap_common],
        help="issue a new capability token",
    )
    ci_p.add_argument("--issuer", required=True, metavar="URI", help="issuer entity URI")
    ci_p.add_argument("--subject", required=True, metavar="URI", help="subject entity URI")
    ci_p.add_argument(
        "--verb",
        required=True,
        metavar="VERB",
        help="permission verb (e.g. read, write)",
    )
    ci_p.add_argument(
        "--object",
        required=True,
        metavar="OBJECT",
        help="object URI the token grants access to (e.g. stigmem://facts)",
    )
    ci_p.add_argument(
        "--ttl-seconds",
        dest="ttl_seconds",
        type=int,
        default=None,
        metavar="N",
        help="token lifetime in seconds (default: node default; max: 7776000 / 90 days)",
    )
    ci_p.set_defaults(func=_cmd_capability_issue)

    # capability verify
    cv_p = cap_sub.add_parser(
        "verify",
        parents=[_cap_common],
        help="verify a capability token",
    )
    cv_p.add_argument(
        "token_json",
        metavar="TOKEN_JSON",
        help="capability token JSON string; pass '-' to read from stdin",
    )
    cv_p.set_defaults(func=_cmd_capability_verify)

    # capability revoke
    cr_p = cap_sub.add_parser(
        "revoke",
        parents=[_cap_common],
        help="revoke a capability token by token_id",
    )
    cr_p.add_argument("token_id", metavar="TOKEN_ID", help="ID of the token to revoke")
    cr_p.add_argument(
        "--reason",
        default="",
        metavar="REASON",
        help="human-readable reason for revocation",
    )
    cr_p.set_defaults(func=_cmd_capability_revoke)

    # ------------------------------------------------------------------ migrate
    migrate_p = sub.add_parser("migrate", help="database migration utilities")
    migrate_sub = migrate_p.add_subparsers(dest="migrate_command", metavar="SUBCOMMAND")
    migrate_sub.required = True

    ne_p = migrate_sub.add_parser(
        "normalize-entities",
        help="populate entity_aliases from non-canonical entity/source URIs in facts (Spec-01-Fact-Model)",  # noqa: E501
    )
    ne_p.add_argument(
        "--dry-run",
        action="store_true",
        help="print aliases without inserting",
    )
    ne_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    ne_p.set_defaults(func=_cmd_migrate_normalize_entities)

    # ------------------------------------------------------------------ plugins
    plugins_p = sub.add_parser(
        "plugins",
        help="inspect installed plugins (PR 4-INF.2)",
    )
    plugins_sub = plugins_p.add_subparsers(dest="plugins_command", metavar="SUBCOMMAND")
    plugins_sub.required = True

    pl_p = plugins_sub.add_parser("list", help="list installed plugins")
    pl_p.add_argument("--json", action="store_true", help="output as JSON")
    pl_p.set_defaults(func=_cmd_plugins_list)

    pd_p = plugins_sub.add_parser("describe", help="describe one installed plugin")
    pd_p.add_argument("name", metavar="NAME", help="plugin name")
    pd_p.add_argument("--json", action="store_true", help="output as JSON")
    pd_p.set_defaults(func=_cmd_plugins_describe)

    ps_p = plugins_sub.add_parser("search", help="search the built-in plugin catalog")
    ps_p.add_argument("query", metavar="QUERY", help="catalog search term")
    ps_p.add_argument("--json", action="store_true", help="output as JSON")
    ps_p.set_defaults(func=_cmd_plugins_search)

    pe_p = plugins_sub.add_parser("enable", help="print install and enable commands")
    pe_p.add_argument("name", metavar="NAME", help="plugin slug or package name")
    pe_p.set_defaults(func=_cmd_plugins_enable)

    pdis_p = plugins_sub.add_parser("disable", help="print disable command")
    pdis_p.add_argument("name", metavar="NAME", help="plugin slug or package name")
    pdis_p.set_defaults(func=_cmd_plugins_disable)

    pdoc_p = plugins_sub.add_parser("doctor", help="diagnose plugin install and enable state")
    pdoc_p.add_argument("--json", action="store_true", help="output as JSON")
    pdoc_p.set_defaults(func=_cmd_plugins_doctor)

    # ------------------------------------------------------------------ mcp
    mcp_p = sub.add_parser(
        "mcp",
        help="manage stigmem-mcp editor integrations",
    )
    mcp_sub = mcp_p.add_subparsers(dest="mcp_command", metavar="SUBCOMMAND")
    mcp_sub.required = True

    mcp_doc_p = mcp_sub.add_parser("doctor", help="diagnose stigmem-mcp setup")
    mcp_doc_p.add_argument("--json", action="store_true", help="output as JSON")
    mcp_doc_p.set_defaults(func=_cmd_mcp_doctor)

    mcp_detect_p = mcp_sub.add_parser("detect", help="detect known editor configs")
    mcp_detect_p.add_argument("--json", action="store_true", help="output as JSON")
    mcp_detect_p.set_defaults(func=_cmd_mcp_detect)

    mcp_status_p = mcp_sub.add_parser("status", help="show editor config status")
    mcp_status_p.add_argument("--json", action="store_true", help="output as JSON")
    mcp_status_p.set_defaults(func=_cmd_mcp_status)

    mcp_config_p = mcp_sub.add_parser("config", help="print editor config snippets")
    mcp_config_p.add_argument("editor", nargs="?", metavar="EDITOR", help="editor slug")
    mcp_config_p.add_argument("--list", action="store_true", help="list supported editors")
    mcp_config_p.add_argument(
        "--stigmem-url",
        default=os.getenv("STIGMEM_URL", "http://localhost:8765"),
        metavar="URL",
        help="Stigmem node URL for the emitted snippet",
    )
    mcp_config_p.add_argument(
        "--stigmem-api-key",
        default=os.getenv("STIGMEM_API_KEY", "<your-api-key>"),
        metavar="KEY",
        help="Stigmem API key for the emitted snippet",
    )
    mcp_config_p.set_defaults(func=_cmd_mcp_config)

    mcp_install_p = mcp_sub.add_parser("install", help="write an editor MCP config")
    mcp_install_p.add_argument("editor", metavar="EDITOR", help="editor slug")
    mcp_install_p.add_argument("--write", action="store_true", help="apply the planned change")
    mcp_install_p.add_argument(
        "--dry-run",
        dest="write",
        action="store_false",
        help="preview the planned change without writing (default)",
    )
    mcp_install_p.add_argument(
        "--force",
        action="store_true",
        help="replace existing stigmem-mcp entry",
    )
    mcp_install_p.add_argument("--yes", action="store_true", help="skip interactive confirmation")
    mcp_install_p.add_argument("--backup-dir", default=None, metavar="DIR", help="backup directory")
    mcp_install_p.add_argument(
        "--stigmem-url",
        default=os.getenv("STIGMEM_URL", "http://localhost:8765"),
        metavar="URL",
        help="Stigmem node URL to write",
    )
    mcp_install_p.add_argument(
        "--stigmem-api-key",
        default=os.getenv("STIGMEM_API_KEY", "<your-api-key>"),
        metavar="KEY",
        help="Stigmem API key to write",
    )
    mcp_install_p.set_defaults(func=_cmd_mcp_install)

    mcp_smoke_p = mcp_sub.add_parser("smoke", help="verify an editor MCP setup")
    mcp_smoke_p.add_argument("editor", metavar="EDITOR", help="editor slug")
    mcp_smoke_p.set_defaults(func=_cmd_mcp_smoke)

    # ------------------------------------------------------------------ doctor
    doctor_p = sub.add_parser("doctor", help="print node and plugin diagnostics")
    doctor_p.add_argument("--json", action="store_true", help="output as JSON")
    doctor_p.set_defaults(func=_cmd_doctor)

    # ------------------------------------------------------------------ federation
    fed_p = sub.add_parser(
        "federation",
        help="federation management (Spec-05-Federation-Trust)",
    )
    fed_sub = fed_p.add_subparsers(dest="fed_command", metavar="SUBCOMMAND")
    fed_sub.required = True

    rp_p = fed_sub.add_parser(
        "register-peer",
        help="register this node as a peer with a remote node (Spec-05-Federation-Trust)",
    )
    rp_p.add_argument(
        "--remote-url",
        required=True,
        metavar="URL",
        help="base URL of the remote node (e.g. http://node-b:8765)",
    )
    rp_p.add_argument(
        "--local-url",
        default=None,
        metavar="URL",
        help="base URL of this node as seen by the remote (default: STIGMEM_NODE_URL)",
    )
    rp_p.add_argument(
        "--scopes",
        default="company,public",
        metavar="SCOPE[,SCOPE]",
        help='comma-separated scopes to share (default: "company,public")',
    )
    rp_p.add_argument(
        "--api-key",
        default=None,
        metavar="KEY",
        help="API key for the remote node (required when remote auth_required=true)",
    )
    rp_p.add_argument(
        "--tls-cert",
        default=None,
        metavar="FILE",
        help="client certificate for mTLS federation registration",
    )
    rp_p.add_argument(
        "--tls-key",
        default=None,
        metavar="FILE",
        help="client private key for mTLS federation registration",
    )
    rp_p.add_argument(
        "--ca-bundle",
        default=None,
        metavar="FILE",
        help="CA bundle used to verify HTTPS federation peers",
    )
    rp_p.set_defaults(func=_cmd_federation_register_peer)

    # ------------------------------------------------------------------ federation cursor-export
    ce_p = fed_sub.add_parser(
        "cursor-export",
        help="export replication cursor positions to a JSON checkpoint file",
    )
    ce_p.add_argument(
        "--out",
        default="-",
        metavar="FILE",
        help='output file path (default: stdout, use "-" for stdout)',
    )
    ce_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    ce_p.set_defaults(func=_cmd_federation_cursor_export)

    # ------------------------------------------------------------------ federation cursor-import
    ci_p = fed_sub.add_parser(
        "cursor-import",
        help="restore replication cursors from a checkpoint file after DB loss",
    )
    ci_p.add_argument(
        "checkpoint_file",
        metavar="FILE",
        help="path to checkpoint JSON produced by cursor-export",
    )
    ci_p.add_argument(
        "--force",
        action="store_true",
        help="overwrite cursors that are already set (default: skip existing non-null cursors)",
    )
    ci_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    ci_p.set_defaults(func=_cmd_federation_cursor_import)

    # ------------------------------------------------------------------ snapshot
    snap_p = sub.add_parser("snapshot", help="backup/restore with signed manifests (Phase 8)")
    snap_sub = snap_p.add_subparsers(dest="snap_command", metavar="SUBCOMMAND")
    snap_sub.required = True

    sc_p = snap_sub.add_parser(
        "create",
        help="create a signed, content-addressed snapshot tarball",
    )
    sc_p.add_argument(
        "--out",
        metavar="PATH",
        default=None,
        help=(
            "output path for the .tar.gz (default: auto-named stigmem-snapshot-<ts>-<hash>.tar.gz)"
        ),
    )
    sc_p.add_argument(
        "--sign-with",
        dest="sign_with",
        metavar="KEY_FILE",
        default=None,
        help="path to a file containing a raw base64url Ed25519 private key (32 bytes); "
        "default: use the node's built-in federation key",
    )
    sc_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    sc_p.set_defaults(func=_cmd_snapshot_create)

    sr_p = snap_sub.add_parser(
        "restore",
        help="verify signature + hashes and restore a snapshot tarball",
    )
    sr_p.add_argument(
        "--from",
        dest="from_path",
        metavar="PATH",
        required=True,
        help="path to the .tar.gz snapshot to restore",
    )
    sr_p.add_argument(
        "--trusted-keys",
        dest="trusted_keys",
        metavar="PATH",
        default=None,
        help="JSON file listing trusted base64url Ed25519 public keys; "
        "default: only the local node's own key",
    )
    sr_p.add_argument(
        "--force-unverified",
        dest="force_unverified",
        action="store_true",
        help=(
            "restore even if signature or hash verification fails (logged loudly; NOT recommended)"
        ),
    )
    sr_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="destination database path (default: STIGMEM_DB_PATH env or settings default)",
    )
    sr_p.set_defaults(func=_cmd_snapshot_restore)

    # ------------------------------------------------------------------ decay
    decay_p = sub.add_parser("decay", help="decay sweeper — expire stale facts (Phase 6)")
    decay_sub = decay_p.add_subparsers(dest="decay_command", metavar="SUBCOMMAND")
    decay_sub.required = True

    sw_p = decay_sub.add_parser(
        "sweep",
        help="mark non-expiring or low-confidence facts as expired",
    )
    sw_p.add_argument(
        "--ttl-seconds",
        dest="ttl_seconds",
        type=int,
        default=None,
        metavar="N",
        help="expire non-expiring facts older than N seconds (0 = expire all)",
    )
    sw_p.add_argument(
        "--min-confidence",
        dest="min_confidence",
        type=float,
        default=None,
        metavar="F",
        help="expire active facts with confidence below F (0.0–1.0)",
    )
    sw_p.add_argument(
        "--scope",
        default="",
        metavar="SCOPE",
        help="restrict sweep to one scope (local/team/company/public)",
    )
    sw_tenant_grp = sw_p.add_mutually_exclusive_group()
    sw_tenant_grp.add_argument(
        "--tenant",
        dest="tenant",
        default="default",
        metavar="TENANT",
        help="restrict sweep to one tenant (default: 'default')",
    )
    sw_tenant_grp.add_argument(
        "--all-tenants",
        dest="all_tenants",
        action="store_true",
        help="sweep every tenant (for multi-tenant operators); mutually exclusive with --tenant",
    )
    sw_p.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be decayed without writing",
    )
    sw_p.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    sw_p.set_defaults(func=_cmd_decay_sweep)

    # ------------------------------------------------------------------ instruction
    instr_p = sub.add_parser(
        "instruction",
        help="instruction manifest tools (Spec-X1-Lazy-Instruction-Discovery)",
    )
    instr_sub = instr_p.add_subparsers(dest="instr_command", metavar="SUBCOMMAND")
    instr_sub.required = True

    im_p = instr_sub.add_parser("manifest", help="manage instruction manifests")
    im_sub = im_p.add_subparsers(dest="manifest_command", metavar="SUBCOMMAND")
    im_sub.required = True

    img_p = im_sub.add_parser(
        "generate",
        help="generate a manifest JSON from a directory of markdown instruction files",
    )
    img_p.add_argument(
        "path", metavar="PATH", help="directory containing markdown instruction files"
    )
    img_p.add_argument(
        "--agent-id",
        dest="agent_id",
        required=True,
        metavar="AGENT_ID",
        help="agent UUID to embed in generated fact_uri values",
    )
    img_p.add_argument(
        "--deployment",
        default="default",
        metavar="DEPLOYMENT",
        help="deployment namespace for instruction: URIs (default: default)",
    )
    img_p.add_argument(
        "--version",
        default="v1",
        metavar="VERSION",
        help="manifest version string (default: v1)",
    )
    img_p.add_argument(
        "--out",
        default=None,
        metavar="FILE",
        help="write JSON to FILE instead of stdout",
    )
    img_p.set_defaults(func=_cmd_instruction_manifest_generate)

    # instruction migrate
    imig_p = instr_sub.add_parser(
        "migrate",
        help="migrate markdown instruction files to stigmem facts + publish manifest",
    )
    imig_p.add_argument("path", metavar="PATH", help="markdown file or directory to migrate")
    scope_grp = imig_p.add_mutually_exclusive_group(required=True)
    scope_grp.add_argument(
        "--role", default=None, metavar="ROLE", help="agent role name (e.g. cto)"
    )
    scope_grp.add_argument(
        "--skill", default=None, metavar="SKILL", help="skill name (e.g. paperclip)"
    )
    imig_p.add_argument(
        "--agent-id",
        dest="agent_id",
        required=True,
        metavar="AGENT_ID",
        help="agent UUID owning the manifest",
    )
    imig_p.add_argument(
        "--deployment",
        default="default",
        metavar="DEPLOYMENT",
        help="deployment namespace (default: default)",
    )
    imig_p.add_argument(
        "--version",
        default="v1",
        metavar="VERSION",
        help="fact version string (default: v1)",
    )
    imig_p.add_argument(
        "--node-url",
        dest="node_url",
        default="http://127.0.0.1:8000",
        metavar="URL",
        help="stigmem node base URL (default: http://127.0.0.1:8000)",
    )
    imig_p.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        metavar="KEY",
        help="API key (or set STIGMEM_API_KEY env var)",
    )
    imig_p.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="path to stigmem.db for local idempotency checks (skips HTTP fact queries)",
    )
    imig_p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="show diff without writing any facts or manifest",
    )
    imig_p.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="skip confirmation prompt",
    )
    imig_p.set_defaults(func=_cmd_instruction_migrate)

    # ------------------------------------------------------------------ audit
    audit_p = sub.add_parser(
        "audit",
        help="discovery audit reports (Spec-X1-Lazy-Instruction-Discovery)",
    )
    audit_sub = audit_p.add_subparsers(dest="audit_command", metavar="SUBCOMMAND")
    audit_sub.required = True

    ad_p = audit_sub.add_parser(
        "discovery",
        help="print discovery audit metrics: Recall@k, Hit@k, miss rate",
    )
    ad_p.add_argument(
        "--agent",
        required=True,
        metavar="AGENT_ID_OR_ROLE",
        help="agent ID (UUID) or role substring to filter",
    )
    ad_p.add_argument(
        "--since",
        default=None,
        metavar="DATE",
        help="ISO 8601 date/datetime to start from (default: 7 days ago)",
    )
    ad_p.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    ad_p.add_argument("--json", action="store_true", help="output as JSON")
    ad_p.set_defaults(func=_cmd_audit_discovery)

    # ------------------------------------------------------------------ identity
    id_p = sub.add_parser(
        "identity",
        help="node identity management (Spec-10-Hardening)",
    )
    id_sub = id_p.add_subparsers(dest="identity_command", metavar="SUBCOMMAND")
    id_sub.required = True

    rk_p = id_sub.add_parser(
        "rotate-key",
        help="rotate the node or issuer Ed25519 key with a dual-trust window (Spec-10-Hardening)",  # noqa: E501
    )
    rk_p.add_argument(
        "--kind",
        choices=["node", "issuer"],
        required=True,
        metavar="KIND",
        help="key type to rotate: node (federation identity) or issuer (capability token signing)",
    )
    rk_p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="generate artefacts and print new key without writing to TL or DB",
    )
    rk_p.add_argument(
        "--dual-trust-days",
        dest="dual_trust_days",
        type=int,
        default=90,
        metavar="DAYS",
        help="days the retiring key stays in accept_set (default: 90; must be ≥ 90)",
    )
    rk_p.add_argument(
        "--db",
        default=None,
        metavar="PATH",
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    rk_p.set_defaults(func=_cmd_identity_rotate_key)

    # ------------------------------------------------------------------ backfill-cids
    bc_p = sub.add_parser(
        "backfill-cids",
        help="compute and persist CIDs for facts that pre-date CID backfill (Spec-21-Content-Addressed-IDs)",  # noqa: E501
    )
    bc_p.add_argument(
        "--db",
        dest="db",
        default=None,
        metavar="PATH",
        help="path to stigmem.db (default: STIGMEM_DB_PATH env or settings default)",
    )
    bc_p.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=500,
        metavar="N",
        help="facts to process per transaction (default: 500)",
    )
    bc_p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress output",
    )
    bc_p.set_defaults(func=_cmd_backfill_cids)

    # ------------------------------------------------------------------ auth
    auth_p = sub.add_parser(
        "auth",
        help="API key management (Spec-06-Capability-Tokens)",
    )
    auth_sub = auth_p.add_subparsers(dest="auth_command", metavar="SUBCOMMAND")
    auth_sub.required = True

    # auth bootstrap-key
    bk_p = auth_sub.add_parser(
        "bootstrap-key",
        help=(
            "register a caller-provided admin API key on a fresh install "
            "(refuses if api_keys is non-empty; system never generates the key)"
        ),
    )
    bk_p.add_argument(
        "--key",
        dest="key",
        default=None,
        metavar="VALUE",
        help=(
            "raw API key value to register. Generate externally; e.g., "
            "`openssl rand -hex 32`. Alternative: STIGMEM_BOOTSTRAP_KEY env var."
        ),
    )
    bk_p.add_argument(
        "--entity-uri",
        dest="entity_uri",
        default="agent:admin",
        metavar="URI",
        help="entity URI to associate with the bootstrap key (default: agent:admin)",
    )
    bk_p.add_argument(
        "--permissions",
        dest="permissions",
        default="admin,write,read",
        metavar="LIST",
        help=("comma-separated permissions for the bootstrap key (default: admin,write,read)"),
    )
    bk_p.set_defaults(func=_cmd_auth_bootstrap_key)

    return parser
