"""Federation protocol routes — spec §5.6–§5.9, §6, §19.2.3."""

from __future__ import annotations

from ...federation.federation_ingest import ingest_fact, write_audit_log  # noqa: F401
from ...settings import settings  # noqa: F401
from .audit_conflicts import (  # noqa: F401
    _encode_value,
    get_audit_log,
    list_conflicts,
    resolve_conflict,
)
from .common import (  # noqa: F401
    PeerTokenDep,
    _allowed_output_scopes,
    _cap_token_covers_scope,
    _get_mtls_peer_cert,
    _require_peer_token,
    _try_peer_token_auth,
    logger,
    router,
)
from .peers import approve_peer, list_peers, register_peer  # noqa: F401
from .pins import create_origin_pin, delete_pin, list_pins  # noqa: F401
from .replication import (  # noqa: F401
    _push_fact_with_cap_token,
    _push_fact_with_peer_token,
    _verify_push_cap_token,
    pull_facts,
    push_facts,
)
from .tombstones import federation_ingest_tombstone, federation_list_tombstones  # noqa: F401

__all__ = [
    "PeerTokenDep",
    "_allowed_output_scopes",
    "_cap_token_covers_scope",
    "_encode_value",
    "_get_mtls_peer_cert",
    "_push_fact_with_cap_token",
    "_push_fact_with_peer_token",
    "_require_peer_token",
    "_try_peer_token_auth",
    "_verify_push_cap_token",
    "get_audit_log",
    "approve_peer",
    "create_origin_pin",
    "delete_pin",
    "federation_ingest_tombstone",
    "federation_list_tombstones",
    "ingest_fact",
    "list_conflicts",
    "list_peers",
    "list_pins",
    "logger",
    "pull_facts",
    "push_facts",
    "register_peer",
    "resolve_conflict",
    "router",
    "settings",
    "write_audit_log",
]
