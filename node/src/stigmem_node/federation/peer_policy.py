"""Per-peer federation tenant policy resolution (Phase 1, fail-closed).

A federated fact's local tenant is determined ENTIRELY by the receiving node's
per-peer policy (no wire-carried tenant in Phase 1). Non-default tenancy is only
real when the multi-tenant plugin is active; otherwise tenant_resolve collapses
everything to 'default' (see multi_tenant_gate). We fail closed rather than
silently label-without-isolate.
"""

from __future__ import annotations

from typing import Any

DEFAULT_TENANT_ID = "default"


class PeerPolicyError(ValueError):
    """Raised when a peer's tenant policy cannot be safely honored (fail-closed)."""


def resolve_ingest_tenant(
    peer: dict[str, Any] | Any,
    *,
    plugin_active: bool,
    node_is_multitenant: bool = False,
) -> str:
    """Return the local tenant inbound facts from this peer are stamped into.

    Fail-closed rules:
    - A non-default ``ingest_tenant`` requires the multi-tenant plugin (else the
      label is not actually isolated) -> PeerPolicyError.
    - An unpinned peer (no ``ingest_tenant``) on a node that hosts non-default
      tenants is ambiguous -> PeerPolicyError (configure the peer explicitly).
    - An explicit ``default`` (or a single-tenant node) is always fine.
    """
    raw = _get(peer, "ingest_tenant")
    pinned: str | None = str(raw) if raw else None
    if pinned is None:
        if node_is_multitenant:
            raise PeerPolicyError(
                "peer has no ingest_tenant but the node hosts non-default tenants; "
                "set the peer's ingest_tenant explicitly"
            )
        return DEFAULT_TENANT_ID
    if pinned != DEFAULT_TENANT_ID and not plugin_active:
        raise PeerPolicyError(
            f"ingest_tenant={pinned!r} requires the multi-tenant plugin "
            "(stigmem-plugin-multi-tenant); without it tenants are not isolated"
        )
    return pinned


def _get(peer: Any, key: str) -> Any:
    """Read a key from a dict or a sqlite3.Row-like object, returning None if absent."""
    try:
        return peer[key]
    except (KeyError, IndexError, TypeError):
        return None
