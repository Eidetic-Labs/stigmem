"""Pull-path per-peer tenant policy (review C1/I2).

These tests pin down the bug the review caught: the pull-path peer SELECT used
to omit the migration-041 policy columns, so ``resolve_ingest_tenant`` always
saw ``ingest_tenant=None`` on pull. They assert (1) the production pull SELECT
carries the policy columns, (2) the shared resolver reads a real peer row's
``ingest_tenant``, and (3) end-to-end a peer pinned to ``tenant-a`` actually
stamps that tenant on the facts it pulls.
"""

from __future__ import annotations

import inspect
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest
from conftest import FedNode

import stigmem_node.multi_tenant_gate as mtg
from stigmem_node.federation import federation_pull
from stigmem_node.federation.peer_policy import (
    PeerPolicyError,
    resolve_ingest_tenant_for_peer,
)
from stigmem_node.storage import make_backend

from .helpers import (
    generate_ed25519_b64,
    insert_active_peer,
    make_bound_peer,
    make_federated_fact,
    make_v2_envelope,
)

# ---------------------------------------------------------------------------
# C1: the pull-path peer SELECT must project the tenant-policy columns, else the
# resolver can never see a peer's pin and silently lands facts in 'default'.
# ---------------------------------------------------------------------------


def test_pull_path_peer_select_carries_tenant_policy() -> None:
    src = inspect.getsource(federation_pull.pull_all_peers_once)
    assert "ingest_tenant" in src, "pull SELECT must project ingest_tenant"
    assert "pull_tenant" in src, "pull SELECT must project pull_tenant"


# ---------------------------------------------------------------------------
# I2: the shared resolver must read the peer ROW's ingest_tenant column and
# wire the plugin + node-multitenancy probes (fail-closed).
# ---------------------------------------------------------------------------


def _migrated_peer_row(db_path: str, ingest_tenant: str | None) -> sqlite3.Row:
    """Insert a peer with the given pin and return its real sqlite3.Row."""
    pub_b64, _priv = generate_ed25519_b64()
    insert_active_peer(
        db_path,
        f"stigmem://peer-{uuid.uuid4()}",
        "http://peer",
        pub_b64,
        ingest_tenant=ingest_tenant,
    )
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, node_id, node_url, allowed_scopes, ingest_tenant, pull_tenant "
            "FROM peers WHERE status = 'active'"
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    return row


def test_resolve_for_peer_reads_row_ingest_tenant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real migrated peer row pinned to 'tenant-a':
    - plugin inactive  -> fail-closed PeerPolicyError
    - plugin active    -> returns 'tenant-a'
    """
    db_path = str(tmp_path / "pull_policy.db")
    make_backend(db_path=db_path).apply_migrations(
        Path(__file__).parent.parent.parent / "migrations"
    )
    row = _migrated_peer_row(db_path, ingest_tenant="tenant-a")
    assert row["ingest_tenant"] == "tenant-a"  # row really carries the pin

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        # No non-default api_keys -> node is single-tenant; the only thing that
        # can flip the result is the plugin probe.
        monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: False)
        with pytest.raises(PeerPolicyError):
            resolve_ingest_tenant_for_peer(row, conn)

        monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: True)
        assert resolve_ingest_tenant_for_peer(row, conn) == "tenant-a"
    finally:
        conn.close()


def test_resolve_for_peer_unpinned_single_tenant_node_defaults(tmp_path: Path) -> None:
    """An unpinned peer on a single-tenant node resolves to 'default' (no raise)."""
    db_path = str(tmp_path / "pull_policy_unpinned.db")
    make_backend(db_path=db_path).apply_migrations(
        Path(__file__).parent.parent.parent / "migrations"
    )
    row = _migrated_peer_row(db_path, ingest_tenant=None)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        assert resolve_ingest_tenant_for_peer(row, conn) == "default"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# End-to-end: a peer pinned via ingest_tenant stamps that tenant on pulled facts.
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.status_code = 200
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._payload


class _StubClient:
    """Minimal stand-in for httpx.AsyncClient used by the pull loop.

    Serves one page of facts for /v1/federation/facts and an empty page for
    tombstones, so a full pull cycle runs without real network.
    """

    def __init__(self, envelope: dict[str, Any]) -> None:
        self._envelope = envelope
        self._served = False

    async def __aenter__(self) -> _StubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> _StubResponse:
        if "/tombstones" in url:
            return _StubResponse({"tombstones": [], "revocations": [], "cursor": None})
        if self._served:
            return _StubResponse({"v": 2, "facts": [], "cursor": None, "has_more": False})
        self._served = True
        return _StubResponse(self._envelope)


def test_pull_pinned_peer_stamps_tenant_on_pulled_facts(
    fed_node: FedNode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1 regression (Phase 2b): a peer whose origin tenant 'tenant-a' maps to local
    'tenant-a' lands its pulled facts in 'tenant-a' (NOT 'default'). The peer is an
    entity_uri-bound peer (so resolve_origin_key succeeds), the page is a signed v2
    envelope, and a peer_tenant_map row resolves origin_tenant='tenant-a'->'tenant-a'.
    """
    import asyncio
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from stigmem_node.db import db as _global_db

    pub_b64, priv_b64 = generate_ed25519_b64()
    priv = Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    )
    peer_node_id = f"stigmem://peer-{uuid.uuid4()}"
    entity_uri = f"stigmem://entity-{uuid.uuid4()}"

    with _global_db() as conn:
        peer_id = make_bound_peer(
            conn,
            node_id=peer_node_id,
            entity_uri=entity_uri,
            pub_b64=pub_b64,
            priv=priv,
        )
        # Map the wire origin tenant 'tenant-a' to local tenant 'tenant-a'.
        conn.execute(
            "INSERT INTO peer_tenant_map (peer_id, origin_tenant, local_tenant) "
            "VALUES (?,?,?)",
            (peer_id, "tenant-a", "tenant-a"),
        )
        conn.commit()

    fact = make_federated_fact(
        entity=f"pull:tenant:{uuid.uuid4()}", value="from-tenant-a", scope="public"
    )
    fact["source"] = peer_node_id

    origin = {
        "tenant": "tenant-a",
        "node_id": peer_node_id,
        "allowed_scopes": ["public"],
        "allowed_tenants": ["tenant-a"],
        "entity_uri": peer_node_id,
    }
    envelope = make_v2_envelope(priv, facts=[fact], origin=origin)

    # The map is non-default, so it requires the multi-tenant plugin to be honored.
    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: True)
    monkeypatch.setattr(
        federation_pull, "_make_pull_client", lambda: _StubClient(envelope)
    )

    asyncio.run(federation_pull.pull_all_peers_once())

    conn = sqlite3.connect(fed_node.db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM facts WHERE id = ?", (fact["id"],)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "pulled fact was not ingested"
    assert row[0] == "tenant-a", f"expected tenant-a, got {row[0]!r}"
