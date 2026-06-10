from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from stigmem_node.federation.peer_policy import (
    PeerPolicyError,
    resolve_ingest_tenant,
)
from stigmem_node.storage import make_backend


def _cols(db_path: str, table: str) -> set[str]:
    conn = sqlite3.connect(db_path)
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    finally:
        conn.close()


def test_migration_041_adds_policy_columns(tmp_path: Path) -> None:
    from stigmem_node.db import _MIGRATIONS_DIR

    db_path = tmp_path / "m041.db"
    make_backend(db_path=str(db_path)).apply_migrations(_MIGRATIONS_DIR)
    assert {"pull_tenant", "ingest_tenant", "allowed_tenants", "trust_tier"} <= _cols(
        str(db_path), "peers"
    )
    assert "federatable" in _cols(str(db_path), "gardens")


def test_resolve_ingest_tenant_pinned() -> None:
    assert resolve_ingest_tenant({"ingest_tenant": "tenant-a"}, plugin_active=True) == "tenant-a"


def test_resolve_ingest_tenant_explicit_default_ok_without_plugin() -> None:
    assert resolve_ingest_tenant({"ingest_tenant": "default"}, plugin_active=False) == "default"


def test_resolve_ingest_tenant_nondefault_without_plugin_fails_closed() -> None:
    with pytest.raises(PeerPolicyError):
        resolve_ingest_tenant({"ingest_tenant": "tenant-a"}, plugin_active=False)


def test_resolve_ingest_tenant_unpinned_on_multitenant_node_fails_closed() -> None:
    with pytest.raises(PeerPolicyError):
        resolve_ingest_tenant({"ingest_tenant": None}, plugin_active=True, node_is_multitenant=True)


def test_resolve_ingest_tenant_unpinned_single_tenant_node_defaults() -> None:
    assert (
        resolve_ingest_tenant(
            {"ingest_tenant": None}, plugin_active=False, node_is_multitenant=False
        )
        == "default"
    )
