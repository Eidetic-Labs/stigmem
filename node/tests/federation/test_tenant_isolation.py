from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from conftest import FedNode

from stigmem_node.federation.peer_policy import (
    PeerPolicyError,
    resolve_ingest_tenant,
)
from stigmem_node.federation_ingest import ingest_fact
from stigmem_node.storage import make_backend

from .helpers import make_federated_fact


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


# ---------------------------------------------------------------------------
# F-FED-INGEST-TENANT — ingest stamps tenant_id; contradiction is tenant-scoped
# ---------------------------------------------------------------------------


def _all_fact_tenant_ids(db_path: str) -> list[tuple[str, str | None]]:
    conn = sqlite3.connect(db_path)
    try:
        return [
            (row[0], row[1])
            for row in conn.execute("SELECT id, tenant_id FROM facts")
        ]
    finally:
        conn.close()


def test_ingest_stamps_tenant_and_no_cross_tenant_contradiction(
    fed_node: FedNode,
) -> None:
    """Two facts sharing (entity, relation, scope) but in different tenants:
    every stored row (main + meta) carries its ingest tenant, and the
    cross-tenant pair MUST NOT be recorded as a contradiction (§F-FED-INGEST-TENANT).
    """
    entity = f"fed:tenant-iso:{uuid.uuid4()}"
    relation = "test:value"
    scope = "public"

    fact_a = make_federated_fact(entity=entity, relation=relation, value="a", scope=scope)
    fact_b = make_federated_fact(
        entity=entity, relation=relation, value="b", scope=scope, hlc_offset_ms=10
    )

    assert ingest_fact(fact_a, "stigmem://node-b", tenant_id="tenant-a") is True
    assert ingest_fact(fact_b, "stigmem://node-b", tenant_id="tenant-b") is True

    # Every facts row carries a non-null tenant_id.
    rows = _all_fact_tenant_ids(fed_node.db_path)
    assert rows, "no facts written"
    assert all(tid is not None for _id, tid in rows), rows

    by_id = dict(rows)
    # The two main facts landed in their respective ingest tenants.
    assert by_id[fact_a["id"]] == "tenant-a"
    assert by_id[fact_b["id"]] == "tenant-b"

    # The received_from meta-fact for each ingested fact (entity == fact id)
    # is stamped with the same ingest tenant as its parent.
    conn = sqlite3.connect(fed_node.db_path)
    try:
        meta_a = conn.execute(
            "SELECT tenant_id FROM facts WHERE entity = ? AND relation = 'stigmem:received_from'",
            (fact_a["id"],),
        ).fetchone()
        meta_b = conn.execute(
            "SELECT tenant_id FROM facts WHERE entity = ? AND relation = 'stigmem:received_from'",
            (fact_b["id"],),
        ).fetchone()
        conflicts = conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0]
    finally:
        conn.close()

    assert meta_a is not None and meta_a[0] == "tenant-a"
    assert meta_b is not None and meta_b[0] == "tenant-b"

    # Cross-tenant facts must NOT contradict.
    assert conflicts == 0


def test_same_tenant_contradiction_still_detected(fed_node: FedNode) -> None:
    """Two facts with the same (entity, relation, scope) in the SAME tenant DO
    create a conflict — proving the tenant scoping didn't disable same-tenant
    contradiction detection.
    """
    entity = f"fed:tenant-same:{uuid.uuid4()}"
    relation = "test:value"
    scope = "public"

    fact_a = make_federated_fact(entity=entity, relation=relation, value="a", scope=scope)
    fact_b = make_federated_fact(
        entity=entity, relation=relation, value="b", scope=scope, hlc_offset_ms=10
    )

    assert ingest_fact(fact_a, "stigmem://node-b", tenant_id="tenant-a") is True
    assert ingest_fact(fact_b, "stigmem://node-b", tenant_id="tenant-a") is True

    conn = sqlite3.connect(fed_node.db_path)
    try:
        conflicts = conn.execute("SELECT COUNT(*) FROM conflicts").fetchone()[0]
        # The conflict facts (between/status) must be stamped with the tenant too.
        conflict_tenants = [
            r[0]
            for r in conn.execute(
                "SELECT DISTINCT tenant_id FROM facts WHERE entity LIKE 'stigmem:conflict:%'"
            )
        ]
    finally:
        conn.close()

    assert conflicts == 1
    assert conflict_tenants == ["tenant-a"], conflict_tenants
