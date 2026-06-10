from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from conftest import FedNode, make_peer_token

from stigmem_node.federation.peer_policy import (
    PeerPolicyError,
    resolve_ingest_tenant,
)
from stigmem_node.federation_ingest import ingest_fact
from stigmem_node.storage import make_backend

from .helpers import (
    generate_ed25519_b64,
    insert_active_peer,
    make_federated_fact,
)


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


# ---------------------------------------------------------------------------
# Backward-compat — the feature is OPT-IN (Phase 1, Task 8).
#
# A peer with NO tenant policy (unconfigured), OR one explicitly pinned to
# ``default`` for both ingest and pull, on a SINGLE-TENANT node (no non-default
# api_keys, multi-tenant plugin inactive) must behave EXACTLY as before the
# tenancy work landed: inbound federated facts land in ``default`` and the pull
# endpoint serves those ``default``-tenant facts unchanged.
# ---------------------------------------------------------------------------


def _fact_tenant(db_path: str, fact_id: str) -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM facts WHERE id = ?", (fact_id,)
        ).fetchone()
    finally:
        conn.close()
    return row[0] if row is not None else None


def test_unconfigured_peer_ingest_lands_in_default(fed_node: FedNode) -> None:
    """Opt-in: a peer with NO tenant policy ingests facts into ``default``.

    On a single-tenant node (the ``fed_node`` fixture creates no non-default
    api_keys and the multi-tenant plugin is inactive), an unpinned
    (``ingest_tenant=None``) peer's resolved ingest tenant is ``default`` — the
    fail-closed resolver returns it without raising — and a fact ingested with
    that resolved value lands in ``default``, exactly the pre-tenancy behavior.
    """
    # The resolver maps an unpinned peer on a single-tenant node to 'default'.
    resolved = resolve_ingest_tenant(
        {"ingest_tenant": None}, plugin_active=False, node_is_multitenant=False
    )
    assert resolved == "default"

    fact = make_federated_fact(
        entity=f"fed:bc-ingest:{uuid.uuid4()}", value="x", scope="public"
    )
    assert ingest_fact(fact, "stigmem://node-b", tenant_id=resolved) is True

    assert _fact_tenant(fed_node.db_path, fact["id"]) == "default"


def test_explicit_default_peer_ingest_lands_in_default(fed_node: FedNode) -> None:
    """Opt-in: a peer explicitly pinned to ``ingest_tenant='default'`` ingests
    into ``default`` even without the multi-tenant plugin (explicit-default is
    always allowed by the fail-closed resolver)."""
    fact = make_federated_fact(
        entity=f"fed:bc-ingest-explicit:{uuid.uuid4()}", value="y", scope="public"
    )
    assert ingest_fact(fact, "stigmem://node-b", tenant_id="default") is True

    assert _fact_tenant(fed_node.db_path, fact["id"]) == "default"


def test_unconfigured_peer_pull_serves_default_facts(fed_node: FedNode) -> None:
    """Opt-in: a peer with NO ``pull_tenant`` policy pulls ``default``-tenant
    facts exactly as before. Locally-authored public facts (tenant ``default``)
    are served; this is the canonical pre-tenancy egress path.
    """
    resp = fed_node.client.post(
        "/v1/facts",
        json={
            "entity": f"fed:bc-pull:{uuid.uuid4()}",
            "relation": "test:value",
            "value": {"type": "string", "v": "default-served"},
            "source": "agent:test",
            "scope": "public",
        },
    )
    assert resp.status_code == 201
    default_id = resp.json()["id"]

    # Peer registered with NO ingest_tenant / pull_tenant policy (unconfigured).
    pub, priv = generate_ed25519_b64()
    node_id = f"stigmem://test-bc-pull-{uuid.uuid4()}"
    insert_active_peer(fed_node.db_path, node_id, "http://testnode-bc-pull", pub)

    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    r = fed_node.client.get(
        "/v1/federation/facts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    returned_ids = {f["id"] for f in r.json()["facts"]}
    assert default_id in returned_ids


def test_explicit_default_pull_tenant_serves_default_facts(fed_node: FedNode) -> None:
    """Opt-in: a peer pinned to ``pull_tenant='default'`` is served the same
    ``default``-tenant facts as an unconfigured peer — explicit-default == the
    unchanged path."""
    resp = fed_node.client.post(
        "/v1/facts",
        json={
            "entity": f"fed:bc-pull-explicit:{uuid.uuid4()}",
            "relation": "test:value",
            "value": {"type": "string", "v": "default-served-explicit"},
            "source": "agent:test",
            "scope": "public",
        },
    )
    assert resp.status_code == 201
    default_id = resp.json()["id"]

    pub, priv = generate_ed25519_b64()
    node_id = f"stigmem://test-bc-pull-explicit-{uuid.uuid4()}"
    insert_active_peer(
        fed_node.db_path,
        node_id,
        "http://testnode-bc-pull-explicit",
        pub,
        pull_tenant="default",
    )

    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    r = fed_node.client.get(
        "/v1/federation/facts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    returned_ids = {f["id"] for f in r.json()["facts"]}
    assert default_id in returned_ids
