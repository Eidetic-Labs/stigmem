"""Egress (pull-server) tenant-pin + fail-closed garden/quarantine filter.

Audit finding F-FED-GARDEN (Tier 1/2). These tests exercise the SERVER side of
federation — ``pull_facts`` in routes/federation/replication.py, which serves
facts to a peer that pulls FROM us. Egress is a PEER concern, not an identity
concern: the garden/quarantine filter must be UNCONDITIONALLY fail-closed and
must NOT depend on garden_acl_enforced() or the identity read chokepoint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from conftest import FedNode, make_peer_token

from stigmem_node.db import db as _db_ctx
from stigmem_node.hlc import node_hlc

from .helpers import generate_ed25519_b64, insert_active_peer


def _insert_fact(
    tenant_id: str,
    *,
    garden_id: str | None = None,
    quarantine_garden_id: str | None = None,
    entity: str | None = None,
) -> str:
    """Insert a single replication-eligible public fact directly into ``facts``.

    Returns the fact id. ``garden_id`` here stamps ``facts.garden_id`` directly;
    membership-side gardening is done separately via ``_set_membership``.
    """
    fact_id = str(uuid.uuid4())
    with _db_ctx() as conn:
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                confidence, scope, hlc, tenant_id, garden_id, quarantine_garden_id, cid)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                entity or f"egress:{tenant_id}:{uuid.uuid4()}",
                "test:value",
                "string",
                "v",
                "agent:test",
                datetime.now(UTC).isoformat(),
                1.0,
                "public",
                node_hlc.tick(),
                tenant_id,
                garden_id,
                quarantine_garden_id,
                # cid-less self-originated rows are egress-skipped (F-FED-2b); stamp one.
                f"bafy{uuid.uuid4().hex}",
            ),
        )
    return fact_id


def _insert_garden(tenant_id: str, *, federatable: int) -> str:
    """Insert a garden owned by ``tenant_id`` with the given federatable flag."""
    garden_id = f"garden:{uuid.uuid4()}"
    with _db_ctx() as conn:
        conn.execute(
            """INSERT INTO gardens
               (id, slug, name, scope, created_by, created_at, tenant_id, federatable)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                garden_id,
                f"slug-{uuid.uuid4()}",
                "g",
                "public",
                "agent:test",
                datetime.now(UTC).isoformat(),
                tenant_id,
                federatable,
            ),
        )
    return garden_id


def _set_membership(fact_id: str, garden_id: str) -> None:
    """Project ``fact_id`` into ``garden_id`` via the membership side-table."""
    with _db_ctx() as conn:
        conn.execute(
            """INSERT INTO fact_garden_membership (fact_id, garden_id, updated_at)
               VALUES (?,?,?)""",
            (fact_id, garden_id, datetime.now(UTC).isoformat()),
        )


def _pull(fed_node: FedNode, pull_tenant: str | None) -> list[dict]:
    """Register a peer (pinned to ``pull_tenant``) and pull facts. Returns records."""
    pub, priv = generate_ed25519_b64()
    node_id = f"stigmem://test-egress-{uuid.uuid4()}"
    insert_active_peer(
        fed_node.db_path,
        node_id,
        "http://testnode-egress",
        pub,
        pull_tenant=pull_tenant,
    )
    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    r = fed_node.client.get(
        "/v1/federation/facts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    # v2 envelope: unwrap each entry to its inner FactRecord.
    return [e["fact"] for e in r.json()["facts"]]


def test_egress_serves_only_peer_pull_tenant(fed_node: FedNode) -> None:
    """A peer pinned to tenant-a gets tenant-a facts, never tenant-b facts."""
    a_id = _insert_fact("tenant-a")
    b_id = _insert_fact("tenant-b")

    returned = {f["id"] for f in _pull(fed_node, "tenant-a")}
    assert a_id in returned
    assert b_id not in returned


def test_egress_excludes_restricted_garden_fact(fed_node: FedNode) -> None:
    """A fact whose projected garden (via membership) is NOT federatable is absent.

    Fail-closed: even though no garden ACL enforcement / recall flag is involved,
    a restricted-garden fact must never egress.
    """
    fact_id = _insert_fact("tenant-a")
    restricted = _insert_garden("tenant-a", federatable=0)
    _set_membership(fact_id, restricted)

    returned = {f["id"] for f in _pull(fed_node, "tenant-a")}
    assert fact_id not in returned


def test_egress_federatable_garden_fact_stripped(fed_node: FedNode) -> None:
    """A fact in a federatable garden IS returned, but with garden_id nulled."""
    fact_id = _insert_fact("tenant-a")
    federatable = _insert_garden("tenant-a", federatable=1)
    _set_membership(fact_id, federatable)

    records = _pull(fed_node, "tenant-a")
    match = [f for f in records if f["id"] == fact_id]
    assert match, "federatable-garden fact should be served"
    assert match[0].get("garden_id") is None, "garden_id must be stripped on egress"


def test_egress_excludes_quarantined_fact(fed_node: FedNode) -> None:
    """A fact with quarantine_garden_id set is absent from egress."""
    q_garden = _insert_garden("tenant-a", federatable=0)
    quarantined = _insert_fact("tenant-a", quarantine_garden_id=q_garden)
    clean = _insert_fact("tenant-a")

    returned = {f["id"] for f in _pull(fed_node, "tenant-a")}
    assert clean in returned
    assert quarantined not in returned
