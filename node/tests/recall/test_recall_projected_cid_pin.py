"""F-SCRYPTO2: recall read-path projected_cid must pin to the canonical-body CID.

``routes/recall/common._fetch_facts_by_ids`` projected ``projected_cid`` as the
lexicographically-smallest ``fact_cid_aliases`` row WITHOUT the
``COALESCE(f.cid, ...)`` pin that every other read path (facts/query,
facts/common, recall/vector_search) uses. With more than one alias for a fact,
``MIN(alias)`` could surface a NON-canonical alias — which the read path then
verifies against the canonical body (spurious 409) and returns to the caller.

This test pins the projection to the canonical-body CID (``f.cid``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from stigmem_node import db as db_mod
from stigmem_node.auth import Identity
from stigmem_node.cid import compute_cid
from stigmem_node.models.recall import RecallWeights
from stigmem_node.routes.recall.as_of import _recall_as_of_impl
from stigmem_node.routes.recall.common import _fetch_facts_by_ids


def _seed_fact_with_extra_alias(db_path: str) -> tuple[str, str]:
    """Insert a fact whose stored f.cid is canonical, plus a non-canonical alias.

    The extra alias is chosen to sort lexicographically BEFORE the canonical CID,
    so a bare ``ORDER BY fca.cid LIMIT 1`` would pick the wrong (non-canonical) one.
    Returns (fact_id, canonical_cid).
    """
    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    entity = "stigmem://test/user/a"
    canonical = compute_cid(
        entity=entity,
        relation="test:role",
        value_type="string",
        value_v="admin",
        source="stigmem://test/source/hr",
        scope="local",
        confidence=0.9,
        interpret_as="content",
    )
    # A second alias that is guaranteed to sort before the canonical CID.
    smaller_alias = "sha256:" + "0" * 64

    db_mod.settings.db_path = db_path
    with db_mod.db() as conn:
        conn.execute(
            "INSERT INTO facts "
            "(id, entity, relation, value_type, value_v, source, timestamp, "
            " valid_until, confidence, scope, tenant_id, interpret_as, cid) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                fact_id,
                entity,
                "test:role",
                "string",
                "admin",
                "stigmem://test/source/hr",
                now,
                None,
                0.9,
                "local",
                "default",
                "content",
                canonical,
            ),
        )
        conn.execute(
            "INSERT INTO fact_cid_aliases (fact_id, cid, tenant_id) VALUES (?,?,?)",
            (fact_id, canonical, "default"),
        )
        conn.execute(
            "INSERT INTO fact_cid_aliases (fact_id, cid, tenant_id) VALUES (?,?,?)",
            (fact_id, smaller_alias, "default"),
        )
    return fact_id, canonical


def test_recall_projected_cid_pins_to_canonical_body_cid(migrated_db: str) -> None:
    """projected_cid must be the canonical-body f.cid, not MIN(alias)."""
    fact_id, canonical = _seed_fact_with_extra_alias(migrated_db)

    with db_mod.db() as conn:
        records = _fetch_facts_by_ids(conn, [fact_id])

    assert fact_id in records, "fact should pass read-path CID verification (no spurious 409)"
    assert records[fact_id].cid == canonical, (
        "recall must return the canonical-body CID, not the smaller non-canonical alias"
    )


def test_recall_as_of_projected_cid_pins_to_canonical_body_cid(migrated_db: str) -> None:
    """The time-travel as_of recall path must also pin projected_cid to f.cid.

    ``routes/recall/as_of`` projected ``projected_cid`` with a BARE alias
    subquery (``ORDER BY fca.cid LIMIT 1``), missing the ``COALESCE(f.cid, ...)``
    pin the four sibling read paths use. With a non-canonical alias that sorts
    first, ``enforce_read_path_cid`` would raise a spurious 409 that aborts the
    whole ``recall?as_of=`` request. After the fix the canonical-body CID is
    projected and the recall succeeds.
    """
    fact_id, canonical = _seed_fact_with_extra_alias(migrated_db)
    as_of = (datetime.now(UTC) + timedelta(minutes=1)).isoformat()
    identity = Identity("stigmem://test/agent/caller", ["read"])

    with db_mod.db() as conn:
        scored_facts, _tombstones, _filtered = _recall_as_of_impl(
            conn,
            query="admin",
            scope="local",
            as_of=as_of,
            is_admin_caller=False,
            tenant_id="default",
            max_chunks=10,
            include_graph=False,
            identity=identity,
            weights=RecallWeights(),
            depth=1,
        )

    cids = {sf.fact.id: sf.fact.cid for sf in scored_facts}
    assert fact_id in cids, "as_of recall must not raise a spurious 409 on the canonical fact"
    assert cids[fact_id] == canonical, (
        "as_of recall must return the canonical-body CID, not the smaller non-canonical alias"
    )
