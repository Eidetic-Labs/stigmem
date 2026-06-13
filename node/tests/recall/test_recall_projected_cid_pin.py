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
from datetime import UTC, datetime

from stigmem_node import db as db_mod
from stigmem_node.cid import compute_cid
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
