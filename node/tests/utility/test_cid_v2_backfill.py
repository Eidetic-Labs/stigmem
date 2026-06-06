"""CID v2 backfill: rebind legacy (v1) fact aliases to their v2 CID.

A fact written before CID v2 has a v1 CID (7-field body, no interpret_as) and
fails read-path verification under v2 until the backfill repoints its alias.
"""

import hashlib
import json
import sqlite3

import pytest

from stigmem_node.cid import CidMismatchError, compute_cid, verify_cid_from_row
from stigmem_node.lifecycle.immutability import rebind_facts_to_cid_v2

_F = dict(
    entity="user:1",
    relation="prefers",
    value_type="string",
    value_v="tea",
    source="agent:a",
    scope="company",
    confidence=1.0,
)


def _v1_cid() -> str:
    """The legacy (pre-v2) CID: 7-field body, no interpret_as."""
    body = {
        "confidence": _F["confidence"],
        "entity": _F["entity"],
        "relation": _F["relation"],
        "scope": _F["scope"],
        "source": _F["source"],
        "value_type": _F["value_type"],
        "value_v": _F["value_v"],
    }
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE facts (id TEXT PRIMARY KEY, entity TEXT, relation TEXT,
            value_type TEXT, value_v TEXT, source TEXT, scope TEXT,
            confidence REAL, interpret_as TEXT, cid TEXT);
        CREATE TABLE fact_cid_aliases (fact_id TEXT, cid TEXT,
            PRIMARY KEY (fact_id, cid));
        CREATE UNIQUE INDEX idx_alias_cid ON fact_cid_aliases(cid);
        CREATE TABLE fact_cid_backfill (fact_id TEXT PRIMARY KEY, status TEXT,
            attempted_at TEXT, error TEXT, updated_at TEXT);
        """
    )
    return conn


def _seed_legacy(conn: sqlite3.Connection, fact_id: str = "f1") -> str:
    v1 = _v1_cid()
    conn.execute(
        "INSERT INTO facts (id, entity, relation, value_type, value_v, source, "
        "scope, confidence, interpret_as, cid) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            fact_id, _F["entity"], _F["relation"], _F["value_type"], _F["value_v"],
            _F["source"], _F["scope"], _F["confidence"], "content", v1,
        ),
    )
    conn.execute(
        "INSERT INTO fact_cid_aliases (fact_id, cid) VALUES (?, ?)", (fact_id, v1)
    )
    conn.commit()
    return v1


def _row(conn: sqlite3.Connection, fact_id: str) -> sqlite3.Row:
    return conn.execute(
        "SELECT f.*, (SELECT a.cid FROM fact_cid_aliases a WHERE a.fact_id = f.id "
        "ORDER BY a.cid LIMIT 1) AS projected_cid FROM facts f WHERE f.id = ?",
        (fact_id,),
    ).fetchone()


def test_legacy_fact_fails_verify_before_rebind():
    conn = _conn()
    _seed_legacy(conn)
    with pytest.raises(CidMismatchError):
        verify_cid_from_row(_row(conn, "f1"))


def test_rebind_makes_legacy_fact_verify_under_v2():
    conn = _conn()
    _seed_legacy(conn)
    stats = rebind_facts_to_cid_v2(conn)
    assert stats["rebound"] == 1
    row = _row(conn, "f1")
    verify_cid_from_row(row)  # must not raise — projected_cid is now v2
    assert row["projected_cid"] == compute_cid(**_F, interpret_as="content")


def test_rebind_is_idempotent():
    conn = _conn()
    _seed_legacy(conn)
    rebind_facts_to_cid_v2(conn)
    assert rebind_facts_to_cid_v2(conn)["rebound"] == 0


def test_old_v1_cid_no_longer_resolves_after_rebind():
    conn = _conn()
    v1 = _seed_legacy(conn)
    rebind_facts_to_cid_v2(conn)
    hit = conn.execute(
        "SELECT fact_id FROM fact_cid_aliases WHERE cid = ?", (v1,)
    ).fetchone()
    assert hit is None  # clean break: the old v1 alias is gone
