"""pending_first_trust quarantine + per-peer cap + TTL eviction (3b.7, I9/NF-R5C-4).

Exercises ``stigmem_node.federation.dnssec.quarantine`` against the
``pending_first_trust`` table (migration 055). Per Rev 6 I9 / §9, operator-confirm
is the *sole* non-DNSSEC first-trust fallback, so the queue MUST be bounded:

  * ``quarantine`` parks/refreshes a candidate binding keyed by
    ``(entity_uri, node_id)``.
  * a per-``relay_peer`` insert cap stops an untrusted relay flooding the queue —
    once a peer is at/over the cap a further *new* row is rejected and an audit
    event is emitted (the operator still sees the flood signal).
  * ``evict_expired`` deletes rows older than the TTL by ``seen_at``.
  * ``list_pending`` / ``get_pending`` / ``remove_pending`` are the DB layer the
    operator-confirm CLI/API (next batch) will call.

Off-path DB helpers — no routes here.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec import quarantine as q


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    c = sqlite3.connect(db_path)
    try:
        yield c
    finally:
        c.close()


@pytest.fixture()
def spy_audit(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """Capture audit_event.emit_nofail calls; returns the (event_type, kwargs) list."""
    seen: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: seen.append((et, kw)))
    return seen


_NOW = datetime(2026, 6, 12, tzinfo=UTC)


def _count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM pending_first_trust").fetchone()[0]


# --- quarantine insert -------------------------------------------------------


def test_quarantine_inserts_row(conn: sqlite3.Connection) -> None:
    ok = q.quarantine(
        conn,
        entity_uri="https://memory.acme.example/",
        node_id="node-1",
        candidate_key_fpr="sha256:abc",
        source="unsigned",
        relay_peer="peer-7",
        now=_NOW,
    )
    assert ok is True
    row = q.get_pending(conn, "https://memory.acme.example/", "node-1")
    assert row is not None
    assert row["candidate_key_fpr"] == "sha256:abc"
    assert row["source"] == "unsigned"
    assert row["relay_peer"] == "peer-7"


def test_quarantine_refreshes_existing_identity(conn: sqlite3.Connection) -> None:
    """Re-quarantining the same (entity_uri, node_id) updates in place (one row),
    refreshing the candidate fingerprint / source / seen_at — it does NOT count
    as a new insert against the cap."""
    q.quarantine(
        conn, entity_uri="u", node_id="n", candidate_key_fpr="fpr-old",
        source="unsigned", relay_peer="peer-7", now=_NOW,
    )
    later = _NOW + timedelta(hours=1)
    ok = q.quarantine(
        conn, entity_uri="u", node_id="n", candidate_key_fpr="fpr-new",
        source="insecure-delegation", relay_peer="peer-7", now=later,
    )
    assert ok is True
    assert _count(conn) == 1
    row = q.get_pending(conn, "u", "n")
    assert row["candidate_key_fpr"] == "fpr-new"
    assert row["source"] == "insecure-delegation"
    assert row["seen_at"] == later.isoformat()


# --- per-peer cap ------------------------------------------------------------


def test_per_peer_cap_rejects_beyond_cap_and_audits(
    conn: sqlite3.Connection, spy_audit: list[tuple[str, dict]]
) -> None:
    cap = 3
    for i in range(cap):
        assert q.quarantine(
            conn, entity_uri=f"u{i}", node_id="n", candidate_key_fpr="fpr",
            source="unsigned", relay_peer="flooder", now=_NOW, cap=cap,
        ) is True
    # The (cap+1)-th NEW row from the same relay_peer is rejected.
    rejected = q.quarantine(
        conn, entity_uri="u-over", node_id="n", candidate_key_fpr="fpr",
        source="unsigned", relay_peer="flooder", now=_NOW, cap=cap,
    )
    assert rejected is False
    assert _count(conn) == cap  # the overflow row was not inserted
    # An audit event names the flooding peer.
    assert any(
        et.endswith("pending_first_trust_cap_exceeded")
        and kw.get("detail", {}).get("relay_peer") == "flooder"
        for et, kw in spy_audit
    ), f"no cap-exceeded audit naming the peer; saw {spy_audit}"


def test_cap_is_per_peer_not_global(conn: sqlite3.Connection) -> None:
    cap = 2
    assert q.quarantine(conn, entity_uri="a", node_id="n", candidate_key_fpr="f",
                        source="unsigned", relay_peer="peer-A", now=_NOW, cap=cap) is True
    assert q.quarantine(conn, entity_uri="b", node_id="n", candidate_key_fpr="f",
                        source="unsigned", relay_peer="peer-A", now=_NOW, cap=cap) is True
    assert q.quarantine(conn, entity_uri="c", node_id="n", candidate_key_fpr="f",
                        source="unsigned", relay_peer="peer-A", now=_NOW, cap=cap) is False
    # A DIFFERENT peer has its own budget and is unaffected.
    assert q.quarantine(conn, entity_uri="d", node_id="n", candidate_key_fpr="f",
                        source="unsigned", relay_peer="peer-B", now=_NOW, cap=cap) is True


def test_refresh_at_cap_still_allowed(conn: sqlite3.Connection) -> None:
    """A peer at its cap can still REFRESH an existing parked row (it adds no new
    row), so a legitimate re-observation is never starved by the flood bound."""
    cap = 1
    assert q.quarantine(conn, entity_uri="u", node_id="n", candidate_key_fpr="f1",
                        source="unsigned", relay_peer="peer-A", now=_NOW, cap=cap) is True
    # Same identity, same peer, at cap -> refresh allowed.
    assert q.quarantine(conn, entity_uri="u", node_id="n", candidate_key_fpr="f2",
                        source="unsigned", relay_peer="peer-A", now=_NOW, cap=cap) is True
    assert q.get_pending(conn, "u", "n")["candidate_key_fpr"] == "f2"


# --- TTL eviction ------------------------------------------------------------


def test_evict_expired_removes_old_rows(conn: sqlite3.Connection) -> None:
    ttl = 7 * 24 * 60 * 60  # 7 days
    old = _NOW - timedelta(days=8)
    fresh = _NOW - timedelta(days=1)
    q.quarantine(conn, entity_uri="old", node_id="n", candidate_key_fpr="f",
                source="unsigned", relay_peer="p", now=old)
    q.quarantine(conn, entity_uri="fresh", node_id="n", candidate_key_fpr="f",
                source="unsigned", relay_peer="p", now=fresh)
    removed = q.evict_expired(conn, now=_NOW, ttl=ttl)
    assert removed == 1
    assert q.get_pending(conn, "old", "n") is None
    assert q.get_pending(conn, "fresh", "n") is not None


def test_evict_expired_boundary_keeps_exactly_ttl(conn: sqlite3.Connection) -> None:
    ttl = 100
    at_ttl = _NOW - timedelta(seconds=ttl)  # exactly ttl old -> kept (strict >)
    q.quarantine(conn, entity_uri="edge", node_id="n", candidate_key_fpr="f",
                source="unsigned", relay_peer="p", now=at_ttl)
    assert q.evict_expired(conn, now=_NOW, ttl=ttl) == 0
    assert q.get_pending(conn, "edge", "n") is not None


# --- list / get / remove -----------------------------------------------------


def test_list_pending_returns_all(conn: sqlite3.Connection) -> None:
    q.quarantine(conn, entity_uri="u1", node_id="n", candidate_key_fpr="f",
                source="unsigned", relay_peer="p", now=_NOW)
    q.quarantine(conn, entity_uri="u2", node_id="n", candidate_key_fpr="f",
                source="insecure-delegation", relay_peer="p", now=_NOW)
    rows = q.list_pending(conn)
    assert {r["entity_uri"] for r in rows} == {"u1", "u2"}
    # Every row exposes the operator-facing fields.
    expected_fields = {
        "entity_uri",
        "node_id",
        "candidate_key_fpr",
        "source",
        "relay_peer",
        "seen_at",
    }
    for r in rows:
        assert expected_fields <= set(r.keys())


def test_get_pending_missing_returns_none(conn: sqlite3.Connection) -> None:
    assert q.get_pending(conn, "nope", "n") is None


def test_remove_pending_deletes(conn: sqlite3.Connection) -> None:
    q.quarantine(conn, entity_uri="u", node_id="n", candidate_key_fpr="f",
                source="unsigned", relay_peer="p", now=_NOW)
    assert q.remove_pending(conn, "u", "n") is True
    assert q.get_pending(conn, "u", "n") is None


def test_remove_pending_missing_returns_false(conn: sqlite3.Connection) -> None:
    assert q.remove_pending(conn, "u", "n") is False
