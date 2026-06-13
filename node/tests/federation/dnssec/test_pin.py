"""Rotation-aware DNSSEC origin-pin store (3b, I1/I6).

Exercises ``stigmem_node.federation.dnssec.pin`` against the
``dnssec_origin_pins`` table (migration 053), keyed by ``(entity_uri, node_id)``.

Per Rev 6 I1 each accepted first-trust binding is pinned to ``(entity_uri,
node_id)``; a later binding disagreeing with the stored anchor is rejected. The
pin records the trusted ``key_fpr`` + rotation ``epoch`` + the grace-window
``prev_fpr``/``prev_until`` + the canonical query ``host`` (I3). ``pin_matches``
encodes the I6 rotation grace: the current fingerprint always matches; the
committed ``prev_fpr`` matches only within its ``prev_until`` window.

Off-path DB helpers — no routes, no resolver wiring here.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec import pin as p

_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_LATER = _NOW + timedelta(hours=1)
_GRACE_UNTIL = (_NOW + timedelta(hours=2)).isoformat()


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    c = sqlite3.connect(db_path)
    try:
        yield c
    finally:
        c.close()


# --- insert + get round-trip -------------------------------------------------


def test_get_pin_missing_returns_none(conn: sqlite3.Connection) -> None:
    assert p.get_pin(conn, "https://memory.acme.example/", "node-1") is None


def test_upsert_then_get_round_trip(conn: sqlite3.Connection) -> None:
    p.upsert_pin(
        conn,
        entity_uri="https://memory.acme.example/",
        node_id="node-1",
        key_fpr="sha256:current",
        epoch=7,
        host="memory.acme.example",
        prev_fpr="sha256:prior",
        prev_until=_GRACE_UNTIL,
        now=_NOW,
    )
    pin = p.get_pin(conn, "https://memory.acme.example/", "node-1")
    assert pin is not None
    assert pin.entity_uri == "https://memory.acme.example/"
    assert pin.node_id == "node-1"
    assert pin.key_fpr == "sha256:current"
    assert pin.epoch == 7
    assert pin.host == "memory.acme.example"
    assert pin.prev_fpr == "sha256:prior"
    assert pin.prev_until == _GRACE_UNTIL
    assert pin.last_validated_at == _NOW.isoformat()


def test_upsert_optional_prev_fields_default_empty(conn: sqlite3.Connection) -> None:
    p.upsert_pin(
        conn,
        entity_uri="u",
        node_id="n",
        key_fpr="f",
        epoch=1,
        host="h",
        now=_NOW,
    )
    pin = p.get_pin(conn, "u", "n")
    assert pin is not None
    assert pin.prev_fpr in (None, "")
    assert pin.prev_until in (None, "")


# --- update bumps last_validated_at ------------------------------------------


def test_upsert_updates_in_place_and_bumps_validated_at(conn: sqlite3.Connection) -> None:
    p.upsert_pin(conn, entity_uri="u", node_id="n", key_fpr="f1", epoch=1, host="h", now=_NOW)
    p.upsert_pin(conn, entity_uri="u", node_id="n", key_fpr="f2", epoch=2, host="h", now=_LATER)
    # Still one row (PK is (entity_uri, node_id)).
    assert conn.execute("SELECT COUNT(*) FROM dnssec_origin_pins").fetchone()[0] == 1
    pin = p.get_pin(conn, "u", "n")
    assert pin is not None
    assert pin.key_fpr == "f2"
    assert pin.epoch == 2
    assert pin.last_validated_at == _LATER.isoformat()


# --- pin_matches: current fpr ------------------------------------------------


def test_pin_matches_current_fpr(conn: sqlite3.Connection) -> None:
    p.upsert_pin(conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=1, host="h", now=_NOW)
    pin = p.get_pin(conn, "u", "n")
    assert p.pin_matches(pin, "cur", now=_NOW) is True


def test_pin_does_not_match_unknown_fpr(conn: sqlite3.Connection) -> None:
    p.upsert_pin(conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=1, host="h", now=_NOW)
    pin = p.get_pin(conn, "u", "n")
    assert p.pin_matches(pin, "totally-different", now=_NOW) is False


# --- pin_matches: prev fpr within / after the grace window -------------------


def test_pin_matches_prev_fpr_within_window(conn: sqlite3.Connection) -> None:
    p.upsert_pin(
        conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=2, host="h",
        prev_fpr="old", prev_until=_GRACE_UNTIL, now=_NOW,
    )
    pin = p.get_pin(conn, "u", "n")
    # _NOW is before prev_until -> the prior key is still honored (I6 grace).
    assert p.pin_matches(pin, "old", now=_NOW) is True


def test_pin_does_not_match_prev_fpr_after_window(conn: sqlite3.Connection) -> None:
    p.upsert_pin(
        conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=2, host="h",
        prev_fpr="old", prev_until=_GRACE_UNTIL, now=_NOW,
    )
    pin = p.get_pin(conn, "u", "n")
    after = datetime.fromisoformat(_GRACE_UNTIL) + timedelta(seconds=1)
    assert p.pin_matches(pin, "old", now=after) is False


def test_pin_prev_fpr_match_requires_a_prev_until(conn: sqlite3.Connection) -> None:
    # An empty prev_until means there is no live grace window -> prev_fpr never
    # matches (a missing deadline is fail-closed, not "forever").
    p.upsert_pin(
        conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=2, host="h",
        prev_fpr="old", prev_until="", now=_NOW,
    )
    pin = p.get_pin(conn, "u", "n")
    assert p.pin_matches(pin, "old", now=_NOW) is False


def test_pin_no_prev_fpr_only_current_matches(conn: sqlite3.Connection) -> None:
    p.upsert_pin(conn, entity_uri="u", node_id="n", key_fpr="cur", epoch=1, host="h", now=_NOW)
    pin = p.get_pin(conn, "u", "n")
    assert p.pin_matches(pin, "cur", now=_NOW) is True
    assert p.pin_matches(pin, "", now=_NOW) is False
