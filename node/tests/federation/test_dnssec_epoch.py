"""Monotonic epoch pin + sticky-signedness (Phase 3 build-phase 3b, task 3b.5).

Exercises ``stigmem_node.federation.dnssec.epoch`` against the ``dnssec_epoch_pins``
table (migration 054). Per Rev 6 I4:

  * ``max_epoch_seen`` is monotonic *per host*: a record whose epoch is below the
    pinned floor is a rollback and is rejected (``dnssec_epoch_rollback``); an
    equal-or-higher epoch is accepted and advances the floor.
  * first contact (no prior row) takes whatever epoch it is handed and pins it
    (honestly unauthenticated as to recency, Rev 6 §15.3) — but thereafter the
    host floor governs *every* node under that host (the pin is keyed by HOST,
    not by identity — TB-5).
  * ``signed_delegation_seen`` is sticky: once True it stays True, so a later
    authenticated "absent" can be treated as an attack by the caller (I2).

The helpers operate on a sqlite3 connection over a freshly-migrated DB — they are
off-path DB primitives the 3b ladder will compose; nothing is wired into the
resolver yet.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec.epoch import (
    accept_epoch,
    mark_signed_delegation,
    signed_delegation_seen,
)


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    c = sqlite3.connect(db_path)
    try:
        yield c
    finally:
        c.close()


def _max_epoch(conn: sqlite3.Connection, host: str) -> int | None:
    row = conn.execute(
        "SELECT max_epoch_seen FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()
    return None if row is None else row[0]


# --- first contact -----------------------------------------------------------


def test_first_contact_accepts_any_epoch_and_pins(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="h", epoch=3) is True
    assert _max_epoch(conn, "h") == 3


def test_first_contact_accepts_epoch_zero(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="h", epoch=0) is True
    assert _max_epoch(conn, "h") == 0


# --- monotonicity ------------------------------------------------------------


def test_rollback_rejected_and_floor_unchanged(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="h", epoch=5) is True
    assert accept_epoch(conn, host="h", epoch=4) is False  # dnssec_epoch_rollback
    assert _max_epoch(conn, "h") == 5  # rollback did not lower the floor


def test_equal_epoch_accepted(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="h", epoch=5) is True
    assert accept_epoch(conn, host="h", epoch=5) is True
    assert _max_epoch(conn, "h") == 5


def test_higher_epoch_accepted_and_advances_floor(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="h", epoch=5) is True
    assert accept_epoch(conn, host="h", epoch=6) is True
    assert _max_epoch(conn, "h") == 6


# --- TB-5: host-keyed, NOT identity-keyed ------------------------------------


def test_second_node_same_host_lower_epoch_is_rollback(conn: sqlite3.Connection) -> None:
    """TB-5 (critical): the epoch floor is a property of the HOST, not the node.

    Node A establishes max_epoch_seen=5 for the host. A *different* node_id under
    the SAME host arriving at epoch 4 must be REJECTED as a rollback — it is NOT
    "accepted because the node is new". ``accept_epoch`` takes only ``host``
    precisely so a second identity cannot reset the floor.
    """
    assert accept_epoch(conn, host="memory.acme.example", epoch=5) is True
    # A second node under the same host shows up at a lower epoch -> rollback.
    assert accept_epoch(conn, host="memory.acme.example", epoch=4) is False
    assert _max_epoch(conn, "memory.acme.example") == 5


def test_distinct_hosts_have_independent_floors(conn: sqlite3.Connection) -> None:
    assert accept_epoch(conn, host="a.example", epoch=9) is True
    # A different host at a lower epoch is its own first contact -> accepted.
    assert accept_epoch(conn, host="b.example", epoch=2) is True
    assert _max_epoch(conn, "a.example") == 9
    assert _max_epoch(conn, "b.example") == 2


# --- sticky-signedness -------------------------------------------------------


def test_signed_delegation_defaults_false(conn: sqlite3.Connection) -> None:
    assert signed_delegation_seen(conn, host="h") is False  # no row yet


def test_mark_signed_delegation_is_sticky(conn: sqlite3.Connection) -> None:
    mark_signed_delegation(conn, host="h")
    assert signed_delegation_seen(conn, host="h") is True


def test_signed_delegation_persists_across_epoch_updates(conn: sqlite3.Connection) -> None:
    mark_signed_delegation(conn, host="h")
    accept_epoch(conn, host="h", epoch=7)  # an ordinary epoch advance
    assert signed_delegation_seen(conn, host="h") is True  # still sticky


def test_mark_signed_delegation_idempotent(conn: sqlite3.Connection) -> None:
    mark_signed_delegation(conn, host="h")
    mark_signed_delegation(conn, host="h")  # second call must not flip it back
    assert signed_delegation_seen(conn, host="h") is True


def test_accept_epoch_does_not_clear_signed_delegation(conn: sqlite3.Connection) -> None:
    """A first-contact accept_epoch on a row that already has the sticky flag set
    must not reset signed_delegation_seen to 0."""
    mark_signed_delegation(conn, host="h")  # creates row, flag=1, epoch defaults
    floor_before = _max_epoch(conn, "h")
    accept_epoch(conn, host="h", epoch=(floor_before or 0) + 1)
    assert signed_delegation_seen(conn, host="h") is True
