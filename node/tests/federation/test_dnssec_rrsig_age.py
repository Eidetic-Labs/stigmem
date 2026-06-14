"""RRSIG-age clamp with operator-confirm fallthrough (Phase 3 build-phase 3b.6).

Exercises ``stigmem_node.federation.dnssec.freshness`` against Rev 6 I4:

  * A FRESH RRSIG (age <= ``max_rrsig_age``) -> ``OK``.
  * An AGED RRSIG (age > ``max_rrsig_age``) on a host that has NEVER served a
    fresh signature -> ``FALLTHROUGH_CONFIRM`` (operator-confirm, NOT a hard
    reject — a slow-resigning zone stays usable behind a human gate).
  * An AGED RRSIG on a host that PREVIOUSLY served a fresh signature -> ``REJECT``
    (a previously-fresh zone suddenly serving only aged signatures is an attack
    signal, not a slow-resigning zone).

"Previously fresh" is derived from the additive ``dnssec_epoch_pins.last_fresh_at``
column (migration 056): ``mark_fresh`` stamps it whenever a fresh RRSIG is
accepted, and ``was_previously_fresh`` reports whether it has ever been stamped.

The classifier itself is pure (no DB) so the age policy is unit-testable; the
DB-backed previously-fresh state is exercised separately. Off-path: nothing here
is wired into the resolver yet.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec.freshness import (
    AgeClass,
    classify_rrsig_age,
    mark_fresh,
    was_previously_fresh,
)

_MAX_AGE = 7 * 24 * 60 * 60  # 7 days, mirrors settings default


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.db"
    apply_migrations(db_path=str(db_path))
    c = sqlite3.connect(db_path)
    try:
        yield c
    finally:
        c.close()


# --- pure classifier ---------------------------------------------------------


def test_fresh_rrsig_is_ok() -> None:
    assert (
        classify_rrsig_age(rrsig_age_seconds=60, max_age=_MAX_AGE, previously_fresh=False)
        is AgeClass.OK
    )


def test_fresh_rrsig_is_ok_even_if_previously_fresh() -> None:
    # A fresh signature is always OK; the previously-fresh signal only governs
    # the *aged* case.
    assert (
        classify_rrsig_age(rrsig_age_seconds=60, max_age=_MAX_AGE, previously_fresh=True)
        is AgeClass.OK
    )


def test_age_equal_to_max_is_ok() -> None:
    # Boundary: exactly at the ceiling is still fresh (clamp is strict-greater).
    assert (
        classify_rrsig_age(rrsig_age_seconds=_MAX_AGE, max_age=_MAX_AGE, previously_fresh=False)
        is AgeClass.OK
    )


def test_aged_on_never_fresh_falls_through_to_confirm() -> None:
    assert (
        classify_rrsig_age(
            rrsig_age_seconds=_MAX_AGE + 1, max_age=_MAX_AGE, previously_fresh=False
        )
        is AgeClass.FALLTHROUGH_CONFIRM
    )


def test_aged_on_previously_fresh_is_reject() -> None:
    assert (
        classify_rrsig_age(
            rrsig_age_seconds=_MAX_AGE + 1, max_age=_MAX_AGE, previously_fresh=True
        )
        is AgeClass.REJECT
    )


def test_negative_age_treated_as_fresh() -> None:
    # A not-yet-valid (future inception) RRSIG has a negative "age"; it is not
    # aged, so the age clamp does not reject it (chain validation handles
    # inception/expiration separately).
    assert (
        classify_rrsig_age(rrsig_age_seconds=-10, max_age=_MAX_AGE, previously_fresh=True)
        is AgeClass.OK
    )


# --- DB-backed previously-fresh state ---------------------------------------


def test_was_previously_fresh_default_false(conn: sqlite3.Connection) -> None:
    assert was_previously_fresh(conn, host="h") is False  # no row


def test_mark_fresh_then_previously_fresh_true(conn: sqlite3.Connection) -> None:
    mark_fresh(conn, host="h", now="2026-06-12T00:00:00Z")
    assert was_previously_fresh(conn, host="h") is True


def test_mark_fresh_is_sticky(conn: sqlite3.Connection) -> None:
    mark_fresh(conn, host="h", now="2026-06-12T00:00:00Z")
    # A later fresh observation just refreshes the timestamp; it never clears.
    mark_fresh(conn, host="h", now="2026-06-13T00:00:00Z")
    assert was_previously_fresh(conn, host="h") is True
    stamp = conn.execute(
        "SELECT last_fresh_at FROM dnssec_epoch_pins WHERE host=?", ("h",)
    ).fetchone()[0]
    assert stamp == "2026-06-13T00:00:00Z"


def test_mark_fresh_on_existing_epoch_row_preserves_epoch(conn: sqlite3.Connection) -> None:
    """mark_fresh must update an existing epoch-pin row in place, not clobber
    the monotonic floor or the sticky signed-delegation flag."""
    conn.execute(
        "INSERT INTO dnssec_epoch_pins "
        "(host, max_epoch_seen, signed_delegation_seen, last_validated_at) "
        "VALUES ('h', 9, 1, '2026-06-12T00:00:00Z')"
    )
    mark_fresh(conn, host="h", now="2026-06-12T01:00:00Z")
    row = conn.execute(
        "SELECT max_epoch_seen, signed_delegation_seen, last_fresh_at "
        "FROM dnssec_epoch_pins WHERE host=?",
        ("h",),
    ).fetchone()
    assert row[0] == 9  # floor preserved
    assert row[1] == 1  # sticky-signedness preserved
    assert row[2] == "2026-06-12T01:00:00Z"  # fresh stamp set
