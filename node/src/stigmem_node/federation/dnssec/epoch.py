"""Per-host monotonic epoch pin + sticky-signedness (Rev 6 I4 / build-phase 3b.5).

State for the ``dnssec_epoch_pins`` table (migration 054), keyed by **host** (the
canonical host derived from the signed wire ``entity_uri`` per I3) — *not* by
identity. The epoch floor and the signed-delegation fact are properties of the
zone, so a host that serves more than one ``node_id`` shares one floor: a second
node arriving under the same host at a lower epoch is a rollback, never a fresh
first-contact (Rev 6 plan TB-5).

Two pieces of state live here:

  * **Monotonic epoch** — ``accept_epoch(conn, host, epoch)`` enforces that a
    host's ``max_epoch_seen`` never decreases. First contact (no row) takes the
    handed epoch and pins it (honestly unauthenticated as to recency, §15.3);
    ``epoch < max_epoch_seen`` is rejected (``dnssec_epoch_rollback``);
    ``epoch >= max_epoch_seen`` is accepted and advances the floor.
  * **Sticky-signedness** — ``mark_signed_delegation`` records that a signed
    delegation has been observed for a host; once set it never clears, so a
    later authenticated "absent" can be treated as an attack by the caller (I2).

These are off-path DB primitives: nothing here is wired into the resolver yet
(that is a later 3b task). All helpers take an open ``sqlite3``-style connection
and participate in its transaction; the caller owns commit/rollback. No DNSSEC /
``dnspython`` import is reachable from this module (I11).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# An epoch-only upsert needs a placeholder validation timestamp for the
# NOT NULL last_validated_at column on a fresh row. The real first-trust ladder
# stamps the genuine validation time; for these primitives "now" suffices and is
# advanced on every accepted epoch.


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def accept_epoch(conn: Any, host: str, epoch: int) -> bool:
    """Apply the monotonic-epoch rule for ``host`` (Rev 6 I4).

    * No prior row (first contact) -> accept, pin ``max_epoch_seen=epoch``, True.
    * ``epoch < max_epoch_seen``    -> reject (``dnssec_epoch_rollback``), the
      stored floor is left unchanged, return False.
    * ``epoch >= max_epoch_seen``   -> accept, advance the floor to ``epoch``,
      refresh ``last_validated_at``, return True.

    Keyed by ``host`` only (TB-5): a different ``node_id`` under the same host is
    governed by the same floor and cannot reset it by being "new".

    The caller owns the transaction; this never commits.
    """
    row = conn.execute(
        "SELECT max_epoch_seen FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()

    if row is None:
        # First contact: take the handed epoch and pin it. signed_delegation_seen
        # defaults to 0 (migration 054); the caller marks it separately.
        conn.execute(
            "INSERT INTO dnssec_epoch_pins "
            "(host, max_epoch_seen, signed_delegation_seen, last_validated_at) "
            "VALUES (?, ?, 0, ?)",
            (host, epoch, _now_iso()),
        )
        return True

    current = row[0]
    if epoch < current:
        # Rollback: leave the floor untouched and reject.
        return False

    # Equal or higher: advance (or hold) the floor; refresh the validation time.
    # signed_delegation_seen is deliberately NOT touched here so the sticky flag
    # survives ordinary epoch advances.
    conn.execute(
        "UPDATE dnssec_epoch_pins SET max_epoch_seen=?, last_validated_at=? WHERE host=?",
        (epoch, _now_iso(), host),
    )
    return True


def mark_signed_delegation(conn: Any, host: str) -> None:
    """Record (stickily) that a signed delegation has been observed for ``host``.

    Idempotent: once ``signed_delegation_seen`` is 1 it stays 1. Creates the row
    if the host has not been seen yet (with ``max_epoch_seen=0`` as a neutral
    floor that any real first-contact epoch will meet-or-exceed). The caller owns
    the transaction.
    """
    row = conn.execute(
        "SELECT host FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO dnssec_epoch_pins "
            "(host, max_epoch_seen, signed_delegation_seen, last_validated_at) "
            "VALUES (?, 0, 1, ?)",
            (host, _now_iso()),
        )
    else:
        conn.execute(
            "UPDATE dnssec_epoch_pins SET signed_delegation_seen=1 WHERE host=?",
            (host,),
        )


def signed_delegation_seen(conn: Any, host: str) -> bool:
    """Return whether a signed delegation has ever been observed for ``host``.

    False when the host has no row yet (never observed signed)."""
    row = conn.execute(
        "SELECT signed_delegation_seen FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()
    return bool(row[0]) if row is not None else False
