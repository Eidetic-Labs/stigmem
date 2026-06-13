"""Rotation-aware DNSSEC origin-pin store (Rev 6 I1/I6 / build-phase 3b).

DB layer over ``dnssec_origin_pins`` (migration 053), keyed by
``(entity_uri, node_id)`` — the pinned DNSSEC binding per identity (I1). When
the first-trust ladder accepts a binding it pins the validated fingerprint +
rotation epoch + the canonical query host (I3) here; a later binding that
disagrees with this stored anchor is an attack and is rejected (I1/I8).

Two pieces:

  * ``upsert_pin`` / ``get_pin`` — write/read the trusted pin. ``upsert_pin``
    stamps ``last_validated_at=now`` on every accepted (re)validation; the row is
    keyed by the identity PK so a re-validation updates in place, never adds a
    second row.
  * ``pin_matches`` — the I6 rotation-grace predicate. A candidate fingerprint
    matches the *current* ``key_fpr`` always; it also matches the committed
    ``prev_fpr`` but **only** while ``now <= prev_until`` (a live grace window).
    A missing/empty ``prev_until`` means there is no live grace window, so
    ``prev_fpr`` never matches (fail-closed — a missing deadline is not
    "forever"). Carried bytes are never a key source (I7); this module only
    compares an independently-resolved candidate against the stored anchor.

Off-path DB primitives: nothing here is wired into the resolver yet (the ladder
in the sibling commit consumes it). All helpers take an open ``sqlite3``-style
connection and participate in its transaction; the caller owns commit/rollback.
No DNSSEC / ``dnspython`` import is reachable from this module (Rev 6 I11).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_COLUMNS = (
    "entity_uri",
    "node_id",
    "key_fpr",
    "epoch",
    "prev_fpr",
    "prev_until",
    "host",
    "last_validated_at",
)
_COLUMNS_SQL = ", ".join(_COLUMNS)
_SELECT_ONE_SQL = (
    f"SELECT {_COLUMNS_SQL} FROM dnssec_origin_pins "  # noqa: S608  # nosec B608
    "WHERE entity_uri=? AND node_id=?"
)


@dataclass(frozen=True)
class Pin:
    """A pinned, DNSSEC-validated origin binding (one ``dnssec_origin_pins`` row)."""

    entity_uri: str
    node_id: str
    key_fpr: str
    epoch: int
    prev_fpr: str | None
    prev_until: str | None
    host: str
    last_validated_at: str


def _row_to_pin(row: Any) -> Pin:
    return Pin(*row)


def get_pin(conn: Any, entity_uri: str, node_id: str) -> Pin | None:
    """Return the pinned binding for ``(entity_uri, node_id)``, or ``None``."""
    row = conn.execute(_SELECT_ONE_SQL, (entity_uri, node_id)).fetchone()
    return _row_to_pin(row) if row is not None else None


def upsert_pin(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
    key_fpr: str,
    epoch: int,
    host: str,
    prev_fpr: str | None = None,
    prev_until: str | None = None,
    now: datetime,
) -> None:
    """Insert or update the trusted pin for ``(entity_uri, node_id)`` (I1/I6).

    Stamps ``last_validated_at=now`` (ISO-8601). Keyed by the identity PK, so a
    re-validation of an existing identity updates the row in place (fingerprint /
    epoch / grace fields / host / validation time) rather than inserting a
    duplicate. The caller owns the transaction.
    """
    validated_at = now.isoformat()
    existing = conn.execute(
        "SELECT entity_uri FROM dnssec_origin_pins WHERE entity_uri=? AND node_id=?",
        (entity_uri, node_id),
    ).fetchone()

    if existing is not None:
        conn.execute(
            "UPDATE dnssec_origin_pins "
            "SET key_fpr=?, epoch=?, prev_fpr=?, prev_until=?, host=?, last_validated_at=? "
            "WHERE entity_uri=? AND node_id=?",
            (key_fpr, epoch, prev_fpr, prev_until, host, validated_at, entity_uri, node_id),
        )
        return

    conn.execute(
        "INSERT INTO dnssec_origin_pins "
        "(entity_uri, node_id, key_fpr, epoch, prev_fpr, prev_until, host, last_validated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (entity_uri, node_id, key_fpr, epoch, prev_fpr, prev_until, host, validated_at),
    )


def pin_matches(pin: Pin, candidate_fpr: str, *, now: datetime) -> bool:
    """Whether ``candidate_fpr`` is honored against the stored pin (Rev 6 I6).

    * Matches the current ``key_fpr`` -> True (always).
    * Matches the committed ``prev_fpr`` -> True only while ``now <= prev_until``
      (a live rotation-grace window). A missing/empty ``prev_until``, or a ``now``
      past it, means the prior key is no longer honored (fail-closed).
    * Otherwise -> False.

    An empty ``candidate_fpr`` never matches (an empty fingerprint is not a key).
    """
    if not candidate_fpr:
        return False

    if candidate_fpr == pin.key_fpr:
        return True

    if pin.prev_fpr and candidate_fpr == pin.prev_fpr and pin.prev_until:
        try:
            deadline = datetime.fromisoformat(pin.prev_until)
        except (ValueError, TypeError):
            # An unparseable/odd deadline is fail-closed: no live grace window.
            # ``prev_until`` is record input the grammar does not constrain, so
            # the comparison below must never raise out of the ladder.
            return False
        # A legitimate NAIVE deadline (no tzinfo) is normalized to UTC so a
        # bare ISO timestamp still honors rotation grace rather than raising a
        # TypeError against the tz-aware `now`.
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=UTC)
        return now <= deadline

    return False
