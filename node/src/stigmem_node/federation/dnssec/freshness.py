"""RRSIG-age clamp with operator-confirm fallthrough (Rev 6 I4 / build-phase 3b.6).

The DNSSEC chain validator (3a) proves a binding's signatures are valid; this
module adds the *age* policy on top of that, per Rev 6 I4:

  * A FRESH RRSIG (age within ``federation_dnssec_max_rrsig_age``, per-origin
    overridable) is ``OK`` — trust it (subject to the epoch pin).
  * An AGED RRSIG (older than the ceiling) on a host that has NEVER served a
    fresh signature falls through to operator-confirm (``FALLTHROUGH_CONFIRM``),
    NOT a hard reject — a genuinely slow-resigning zone stays usable behind a
    human gate rather than being silently denied.
  * An AGED RRSIG on a host that PREVIOUSLY served a fresh signature is an attack
    signal (``REJECT``): a previously-fresh zone that suddenly serves only aged
    signatures looks like a replay/suppression attempt, not a slow re-sign.

"Previously fresh" is durable per-host state in ``dnssec_epoch_pins.last_fresh_at``
(migration 056): ``mark_fresh`` stamps it whenever a fresh RRSIG is accepted and
``was_previously_fresh`` reports whether it has ever been stamped. Like
``signed_delegation_seen`` it is sticky in meaning — only ever refreshed forward,
never cleared — so the previously-fresh hard-reject cannot be erased by a later
aged record.

The classifier ``classify_rrsig_age`` is pure (no DB, no time source) so the age
policy is directly unit-testable; the DB-backed previously-fresh state is a thin
upsert. Off-path: nothing here is wired into the resolver yet (a later 3b task).
No DNSSEC / ``dnspython`` import is reachable from this module (I11).
"""

from __future__ import annotations

import enum
from typing import Any


class AgeClass(enum.Enum):
    """The age verdict the first-trust ladder dispatches on (Rev 6 I4)."""

    OK = "ok"
    FALLTHROUGH_CONFIRM = "fallthrough_confirm"
    REJECT = "reject"


def classify_rrsig_age(
    *,
    rrsig_age_seconds: float,
    max_age: int,
    previously_fresh: bool,
) -> AgeClass:
    """Classify a binding RRSIG by age (Rev 6 I4).

    ``rrsig_age_seconds`` is how old the signature is relative to now (a negative
    value means a not-yet-valid / future-inception signature — not aged, so the
    age clamp leaves it ``OK`` and inception/expiration is the chain validator's
    concern). ``max_age`` is the per-origin-overridable ceiling
    (``federation_dnssec_max_rrsig_age``). ``previously_fresh`` is the host's
    durable previously-fresh marker.

      * age <= max_age              -> OK (fresh; the previously-fresh signal is
        irrelevant for a fresh signature).
      * age >  max_age, never fresh -> FALLTHROUGH_CONFIRM (slow-resigning zone
        stays usable behind a human gate).
      * age >  max_age, prev fresh  -> REJECT (attack signal).
    """
    if rrsig_age_seconds <= max_age:
        return AgeClass.OK
    if previously_fresh:
        return AgeClass.REJECT
    return AgeClass.FALLTHROUGH_CONFIRM


def mark_fresh(conn: Any, host: str, *, now: str) -> None:
    """Stamp ``host`` as having served a fresh RRSIG at ``now`` (ISO-8601).

    Upserts ``dnssec_epoch_pins.last_fresh_at`` in place — preserving the
    monotonic epoch floor and the sticky signed-delegation flag on an existing
    row, or creating a neutral row (``max_epoch_seen=0``) if the host is new. The
    stamp only moves forward in meaning (the previously-fresh predicate is
    "non-null"); the caller owns the transaction.
    """
    row = conn.execute(
        "SELECT host FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO dnssec_epoch_pins "
            "(host, max_epoch_seen, signed_delegation_seen, last_validated_at, last_fresh_at) "
            "VALUES (?, 0, 0, ?, ?)",
            (host, now, now),
        )
    else:
        conn.execute(
            "UPDATE dnssec_epoch_pins SET last_fresh_at=? WHERE host=?",
            (now, host),
        )


def was_previously_fresh(conn: Any, host: str) -> bool:
    """Return whether ``host`` has ever served a fresh RRSIG (last_fresh_at set).

    False when the host has no row, or has a row but no fresh observation yet."""
    row = conn.execute(
        "SELECT last_fresh_at FROM dnssec_epoch_pins WHERE host=?", (host,)
    ).fetchone()
    return row is not None and row[0] is not None
