"""Operator origin-pin store — Phase 2c W4.1.

The operator pins an ``(entity_uri, node_id, key_fingerprint)`` triple obtained
out-of-band, asserting that a specific key controls a specific origin.  This is
the same trust primitive as 2a direct-peer approval: the operator confirms a
fingerprint they verified independently rather than trusting a network-delivered
key at run time.

The ``key_fingerprint`` stored here is produced by ``peer_pubkey_fingerprint``
(sha256:<hex>) so it is directly comparable to the fingerprint computed from a
manifest's ``public_key`` field — the relay resolver (W4.2) calls
``get_origin_pin`` then compares against the manifest key without needing any
format conversion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..routes._federation_impl import peer_pubkey_fingerprint


def fingerprint_from_pubkey(pubkey: str) -> str:
    """Return the sha256: fingerprint for *pubkey* using the canonical primitive.

    Delegates to ``peer_pubkey_fingerprint`` so the stored fingerprint is
    identical in form to what ``approve_peer_impl`` computes — the relay
    resolver can compare them directly.
    """
    return peer_pubkey_fingerprint(pubkey)


def put_origin_pin(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
    key_fingerprint: str,
    pinned_by: str | None,
) -> None:
    """Upsert an origin pin.

    Idempotent: re-pinning the same key is a no-op update.  Pinning a
    *different* key for an existing ``(entity_uri, node_id)`` replaces the
    old fingerprint — that is an explicit operator action (key rotation).

    ``pinned_at`` is set to UTC now on every upsert so the timestamp reflects
    the most recent operator confirmation.
    """
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """INSERT INTO origin_pins (entity_uri, node_id, key_fingerprint, pinned_by, pinned_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (entity_uri, node_id)
           DO UPDATE SET
               key_fingerprint = excluded.key_fingerprint,
               pinned_by       = excluded.pinned_by,
               pinned_at       = excluded.pinned_at""",
        (entity_uri, node_id, key_fingerprint, pinned_by, now),
    )


def get_origin_pin(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
) -> dict[str, Any] | None:
    """Return the pin row for ``(entity_uri, node_id)``, or ``None`` if absent."""
    row = conn.execute(
        "SELECT entity_uri, node_id, key_fingerprint, pinned_by, pinned_at"
        " FROM origin_pins WHERE entity_uri = ? AND node_id = ?",
        (entity_uri, node_id),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def list_origin_pins(conn: Any) -> list[dict[str, Any]]:
    """Return all pinned origins as a list of dicts."""
    rows = conn.execute(
        "SELECT entity_uri, node_id, key_fingerprint, pinned_by, pinned_at"
        " FROM origin_pins ORDER BY entity_uri, node_id"
    ).fetchall()
    return [dict(r) for r in rows]


def delete_origin_pin(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
) -> bool:
    """Delete the pin for ``(entity_uri, node_id)``.

    Returns ``True`` if a row was deleted, ``False`` if no such pin existed.
    """
    cur = conn.execute(
        "DELETE FROM origin_pins WHERE entity_uri = ? AND node_id = ?",
        (entity_uri, node_id),
    )
    return bool(cur.rowcount > 0)
