"""Rotation grace via the pinned prev_fpr on the relay re-check (Rev 6 I6 — 3c.3).

Rev 6 I6: the per-fact verifying key comes only from the DNSSEC-validated
fingerprint, or — within ``federation_key_rotation_grace_hours`` of a rotation —
the committed ``prev_fpr``. On the relay path the recency re-check
(``recheck_relay_binding``) must therefore HONOR a relayed fact whose origin key
matches the proven ``prev_fpr`` while inside the grace window, and REJECT it once
the window has elapsed.

The grace is anchored on the pinned ``prev_until`` (set by the Commit-1 rotation
path: on a rotation the OLD pinned key becomes ``prev_fpr`` with ``prev_until`` =
the record's committed deadline OR ``now + federation_key_rotation_grace_hours``).
The predicate is the shared ``pin.pin_matches`` (current-or-prev-within-grace).

These tests drive the re-check directly with a pin that already carries a
rotation grace window (as Commit-1's rotation path would have left it), and a
relayed candidate key equal to the retiring ``prev_fpr``.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec import epoch as ep
from stigmem_node.federation.dnssec import freshness as fr
from stigmem_node.federation.dnssec import pin as pinstore
from stigmem_node.federation.dnssec import recheck as rc

from .conftest import HOST, NOW

ENTITY_URI = "https://memory.acme.example/"
CANON_HOST = HOST.rstrip(".")
NODE_ID = "node-A"
# The fixture's live ACTIVE binding (conftest.DEFAULT_RECORD) is the CURRENT
# (post-rotation) key the zone now serves.
CURRENT_FPR = "abc123def"
# The retiring key from the most recent rotation, still in its grace window.
PREV_FPR = "oldkey111"
NOW_DT = datetime.fromtimestamp(NOW, tz=UTC)


class _Settings:
    federation_dnssec_recheck_floor_seconds = 300
    federation_dnssec_recheck_cap_seconds = 3600
    federation_dnssec_unreachable_grace_seconds = 86400
    federation_dnssec_unreachable_ttl_multiple = 4
    federation_dnssec_max_rrsig_age = 7 * 24 * 60 * 60
    federation_key_rotation_grace_hours = 168


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
def settings() -> _Settings:
    return _Settings()


@pytest.fixture()
def audit_capture(monkeypatch) -> list[str]:
    seen: list[str] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: seen.append(et))
    return seen


def _seed_rotated_pin(conn: sqlite3.Connection, *, prev_until: str, validated_at: datetime) -> None:
    """Pin a post-rotation binding: current=CURRENT_FPR, prev=PREV_FPR within grace."""
    pinstore.upsert_pin(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=CURRENT_FPR,
        epoch=7,
        host=CANON_HOST,
        prev_fpr=PREV_FPR,
        prev_until=prev_until,
        now=validated_at,
    )
    ep.accept_epoch(conn, CANON_HOST, 7)
    ep.mark_signed_delegation(conn, CANON_HOST)
    fr.mark_fresh(conn, CANON_HOST, now=validated_at.isoformat())
    conn.commit()


def test_prev_fpr_relayed_key_honored_within_grace(conn, settings, record_chain_factory) -> None:
    # Pin a rotation whose grace window is still open (prev_until 1h in the future).
    grace_until = (NOW_DT + timedelta(hours=1)).isoformat()
    _seed_rotated_pin(conn, prev_until=grace_until, validated_at=NOW_DT - timedelta(hours=2))
    # The zone still serves the CURRENT key; the relayed fact is signed by the
    # retiring PREV_FPR. Within grace -> HONOR (no raise).
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=7")
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=PREV_FPR,
        resolver=resolver,
        settings=settings,
        now=NOW_DT,
    )  # honor


def test_prev_fpr_relayed_key_rejected_past_grace(
    conn, settings, audit_capture, record_chain_factory
) -> None:
    # The grace window has already closed (prev_until 1h in the PAST).
    grace_until = (NOW_DT - timedelta(hours=1)).isoformat()
    _seed_rotated_pin(conn, prev_until=grace_until, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=7")
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PREV_FPR,
            resolver=resolver,
            settings=settings,
            now=NOW_DT,
        )
    # Past-grace prior key is an unsanctioned key on a current binding -> key changed.
    assert "relay_origin_key_changed" in audit_capture


def test_current_fpr_relayed_key_always_honored(conn, settings, record_chain_factory) -> None:
    # The relayed fact signed by the CURRENT key is honored regardless of grace.
    grace_until = (NOW_DT - timedelta(hours=1)).isoformat()  # prev grace closed
    _seed_rotated_pin(conn, prev_until=grace_until, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=7")
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=CURRENT_FPR,
        resolver=resolver,
        settings=settings,
        now=NOW_DT,
    )  # honor
