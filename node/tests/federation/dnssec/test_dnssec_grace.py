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


# --------------------------------------------------------------------------- #
# I6 (R1-F1): a rotation grace is CLAMPED to the configured policy. The record
# may SHORTEN the window but NEVER EXTEND it past `rotation_observed_at + grace`.
# --------------------------------------------------------------------------- #


def _pin_at_epoch7(conn: sqlite3.Connection, *, validated_at: datetime) -> None:
    """Pin a pre-rotation binding (CURRENT_FPR @ epoch 7, no prev grace)."""
    pinstore.upsert_pin(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=CURRENT_FPR,
        epoch=7,
        host=CANON_HOST,
        now=validated_at,
    )
    ep.accept_epoch(conn, CANON_HOST, 7)
    ep.mark_signed_delegation(conn, CANON_HOST)
    fr.mark_fresh(conn, CANON_HOST, now=validated_at.isoformat())
    conn.commit()


def test_rotation_record_far_future_prev_until_is_clamped_to_grace(
    conn, settings, record_chain_factory
) -> None:
    # A rotation record sets prev_until=2999-… (an attempt to honor the retired
    # key indefinitely, defeating I6). The re-check must CLAMP the pinned window
    # to now + federation_key_rotation_grace_hours, NOT honor the far-future date.
    _pin_at_epoch7(conn, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory(
        "v=stigmem1; fpr=newkey999; epoch=8; prev_fpr=abc123def; prev_until=2999-01-01T00:00:00"
    )
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr="newkey999",  # the new current key honors the rotation
        resolver=resolver,
        settings=settings,
        now=NOW_DT,
    )
    pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin is not None and pin.prev_fpr == CURRENT_FPR and pin.prev_until
    deadline = datetime.fromisoformat(pin.prev_until)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    ceiling = NOW_DT + timedelta(hours=settings.federation_key_rotation_grace_hours)
    assert abs((deadline - ceiling).total_seconds()) < 2  # clamped to the policy ceiling
    assert deadline < NOW_DT + timedelta(days=365)  # NOT the year-2999 deadline


def test_retired_key_rejected_at_grace_ceiling_despite_far_future_record(
    conn, settings, audit_capture, record_chain_factory
) -> None:
    # End-to-end of R1-F1: pin a rotation whose record claimed prev_until=2999-…
    # but is clamped to grace (168h). A fact still signed by the retired key is
    # REJECTED at now + 30 days (well past the 168h clamp), proving the far-future
    # record deadline did NOT extend the window.
    grace_hours = settings.federation_key_rotation_grace_hours  # 168h == 7 days
    rotation_observed = NOW_DT - timedelta(days=30)
    clamped = (rotation_observed + timedelta(hours=grace_hours)).isoformat()
    _seed_rotated_pin(conn, prev_until=clamped, validated_at=rotation_observed)
    # The zone still serves the CURRENT key; a relayed fact is signed by the
    # RETIRED prev key, now() = 30 days after the rotation -> past the clamped
    # grace -> reject (NOT honored to year 2999).
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
    assert "relay_origin_key_changed" in audit_capture


def test_rotation_record_may_shorten_grace_below_policy_ceiling(
    conn, settings, record_chain_factory
) -> None:
    # The record may SHORTEN the grace: a prev_until SOONER than now + grace is
    # honored as the earlier deadline (min(record, ceiling)).
    _pin_at_epoch7(conn, validated_at=NOW_DT - timedelta(hours=2))
    short_until = (NOW_DT + timedelta(hours=2)).isoformat()  # << 168h ceiling
    resolver = record_chain_factory(
        f"v=stigmem1; fpr=newkey999; epoch=8; prev_fpr=abc123def; prev_until={short_until}"
    )
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr="newkey999",
        resolver=resolver,
        settings=settings,
        now=NOW_DT,
    )
    pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin is not None and pin.prev_until
    deadline = datetime.fromisoformat(pin.prev_until)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    expected = NOW_DT + timedelta(hours=2)
    assert abs((deadline - expected).total_seconds()) < 2  # the EARLIER (shorter) deadline


def test_steady_state_recheck_does_not_extend_grace_window(
    conn, settings, record_chain_factory
) -> None:
    # R1-F1 steady-state: a record that keeps re-advertising prev_fpr (with an
    # EMPTY prev_until) across several re-checks within grace must NOT push the
    # deadline forward; the window lapses on its ORIGINAL schedule.
    rotation_observed = NOW_DT
    grace_hours = settings.federation_key_rotation_grace_hours  # 168h
    original_deadline = rotation_observed + timedelta(hours=grace_hours)
    # Seed the pin AS IF a rotation was just observed at NOW_DT (prev grace open).
    _seed_rotated_pin(
        conn, prev_until=original_deadline.isoformat(), validated_at=rotation_observed
    )
    # The zone keeps re-advertising the SAME rotation (current=CURRENT_FPR,
    # prev_fpr=PREV_FPR) with NO prev_until. Re-check repeatedly, advancing time
    # within grace each step. The pinned prev_until must NOT move forward.
    steady_record = f"v=stigmem1; fpr={CURRENT_FPR}; epoch=7; prev_fpr={PREV_FPR}"
    for hours in (24, 72, 120):  # all within the 168h window
        # Each step is past the floor cadence (validated_at advances on honor), so
        # the re-check re-resolves and runs _honor_active steady-state.
        step_now = rotation_observed + timedelta(hours=hours)
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=CURRENT_FPR,  # the current key honors
            resolver=record_chain_factory(steady_record),
            settings=settings,
            now=step_now,
        )
        pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
        assert pin is not None and pin.prev_until
        d = datetime.fromisoformat(pin.prev_until)
        if d.tzinfo is None:
            d = d.replace(tzinfo=UTC)
        # The deadline is PRESERVED — never advanced to step_now + grace.
        assert abs((d - original_deadline).total_seconds()) < 2

    # And the retired key lapses at the ORIGINAL deadline, not refreshed forward:
    # at original_deadline + 1h the prev key is rejected.
    past_grace = original_deadline + timedelta(hours=1)
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PREV_FPR,  # the retired key, now past the original window
            resolver=record_chain_factory(steady_record),
            settings=settings,
            now=past_grace,
        )


# --------------------------------------------------------------------------- #
# R1-F2: the rollback/freshness defenses are keyed on the host RE-DERIVED from
# the signed entity_uri, NOT a caller-passed host param.
# --------------------------------------------------------------------------- #


def test_host_rederived_from_entity_uri_not_passed_param(
    conn, settings, record_chain_factory
) -> None:
    # The epoch floor was pinned under the CANONICAL host (CANON_HOST). Pass a
    # mismatched/empty host param; a rollback to a lower epoch must STILL be
    # caught because the epoch floor is keyed on the host re-derived from the
    # signed entity_uri, not the bogus param.
    _seed_rotated_pin(
        conn,
        prev_until=(NOW_DT + timedelta(hours=1)).isoformat(),
        validated_at=NOW_DT - timedelta(hours=2),
    )
    ep.accept_epoch(conn, CANON_HOST, 9)  # raise the canonical-host floor to 9
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=8")  # rollback
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host="",  # empty/bogus param — must NOT silence the rollback defense
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=CURRENT_FPR,
            resolver=resolver,
            settings=settings,
            now=NOW_DT,
        )
