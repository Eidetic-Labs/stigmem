"""Regression: the I5 relay re-check cadence + grace anchor on DNS validation,
not on a pure ladder pin-match (build-phase 3c security fix).

The relay path runs the first-trust ladder (``resolve_first_trust``) BEFORE the
I5 recency/revocation re-check (``recheck_relay_binding``). Both the re-check
CADENCE and the unreachable/suppression GRACE are anchored on the persistent
``pin.last_validated_at``. ``last_validated_at`` MUST therefore mean "last
genuine DNSSEC chain validation": only a real DNS re-resolution may advance it.

The bug: the ladder's established-pin MATCH branch performed NO DNS work yet
called ``upsert_pin(..., now=now)``, stamping ``last_validated_at=now``. Composed
on the relay path, that meant the re-check immediately downstream saw
``now - last_validated_at == 0 < floor`` -> HONOR WITHOUT re-resolving, so a
``status=revoked`` / rolled-back record was never consulted. The same refresh
also let relay activity (not DNS) extend the unreachable grace indefinitely.

These tests compose the ladder + re-check EXACTLY as
``origin_identity._dnssec_first_trust_keys`` does (ladder TRUSTED -> re-check),
so they are the end-to-end proof the fix closes the bug. They are distinct from
``test_dnssec_recheck.py``, which calls ``recheck_relay_binding`` directly on a
stale-seeded pin and therefore never exercised the ladder's refresh.
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
from stigmem_node.federation.dnssec.ladder import TrustDecision, resolve_first_trust

from .conftest import HOST, NOW

ENTITY_URI = "https://memory.acme.example/"
CANON_HOST = HOST.rstrip(".")  # "memory.acme.example"
NODE_ID = "node-A"
PINNED_FPR = "abc123def"  # the fixture DEFAULT_RECORD binds this fpr at epoch 7
NOW_DT = datetime.fromtimestamp(NOW, tz=UTC)


class _Settings:
    """Settings stand-in carrying exactly the fields the ladder + re-check read."""

    federation_dnssec_recheck_floor_seconds = 300
    federation_dnssec_recheck_cap_seconds = 3600
    federation_dnssec_unreachable_grace_seconds = 86400
    federation_dnssec_unreachable_ttl_multiple = 4
    federation_dnssec_max_rrsig_age = 7 * 24 * 60 * 60
    federation_key_rotation_grace_hours = 168
    federation_dnssec_pending_confirm_cap = 100


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
def audit(monkeypatch) -> list[tuple[str, dict]]:
    seen: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: seen.append((et, kw)))
    return seen


def _audit_types(audit: list[tuple[str, dict]]) -> list[str]:
    return [et for et, _ in audit]


def _seed_pin(
    conn: sqlite3.Connection,
    *,
    key_fpr: str = PINNED_FPR,
    epoch: int = 7,
    validated_at: datetime,
    host: str = CANON_HOST,
) -> None:
    """Pin a DNSSEC binding (as the first-trust ladder would) + the host markers."""
    pinstore.upsert_pin(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=key_fpr,
        epoch=epoch,
        host=host,
        now=validated_at,
    )
    ep.accept_epoch(conn, host, epoch)
    ep.mark_signed_delegation(conn, host)
    fr.mark_fresh(conn, host, now=validated_at.isoformat())
    conn.commit()


def _ladder(conn, settings, resolver, *, now=NOW_DT) -> TrustDecision:
    return resolve_first_trust(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        candidate_key_fpr=PINNED_FPR,
        resolver=resolver,
        settings=settings,
        now=now,
        relay_peer="peer-1",
        source="relay",
    )


def _ladder_then_recheck(conn, settings, resolver, *, now=NOW_DT) -> None:
    """Compose ladder -> re-check exactly as _dnssec_first_trust_keys does.

    The ladder runs FIRST; on TRUSTED the relay path then runs the I5
    recency/revocation re-check. Raises ``RecheckRejected`` if the re-check
    rejects (the bug scenario must fail closed here).
    """
    decision = _ladder(conn, settings, resolver, now=now)
    assert decision.outcome is TrustDecision.Outcome.TRUSTED, decision
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=PINNED_FPR,
        resolver=resolver,
        settings=settings,
        now=now,
    )


# --------------------------------------------------------------------------- #
# (1) the ladder's established-pin match does NOT advance last_validated_at
# --------------------------------------------------------------------------- #


def test_pin_match_does_not_advance_last_validated_at(conn, settings, valid_chain) -> None:
    """A pure pin match (no DNS chain resolved) must leave ``last_validated_at``
    UNCHANGED — only a genuine DNSSEC resolution may stamp it (I5)."""
    seeded_at = NOW_DT - timedelta(hours=3)
    _seed_pin(conn, validated_at=seeded_at)

    decision = _ladder(conn, settings, valid_chain, now=NOW_DT)
    assert decision.outcome is TrustDecision.Outcome.TRUSTED

    pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin is not None
    # The seeded (old) timestamp survives the match; it was NOT advanced to NOW.
    assert pin.last_validated_at == seeded_at.isoformat()
    assert pin.last_validated_at != NOW_DT.isoformat()


# --------------------------------------------------------------------------- #
# (2) end-to-end: ladder pin-match no longer masks revocation / rollback
# --------------------------------------------------------------------------- #


def test_e2e_pinned_past_cadence_revoked_fails_closed(
    conn, settings, audit, record_chain_factory
) -> None:
    """An established pin past the cadence + a resolver now serving
    ``status=revoked`` -> the re-check re-resolves and REJECTS. The ladder
    pin-match must NOT refresh ``last_validated_at`` (which would let the
    re-check HONOR without consulting the tombstone).

    A single resolver backs both the ladder and the re-check in one composed
    call (as the relay path does): the ladder returns TRUSTED via the pin-match
    branch WITHOUT consulting DNS, then the re-check re-resolves the same chain
    and sees the revoked tombstone."""
    # Pinned well past the 300s floor cadence so the re-check WILL re-resolve —
    # provided the ladder did not just refresh last_validated_at to now.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; status=revoked; epoch=9; fpr=")

    with pytest.raises(rc.RecheckRejected):
        _ladder_then_recheck(conn, settings, resolver, now=NOW_DT)
    assert "relay_origin_revoked" in _audit_types(audit)


def test_e2e_pinned_past_cadence_rollback_fails_closed(
    conn, settings, audit, record_chain_factory
) -> None:
    """An established pin at epoch 9 past the cadence + a resolver serving a LOWER
    epoch (8) -> the re-check re-resolves and REJECTS the rollback. Proves the
    ladder pin-match did not mask the rollback by refreshing last_validated_at."""
    _seed_pin(conn, epoch=9, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory(f"v=stigmem1; fpr={PINNED_FPR}; epoch=8")

    with pytest.raises(rc.RecheckRejected):
        _ladder_then_recheck(conn, settings, resolver, now=NOW_DT)
    types = _audit_types(audit)
    assert "relay_origin_rolled_back" in types
    assert "relay_origin_revoked" not in types  # a rollback is NOT a revocation


def test_e2e_revocation_masked_if_pin_match_refreshed_cadence(
    conn, settings, audit, record_chain_factory
) -> None:
    """Direct demonstration the fix matters: had the ladder pin-match advanced
    ``last_validated_at`` to ``now``, the re-check would see it within the floor
    cadence and HONOR without re-resolving — masking the revoked record. With the
    fix, the seeded (old) timestamp survives so the re-check re-resolves and the
    revocation is caught. We assert both: the timestamp is unchanged after the
    ladder, AND the composed re-check rejects."""
    seeded_at = NOW_DT - timedelta(hours=2)
    _seed_pin(conn, validated_at=seeded_at)
    resolver = record_chain_factory("v=stigmem1; status=revoked; epoch=9; fpr=")

    decision = _ladder(conn, settings, resolver, now=NOW_DT)
    assert decision.outcome is TrustDecision.Outcome.TRUSTED
    # The ladder match left the anchor's last-validation time at the seeded value;
    # the re-check therefore reads it as past the floor cadence and re-resolves.
    pin_after_ladder = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin_after_ladder.last_validated_at == seeded_at.isoformat()

    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PINNED_FPR,
            resolver=resolver,
            settings=settings,
            now=NOW_DT,
        )
    assert "relay_origin_revoked" in _audit_types(audit)


# --------------------------------------------------------------------------- #
# (3) unreachable grace is anchored on the last genuine DNS validation, not on
#     relay activity: repeated pin-match relays do NOT extend the grace window.
# --------------------------------------------------------------------------- #


def test_repeated_pin_match_does_not_extend_unreachable_grace(
    conn, settings, audit, valid_chain, no_answer_chain
) -> None:
    """A facts-flowing attacker must not be able to extend the suppression grace
    by keeping relay activity alive. The grace is measured from the last GENUINE
    DNS validation; a pure pin-match relay does not refresh it.

    Seed the pin so the LAST genuine validation is past the unreachable grace
    (the grace is ``min(86400, 4*3600)=14400s`` with the pinned defaults). Drive
    repeated ladder pin-matches (the "facts kept flowing" activity) — each is
    TRUSTED but stamps no DNS time — then a suppressed (no-answer) re-check. With
    the grace anchored on the un-refreshed last_validated_at, the re-check is past
    grace and fails closed."""
    grace_s = min(
        settings.federation_dnssec_unreachable_grace_seconds,
        settings.federation_dnssec_unreachable_ttl_multiple
        * settings.federation_dnssec_recheck_cap_seconds,
    )
    last_genuine = NOW_DT - timedelta(seconds=grace_s + 600)  # past the grace
    _seed_pin(conn, validated_at=last_genuine)

    # "Facts kept flowing": several pin-match relays through the ladder. Each
    # validates against a healthy chain (TRUSTED) but performs no DNS resolution,
    # so none may advance the genuine-validation timestamp.
    for _ in range(3):
        decision = _ladder(conn, settings, valid_chain, now=NOW_DT)
        assert decision.outcome is TrustDecision.Outcome.TRUSTED
    pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin.last_validated_at == last_genuine.isoformat()  # NOT extended

    # Now the origin's DNS goes dark (suppression / no-answer). Because the grace
    # is anchored on the un-refreshed genuine-validation time (past grace), the
    # re-check fails closed rather than honoring indefinitely.
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PINNED_FPR,
            resolver=no_answer_chain,
            settings=settings,
            now=NOW_DT,
        )
    types = _audit_types(audit)
    assert "relay_origin_recheck_unreachable" in types
    assert "relay_origin_revoked" not in types  # suppression is never a revocation
