"""Relay-path DNSSEC recency/revocation re-check engine (Rev 6 I5 — 3c.2).

``recheck_relay_binding`` is the asymmetric recency/revocation engine the relay
path consults BEFORE honoring an already-pinned DNSSEC binding. Its contract
(Rev 6 I5, plan 3c.2):

  * **Cadence** — within ``effective_interval`` of the pin's persistent
    ``last_validated_at`` the binding is HONORED with no DNS egress (the resolver
    is never consulted). Anchored on the PERSISTENT ``pin.last_validated_at`` so
    revocation is detectable within the interval across restarts.
  * **Positive withdrawal is hard reject** — a DNSSEC-validated REVOKED record,
    or an epoch rollback, on the pinned binding -> raise + audit
    (``relay_origin_revoked`` / ``relay_origin_rolled_back``). An attacker cannot
    forge a withdrawal record, so a positive answer is always honored as proof.
  * **Suppression is time-boxed fail-closed, NEVER revocation** — no positive
    proof (BOGUS / UNVALIDATABLE / INSECURE / ABSENT_AUTHENTICATED, including a
    transport SERVFAIL/timeout mapped to BOGUS) is honored only while
    ``(now - pin.last_validated_at) <= min(unreachable_grace, k*ttl)``; past that
    it fails closed (``relay_origin_recheck_unreachable``), and it NEVER emits
    ``relay_origin_revoked`` (suppression is not a revocation primitive).
  * **Aged RRSIG on the relay path is hard reject** — operator-confirm is
    first-trust-only and cannot run mid-relay, so an aged-but-valid ACTIVE binding
    (FALLTHROUGH_CONFIRM or the previously-fresh REJECT) -> raise
    (``relay_origin_recheck_stale``).
  * **Rotation honored** — an ACTIVE binding with a higher epoch + a new
    fingerprint advances the pin (new key_fpr, prev_fpr=old, prev_until=grace) and
    marks fresh; a fingerprint matching NEITHER current-nor-prev -> raise
    (``relay_origin_key_changed``).

These tests write their OWN fresh TDD (no prior test_dnssec_recheck.py). They use
the offline DNSSEC fixture harness (``conftest.py``) for the resolver scenarios
and a freshly-migrated sqlite DB for the pin/epoch/freshness state.
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

# The entity_uri whose canonical host is the fixture HOST ("memory.acme.example").
ENTITY_URI = "https://memory.acme.example/"
CANON_HOST = HOST.rstrip(".")  # "memory.acme.example"
NODE_ID = "node-A"
# The default fixture binding (conftest.DEFAULT_RECORD) binds this fpr at epoch 7.
PINNED_FPR = "abc123def"
# A wall-clock reference aligned with the fixture's pinned validator NOW, so the
# fixtures' RRSIGs are fresh against the same `now` the re-check passes in.
NOW_DT = datetime.fromtimestamp(NOW, tz=UTC)


class _Settings:
    """Minimal settings stand-in carrying exactly the fields the re-check reads."""

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
def audit(monkeypatch) -> list[tuple[str, dict]]:
    """Capture audit_event.emit_nofail calls -> (event_type, kwargs)."""
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
    prev_fpr: str | None = None,
    prev_until: str | None = None,
    host: str = CANON_HOST,
) -> None:
    """Pin a DNSSEC binding (as the first-trust ladder would) + the host epoch floor."""
    pinstore.upsert_pin(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=key_fpr,
        epoch=epoch,
        host=host,
        prev_fpr=prev_fpr,
        prev_until=prev_until,
        now=validated_at,
    )
    ep.accept_epoch(conn, host, epoch)
    ep.mark_signed_delegation(conn, host)
    fr.mark_fresh(conn, host, now=validated_at.isoformat())
    conn.commit()


class _ExplodingResolver:
    """Fails the test if it is ever consulted (proves the cadence short-circuit)."""

    def query(self, qname: str, rdtype: str):  # pragma: no cover - must not run
        raise AssertionError("within-cadence re-check must NOT re-resolve (no DNS egress)")


# --------------------------------------------------------------------------- #
# typed reject surface
# --------------------------------------------------------------------------- #


def test_recheck_rejected_is_a_typed_origin_identity_error() -> None:
    """The typed reject is an OriginIdentityError subclass so the relay call site
    maps it cleanly to a fail-closed verdict."""
    from stigmem_node.federation.origin_identity import OriginIdentityError

    assert issubclass(rc.RecheckRejected, OriginIdentityError)


# --------------------------------------------------------------------------- #
# cadence: within-interval HONOR (no DNS)
# --------------------------------------------------------------------------- #


def test_within_cadence_honors_without_resolving(conn, settings) -> None:
    # Pinned 100s ago; the floor cadence is 300s -> within interval -> HONOR,
    # the resolver is never consulted.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(seconds=100))
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=PINNED_FPR,
        resolver=_ExplodingResolver(),
        settings=settings,
        now=NOW_DT,
    )  # returns None (honor) without raising or resolving


def test_missing_pin_is_fail_closed(conn, settings) -> None:
    # A re-check with no pin is a contract breach (the TRUSTED branch always pins
    # first) -> fail-closed reject, resolver never consulted.
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PINNED_FPR,
            resolver=_ExplodingResolver(),
            settings=settings,
            now=NOW_DT,
        )


# --------------------------------------------------------------------------- #
# ACTIVE: steady-state re-validation HONOR
# --------------------------------------------------------------------------- #


def test_past_cadence_active_match_honors(conn, settings, record_chain_factory) -> None:
    # Pinned long ago (past the floor cadence) -> re-resolve; the live record
    # still binds the pinned fpr at the same epoch -> HONOR + refresh
    # last_validated_at.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=7")
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
    pin = pinstore.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin is not None
    assert pin.last_validated_at == NOW_DT.isoformat()  # refreshed


# --------------------------------------------------------------------------- #
# ACTIVE rotation: higher epoch + new fpr -> HONOR + grace prev set
# --------------------------------------------------------------------------- #


def test_rotation_higher_epoch_new_fpr_honors_and_sets_grace(
    conn, settings, record_chain_factory
) -> None:
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    # The live record rotated: epoch 8, new fpr, prev_fpr = the old pinned fpr.
    resolver = record_chain_factory("v=stigmem1; fpr=newkey999; epoch=8; prev_fpr=abc123def")
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
    assert pin is not None
    assert pin.key_fpr == "newkey999"
    assert pin.epoch == 8
    # The old key is retained as prev with a live grace window (I6).
    assert pin.prev_fpr == "abc123def"
    assert pin.prev_until
    deadline = datetime.fromisoformat(pin.prev_until)
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=UTC)
    assert deadline > NOW_DT


def test_rotation_prev_until_uses_grace_when_record_omits_it(
    conn, settings, record_chain_factory
) -> None:
    # The record carries no prev_until; the re-check derives one from
    # federation_key_rotation_grace_hours (I6: grace OR record.prev_until).
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; fpr=newkey999; epoch=8; prev_fpr=abc123def")
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
    expected = NOW_DT + timedelta(hours=settings.federation_key_rotation_grace_hours)
    assert abs((deadline - expected).total_seconds()) < 2


# --------------------------------------------------------------------------- #
# ACTIVE rotation: fpr matching NEITHER current nor prev -> key changed reject
# --------------------------------------------------------------------------- #


def test_active_fpr_matches_neither_rejects_key_changed(
    conn, settings, audit, record_chain_factory
) -> None:
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    # Live record at SAME epoch but a different fpr (no rotation epoch bump): the
    # candidate the relay carries matches neither current nor prev -> key changed.
    resolver = record_chain_factory("v=stigmem1; fpr=stranger000; epoch=7")
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr="stranger000",
            resolver=resolver,
            settings=settings,
            now=NOW_DT,
        )
    assert "relay_origin_key_changed" in _audit_types(audit)


# --------------------------------------------------------------------------- #
# REVOKED: positive withdrawal -> hard reject + relay_origin_revoked
# --------------------------------------------------------------------------- #


def test_revoked_record_rejects_and_audits_revoked(conn, settings, audit, revoked_chain) -> None:
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PINNED_FPR,
            resolver=revoked_chain,
            settings=settings,
            now=NOW_DT,
        )
    assert "relay_origin_revoked" in _audit_types(audit)


# --------------------------------------------------------------------------- #
# ROLLBACK: ACTIVE record at a lower epoch than the host floor -> reject
# --------------------------------------------------------------------------- #


def test_rollback_lower_epoch_rejects_and_audits_rolled_back(
    conn, settings, audit, record_chain_factory
) -> None:
    # Host floor pinned at epoch 9; the live record serves epoch 8 (a rollback).
    _seed_pin(conn, epoch=9, validated_at=NOW_DT - timedelta(hours=2))
    resolver = record_chain_factory("v=stigmem1; fpr=abc123def; epoch=8")
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
    types = _audit_types(audit)
    assert "relay_origin_rolled_back" in types
    assert "relay_origin_revoked" not in types  # a rollback is NOT a revocation


# --------------------------------------------------------------------------- #
# AGED RRSIG on the relay path -> hard reject (operator-confirm is first-trust-only)
# --------------------------------------------------------------------------- #


def test_aged_rrsig_active_rejects_stale(conn, settings, audit, record_chain_factory) -> None:
    # The live ACTIVE record validates (expiration inside the validator window)
    # but its RRSIG inception is far in the past -> aged. On the relay path this
    # is a hard reject (FALLTHROUGH_CONFIRM/REJECT both -> reject), never a
    # mid-relay operator-confirm.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=2))
    aged_inception = datetime.fromtimestamp(NOW, tz=UTC) - timedelta(days=40)
    resolver = record_chain_factory(
        "v=stigmem1; fpr=abc123def; epoch=7", inception=aged_inception
    )
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
    types = _audit_types(audit)
    assert "relay_origin_recheck_stale" in types
    assert "relay_origin_revoked" not in types  # aged != revoked


# --------------------------------------------------------------------------- #
# SUPPRESSION (no positive proof) within grace -> HONOR; past grace -> reject
# --------------------------------------------------------------------------- #


def test_suppression_within_grace_honors(conn, settings, no_answer_chain) -> None:
    # Pinned 1h ago; a no-answer (UNVALIDATABLE/BOGUS) is within the unreachable
    # grace -> HONOR (the pinned key is still served, fail-OPEN within grace).
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=1))
    rc.recheck_relay_binding(
        conn,
        host=CANON_HOST,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        key_fpr=PINNED_FPR,
        resolver=no_answer_chain,
        settings=settings,
        now=NOW_DT,
    )  # honor (no raise)


def test_suppression_past_grace_rejects_unreachable_never_revoked(
    conn, settings, audit, no_answer_chain
) -> None:
    # Pinned far in the past, beyond min(unreachable_grace, k*ttl). A no-answer
    # PAST grace fails closed with relay_origin_recheck_unreachable — and NEVER
    # relay_origin_revoked (suppression is not a revocation primitive).
    _seed_pin(conn, validated_at=NOW_DT - timedelta(days=10))
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
    assert "relay_origin_revoked" not in types


def test_suppression_bogus_forged_chain_is_unreachable_not_revoked(
    conn, settings, audit, forged_rrsig_chain
) -> None:
    # A forged/broken chain maps to BOGUS = suppression class (no positive
    # proof). Past grace -> unreachable, NEVER revoked.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(days=10))
    with pytest.raises(rc.RecheckRejected):
        rc.recheck_relay_binding(
            conn,
            host=CANON_HOST,
            entity_uri=ENTITY_URI,
            node_id=NODE_ID,
            key_fpr=PINNED_FPR,
            resolver=forged_rrsig_chain,
            settings=settings,
            now=NOW_DT,
        )
    assert "relay_origin_recheck_unreachable" in _audit_types(audit)
    assert "relay_origin_revoked" not in _audit_types(audit)


def test_suppression_never_emits_revoked_within_grace(
    conn, settings, audit, no_answer_chain
) -> None:
    # Belt-and-suspenders for the I5 invariant: within grace a suppression honors
    # and emits NO revocation event at all.
    _seed_pin(conn, validated_at=NOW_DT - timedelta(hours=1))
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
    assert "relay_origin_revoked" not in _audit_types(audit)
