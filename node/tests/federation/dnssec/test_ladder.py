"""First-trust ladder: operator-pin -> DNSSEC -> operator-confirm -> fail-closed.

Rev 6 §2/I1/I10 ladder, build-phase 3b. ``resolve_first_trust`` is a PURE
resolver: it composes the already-built 3a/3b primitives (pin store, DNSSEC
resolve, epoch pin, RRSIG-age clamp, quarantine) into the precedence ladder and
returns a ``TrustDecision`` (``TRUSTED | PENDING_CONFIRM | REJECTED`` + reason).
It does NOT read ``federation_dnssec_trust_enabled`` (the flag gates the CALL
SITE in the next batch), does NOT touch the relay path, and is not wired
anywhere yet.

Reuses the signed offline DNSSEC fixture harness in this directory's
``conftest.py``. The fixture leaf host is ``memory.acme.example`` and its active
binding record is ``fpr=abc123def; epoch=7``.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from stigmem_node.db import apply_migrations
from stigmem_node.federation.dnssec import epoch as ep
from stigmem_node.federation.dnssec import freshness as fr
from stigmem_node.federation.dnssec import ladder as ladder_mod
from stigmem_node.federation.dnssec import pin as p
from stigmem_node.federation.dnssec import quarantine as q
from stigmem_node.federation.dnssec.ladder import TrustDecision, resolve_first_trust
from stigmem_node.federation.dnssec.record import BindingRecord
from stigmem_node.federation.dnssec.resolve import DnssecResult
from stigmem_node.settings import Settings

from .conftest import HOST
from .conftest import NOW as _CONFTEST_NOW

# A DNSSEC-capable entity_uri whose host canonicalizes to the fixture HOST.
HOSTNAME = HOST.rstrip(".")  # memory.acme.example
ENTITY_URI = "https://" + HOSTNAME + "/"
RECORD_FPR = "abc123def"  # the fixture's active binding fingerprint
RECORD_EPOCH = 7
NODE_ID = "node-A"
# Within the fixture's max-RRSIG-age window of the binding inception (2026-06-01)
# so the real age clamp reads the default ``valid_chain`` binding as fresh.
_NOW = datetime(2026, 6, 5, tzinfo=UTC)


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
def settings() -> Settings:
    # A fresh default settings object (flags off — the ladder ignores the flag).
    return Settings()


def _call(conn, settings, resolver, *, entity_uri=ENTITY_URI, node_id=NODE_ID,
          candidate=RECORD_FPR, now=_NOW, relay_peer="peer-1", source="relay",
          rrsig_age_seconds=None) -> TrustDecision:
    return resolve_first_trust(
        conn,
        entity_uri=entity_uri,
        node_id=node_id,
        candidate_key_fpr=candidate,
        resolver=resolver,
        settings=settings,
        now=now,
        relay_peer=relay_peer,
        source=source,
        rrsig_age_seconds=rrsig_age_seconds,
    )


# --- step 1: operator-pin / existing pin -------------------------------------


def test_existing_pin_match_is_trusted(conn, settings, valid_chain):
    p.upsert_pin(conn, entity_uri=ENTITY_URI, node_id=NODE_ID, key_fpr=RECORD_FPR,
                 epoch=RECORD_EPOCH, host=HOSTNAME, now=_NOW - timedelta(hours=1))
    d = _call(conn, settings, valid_chain)
    assert d.outcome is TrustDecision.Outcome.TRUSTED, d
    # last_validated_at refreshed on the matching re-validation.
    assert p.get_pin(conn, ENTITY_URI, NODE_ID).last_validated_at == _NOW.isoformat()


def test_existing_pin_mismatch_is_rejected(conn, settings, valid_chain):
    """An established pin whose stored fpr differs from the candidate is an attack
    against the anchor; do NOT silently fall through to DNSSEC first-trust."""
    p.upsert_pin(conn, entity_uri=ENTITY_URI, node_id=NODE_ID, key_fpr="pinned-other",
                 epoch=RECORD_EPOCH, host=HOSTNAME, now=_NOW)
    d = _call(conn, settings, valid_chain, candidate="totally-different")
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert "pin" in d.reason.lower()


# --- step 2: DNSSEC ----------------------------------------------------------


def test_secure_fresh_binding_is_trusted_and_pins(conn, settings, valid_chain):
    d = _call(conn, settings, valid_chain)
    assert d.outcome is TrustDecision.Outcome.TRUSTED, d
    # A pin was created for the identity.
    pin = p.get_pin(conn, ENTITY_URI, NODE_ID)
    assert pin is not None
    assert pin.key_fpr == RECORD_FPR
    assert pin.epoch == RECORD_EPOCH
    assert pin.host == HOSTNAME
    # Epoch floor + sticky-signed + fresh markers were stamped for the host.
    assert ep.signed_delegation_seen(conn, HOSTNAME) is True
    assert fr.was_previously_fresh(conn, HOSTNAME) is True


def test_candidate_not_matching_record_is_rejected(conn, settings, valid_chain):
    """SECURE record binds a DIFFERENT fpr than the candidate -> hard reject."""
    d = _call(conn, settings, valid_chain, candidate="some-other-fpr")
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None  # nothing pinned


def test_revoked_record_is_rejected(conn, settings, revoked_chain):
    d = _call(conn, settings, revoked_chain, candidate="")
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert "revok" in d.reason.lower()


def test_epoch_rollback_is_rejected(conn, settings, valid_chain):
    # Pin the host's epoch floor above the record's epoch=7 so it reads as rollback.
    ep.accept_epoch(conn, HOSTNAME, 100)
    d = _call(conn, settings, valid_chain)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert "epoch" in d.reason.lower() or "rollback" in d.reason.lower()
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None


def test_aged_rrsig_never_fresh_falls_through_to_confirm(conn, settings, binding_chain_factory):
    """A SECURE binding whose binding RRSIG inception is older than the age ceiling,
    on a never-fresh host -> PENDING_CONFIRM (a slow-resigning zone stays usable
    behind a human gate, I4). The age is derived from the real RRSIG inception via
    the resolver, NOT injected."""
    aged_inception = _NOW - timedelta(seconds=settings.federation_dnssec_max_rrsig_age + 86400)
    resolver = binding_chain_factory(inception=aged_inception)
    d = _call(conn, settings, resolver)
    assert d.outcome is TrustDecision.Outcome.PENDING_CONFIRM, d
    # The candidate was quarantined for operator-confirm.
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is not None
    # No pin yet (not trusted).
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None


def test_fresh_rrsig_inception_is_trusted(conn, settings, binding_chain_factory):
    """A SECURE binding whose binding RRSIG inception is recent (within the age
    ceiling) is fresh -> TRUSTED, with the age derived end-to-end via the
    resolver (not injected)."""
    recent_inception = _NOW - timedelta(seconds=settings.federation_dnssec_max_rrsig_age // 2)
    resolver = binding_chain_factory(inception=recent_inception)
    d = _call(conn, settings, resolver)
    assert d.outcome is TrustDecision.Outcome.TRUSTED, d
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is not None


def test_aged_rrsig_previously_fresh_is_rejected(conn, settings, binding_chain_factory):
    """A previously-fresh sticky host suddenly serving only an aged binding RRSIG
    is an attack signal -> hard reject (I4). Age is derived from the real RRSIG
    inception via the resolver."""
    fr.mark_fresh(conn, HOSTNAME, now=(_NOW - timedelta(days=1)).isoformat())
    aged_inception = _NOW - timedelta(seconds=settings.federation_dnssec_max_rrsig_age + 86400)
    resolver = binding_chain_factory(inception=aged_inception)
    d = _call(conn, settings, resolver)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is None


def test_two_covering_rrsigs_aged_real_sig_previously_fresh_is_rejected(
    conn, settings, two_covering_rrsigs_chain
):
    """F1 (CRITICAL) end-to-end: a binding TXT served with the real stale-but-valid
    RRSIG plus an injected near-now RRSIG signed by a rogue key. The validator must
    derive the freshness inception from ONLY the real (stale) signature, so on a
    previously-fresh host the age clamp fires -> REJECTED (aged-on-previously-fresh,
    I4). If the attacker's near-now inception leaked through, the binding would read
    as fresh and be TRUSTED — the bug this guards against."""
    # The validator's clock is pinned to the conftest NOW; resolve the ladder at
    # the same instant so the derived age (now - real-stale-inception ~ 40 days,
    # well past the 7-day ceiling) is self-consistent with the validation window.
    now = datetime.fromtimestamp(_CONFTEST_NOW, tz=UTC)
    fr.mark_fresh(conn, HOSTNAME, now=(now - timedelta(days=1)).isoformat())
    d = _call(conn, settings, two_covering_rrsigs_chain, now=now)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert "aged" in d.reason.lower() or "fresh" in d.reason.lower()
    # Hard fail-closed: nothing pinned, nothing parked.
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is None


def test_insecure_delegation_quarantines(conn, settings, unsigned_delegation):
    """Authenticated insecure (unsigned) delegation -> operator-confirm."""
    d = _call(conn, settings, unsigned_delegation)
    assert d.outcome is TrustDecision.Outcome.PENDING_CONFIRM, d
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is not None


def test_unvalidatable_absence_fails_closed(conn, settings, unvalidatable_absence):
    """An absence with no validatable denial proof -> reject (never fall through)."""
    d = _call(conn, settings, unvalidatable_absence)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d


def test_bogus_chain_is_rejected(conn, settings, forged_rrsig_chain):
    d = _call(conn, settings, forged_rrsig_chain)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d


def test_sticky_signed_then_absent_is_rejected(conn, settings, stripped_nsec3):
    """An authenticated absence on a host that has previously served a SIGNED
    delegation is an attack (sticky-signedness, I2) -> reject, not confirm."""
    ep.mark_signed_delegation(conn, HOSTNAME)
    d = _call(conn, settings, stripped_nsec3)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d


def test_plain_absence_quarantines(conn, settings, stripped_nsec3):
    """An authenticated absence on a never-signed host -> operator-confirm."""
    d = _call(conn, settings, stripped_nsec3)
    assert d.outcome is TrustDecision.Outcome.PENDING_CONFIRM, d
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is not None


# --- non-domain entity_uri (DNSSEC tier not applicable) ----------------------


def test_non_domain_entity_uri_quarantines(conn, settings, valid_chain):
    d = _call(conn, settings, valid_chain, entity_uri="urn:stigmem:node:7")
    assert d.outcome is TrustDecision.Outcome.PENDING_CONFIRM, d
    assert q.get_pending(conn, "urn:stigmem:node:7", NODE_ID) is not None


# --- step 3: operator-confirm queue cap --------------------------------------


def test_quarantine_cap_full_fails_closed(conn, settings, unsigned_delegation):
    """When the operator-confirm queue is full for the relay peer, the binding
    cannot be parked -> fail closed (REJECTED), not silently trusted."""
    settings.federation_dnssec_pending_confirm_cap = 1
    # Fill the cap with one row attributed to the same peer.
    q.quarantine(conn, entity_uri="https://other.example/", node_id="x",
                 candidate_key_fpr="f", source="relay", relay_peer="peer-1", now=_NOW, cap=1)
    d = _call(conn, settings, unsigned_delegation)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert "queue" in d.reason.lower() or "cap" in d.reason.lower() or "full" in d.reason.lower()


# --- TB-1: self-trust / self-cert (no self-signed shortcut) ------------------


def test_self_origin_is_not_auto_trusted(conn, settings, valid_chain):
    """TB-1: an origin block naming THIS node's own identity must NOT yield an
    unconditional TRUSTED via a self-signed shortcut. It must go through the same
    ladder. Here the candidate fpr does NOT match the DNSSEC record, so even a
    'self' origin resolves by the normal rules -> REJECTED (no self-bypass)."""
    d = resolve_first_trust(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        candidate_key_fpr="this-nodes-own-self-asserted-key",
        resolver=valid_chain,
        settings=settings,
        now=_NOW,
        relay_peer=None,
        source="self",
    )
    # Normal-rule resolution (DNSSEC record binds abc123def, not the self key).
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None


def test_self_origin_matching_dnssec_record_still_goes_through_ladder(conn, settings, valid_chain):
    """A 'self' origin whose candidate DOES match the DNSSEC record is trusted by
    the DNSSEC rule (not a self-bypass) and is pinned like any other origin."""
    d = resolve_first_trust(
        conn,
        entity_uri=ENTITY_URI,
        node_id=NODE_ID,
        candidate_key_fpr=RECORD_FPR,
        resolver=valid_chain,
        settings=settings,
        now=_NOW,
        relay_peer=None,
        source="self",
    )
    assert d.outcome is TrustDecision.Outcome.TRUSTED, d
    # Trust came from a DNSSEC pin, not a self shortcut.
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is not None


# --- I4 contract guard: ACTIVE must carry an RRSIG inception -----------------


def test_active_without_rrsig_inception_is_rejected(conn, settings, valid_chain, monkeypatch):
    """Contract breach: an ACTIVE outcome with no ``rrsig_inception`` cannot have
    its age derived, so it MUST fail closed (REJECTED) — never be treated as
    fresh (I4). Stub the resolver to return an inception-less ACTIVE."""
    record = BindingRecord(fpr=RECORD_FPR, epoch=RECORD_EPOCH)
    stub = DnssecResult(
        DnssecResult.Outcome.ACTIVE, record=record, host=HOSTNAME, rrsig_inception=None
    )
    monkeypatch.setattr(ladder_mod, "resolve_dnssec_binding", lambda *a, **k: stub)
    d = _call(conn, settings, valid_chain)
    assert d.outcome is TrustDecision.Outcome.REJECTED, d
    # Nothing pinned and nothing parked — a hard fail-closed.
    assert p.get_pin(conn, ENTITY_URI, NODE_ID) is None
    assert q.get_pending(conn, ENTITY_URI, NODE_ID) is None
