"""Tests for the DNSSEC-trust FAIL-CLOSED structural guard
(scripts/check_dnssec_trust_fail_closed.py, Rev 6 §11 / I1/I2/I3/I4/I5/I10, plan 3c.5).

The guard fails CI if any first-trust or recency path could return a trusted key
without:
  (a) clearing the operator-pin / DNSSEC root tier (rooted, not derived — I1),
  (b) a chain-validated record (``resolve_dnssec_binding`` consulted — I2),
  (c) the canonical signed-``entity_uri`` host derivation (``host_from_entity_uri`` — I3),
  (d) monotonic-epoch + the asymmetric relay-path re-check (``accept_epoch`` +
      ``recheck_relay_binding`` wired on the TRUSTED path — I4/I5);
and if DNS-unreachable / unvalidatable / ``revoked`` / rollback do not resolve to a
typed reject (``relay_origin_revoked`` / ``relay_origin_rolled_back`` /
``relay_origin_recheck_unreachable`` + ``RecheckRejected``).

It mirrors the default-off guard's discipline: AST-scoped ordering checks (not vacuous
string-greps that pass trivially), plus a live-tree pass and synthetic negatives proving
the guard catches each class of regression.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_checker():
    # node/tests/<this file> -> repo root is parents[2]; the guard lives in scripts/.
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "check_dnssec_trust_fail_closed.py"
    )
    spec = importlib.util.spec_from_file_location("check_dnssec_trust_fail_closed", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_tree_passes_the_guard() -> None:
    """The live source tree satisfies every fail-closed assertion."""
    checker = _load_checker()
    assert checker.check() == 0


# --- Ladder first-trust assertions (I1/I2/I3/I4) -----------------------------


def test_ladder_flags_trusted_before_pin_or_dnssec() -> None:
    """A ladder that returns _trusted BEFORE consulting the pin tier / DNSSEC chain
    is silent first-seen-wins (I1 violation) — the guard must catch the inversion."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    return _trusted('first seen wins')\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    ep.accept_epoch(conn, host, result.record.epoch)\n"
    )
    failures = checker._check_ladder(text)
    assert any("_trusted" in f and ("pin" in f.lower() or "dnssec" in f.lower()) for f in failures)


def test_ladder_flags_missing_dnssec_resolution() -> None:
    """A ladder that never consults the chain-validated record (no
    resolve_dnssec_binding) cannot be DNSSEC-rooted (I2)."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    ep.accept_epoch(conn, host, 5)\n"
        "    return _trusted('no chain check')\n"
    )
    failures = checker._check_ladder(text)
    assert any("resolve_dnssec_binding" in f for f in failures)


def test_ladder_flags_missing_canonical_host() -> None:
    """A ladder that does not derive the host from the signed entity_uri via the one
    canonical derivation (host_from_entity_uri) violates I3."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    ep.accept_epoch(conn, 'h', result.record.epoch)\n"
        "    return _trusted('no canonical host')\n"
    )
    failures = checker._check_ladder(text)
    assert any("host_from_entity_uri" in f for f in failures)


def test_ladder_flags_missing_monotonic_epoch() -> None:
    """A ladder that never enforces the monotonic-epoch floor (accept_epoch) cannot
    reject a rollback (I4)."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    return _trusted('no epoch floor')\n"
    )
    failures = checker._check_ladder(text)
    assert any("accept_epoch" in f for f in failures)


def test_ladder_passes_on_rooted_engine() -> None:
    """A ladder that consults the pin tier, the DNSSEC chain, the canonical host, and
    the monotonic epoch BEFORE any _trusted return satisfies the first-trust assertions."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    if existing is not None:\n"
        "        if pinstore.pin_matches(existing, candidate_key_fpr, now=now):\n"
        "            return _trusted('matches established pin')\n"
        "        return _rejected('candidate disagrees with established pin')\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    if host is None:\n"
        "        return _quarantine_or_fail_closed(conn)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    if result.outcome is DnssecResult.Outcome.REVOKED:\n"
        "        return _rejected('dnssec revoked record')\n"
        "    if not ep.accept_epoch(conn, host, result.record.epoch):\n"
        "        return _rejected('dnssec epoch rollback')\n"
        "    return _trusted('dnssec-validated binding')\n"
    )
    assert checker._check_ladder(text) == []


# --- Recency / asymmetric re-check assertions (I5/I10) -----------------------


def test_recheck_flags_missing_revoked_reject() -> None:
    """A recheck.py that never hard-rejects a positive withdrawal
    (no relay_origin_revoked) is incomplete (I5)."""
    checker = _load_checker()
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('x')\n"
    )
    failures = checker._check_recheck(recheck)
    assert any("relay_origin_revoked" in f for f in failures)


def test_recheck_flags_missing_rollback_reject() -> None:
    checker = _load_checker()
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('x')\n"
    )
    failures = checker._check_recheck(recheck)
    assert any("relay_origin_rolled_back" in f for f in failures)


def test_recheck_flags_missing_unreachable_reject() -> None:
    """DNS-unreachable past grace must fail closed (relay_origin_recheck_unreachable)."""
    checker = _load_checker()
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_rolled_back")\n'
        "raise RecheckRejected('x')\n"
    )
    failures = checker._check_recheck(recheck)
    assert any("relay_origin_recheck_unreachable" in f for f in failures)


def test_recheck_flags_missing_typed_raise() -> None:
    """A recheck engine that never raises the typed reject (returns trust instead) is a
    silent-trust hole on the reject branches."""
    checker = _load_checker()
    recheck = (
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "return None\n"  # no typed raise
    )
    failures = checker._check_recheck(recheck)
    assert any("RecheckRejected" in f for f in failures)


def test_recheck_passes_on_asymmetric_engine() -> None:
    checker = _load_checker()
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('revoked')\n"
    )
    assert checker._check_recheck(recheck) == []


# --- TRUSTED-path gating: a key is never honored without the recheck (I5) ----


def test_trusted_gate_flags_key_without_recheck() -> None:
    """The DNSSEC first-trust helper must route a TRUSTED verdict through
    recheck_relay_binding BEFORE returning a key — else a DNSSEC key is honored with
    no recency/revocation path (I5)."""
    checker = _load_checker()
    helper = (
        "def _dnssec_first_trust_keys(conn, *, node_id, entity_uri, candidate, "
        "candidate_fp, relay_peer):\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
        "    decision = resolve_first_trust(conn, candidate_key_fpr=candidate_fp)\n"
        "    if decision.outcome is TrustDecision.Outcome.TRUSTED:\n"
        "        keys = _keys_from_manifest(candidate)\n"
        "        return keys\n"
    )
    failures = checker._check_trusted_gate(helper)
    assert any("recheck_relay_binding" in f for f in failures)


def test_trusted_gate_flags_recheck_after_key() -> None:
    """The recheck must precede the key return, not follow it (else the key is already
    honored before the recency check could reject it)."""
    checker = _load_checker()
    helper = (
        "def _dnssec_first_trust_keys(conn, *, node_id, entity_uri, candidate, "
        "candidate_fp, relay_peer):\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
        "    decision = resolve_first_trust(conn, candidate_key_fpr=candidate_fp)\n"
        "    if decision.outcome is TrustDecision.Outcome.TRUSTED:\n"
        "        keys = _keys_from_manifest(candidate)\n"
        "        recheck_relay_binding(conn)\n"
        "        return keys\n"
    )
    failures = checker._check_trusted_gate(helper)
    assert any("recheck_relay_binding" in f and "before" in f.lower() for f in failures)


def test_trusted_gate_passes_when_recheck_precedes_key() -> None:
    checker = _load_checker()
    helper = (
        "def _dnssec_first_trust_keys(conn, *, node_id, entity_uri, candidate, "
        "candidate_fp, relay_peer):\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
        "    decision = resolve_first_trust(conn, candidate_key_fpr=candidate_fp)\n"
        "    if decision.outcome is TrustDecision.Outcome.TRUSTED:\n"
        "        recheck_relay_binding(conn)\n"
        "        keys = _keys_from_manifest(candidate)\n"
        "        return keys\n"
    )
    assert checker._check_trusted_gate(helper) == []
