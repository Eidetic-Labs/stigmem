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

The checks are AST-scoped (not vacuous string-greps), with PER-BRANCH coverage:

  * F-FC-1: every ``If`` that positively tests a NON-ACTIVE ``DnssecResult.Outcome``
    member must reject/quarantine/fail-closed in its body and NEVER ``_trusted(`` —
    so a single mis-mapped branch (``REVOKED -> _trusted``), or a renamed/added
    non-ACTIVE outcome mapped to ``_trusted``, is caught.
  * F-FC-2: the recheck reject symbols / ``raise RecheckRejected`` are asserted
    against the engine function AST (an ``_audit_relay(...)`` string arg / a real
    ``ast.Raise``), so a docstring-only stub is caught.
  * F-FC-3: every ``_keys_from_manifest`` key-honor point must be dominated by a
    ``recheck_relay_binding(`` call on its OWN path — a second key-return branch
    with no recheck is caught.
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


# The non-ACTIVE outcome set the live ladder/recheck branches map to a reject. The
# guard enumerates this from the live enum; the tests pin the same realistic set so
# the synthetic snippets exercise the per-branch lattice as the guard would in CI.
_NON_ACTIVE = {
    "REVOKED",
    "BOGUS",
    "UNVALIDATABLE",
    "INSECURE",
    "ABSENT_AUTHENTICATED",
    "NOT_APPLICABLE",
}


def test_current_tree_passes_the_guard() -> None:
    """The live source tree satisfies every fail-closed assertion."""
    checker = _load_checker()
    assert checker.check() == 0


def test_outcome_enum_is_enumerated_from_resolve_source() -> None:
    """The non-ACTIVE set is derived from the LIVE enum (so a renamed/added outcome
    is reflected automatically, not a hard-coded three-spelling list)."""
    checker = _load_checker()
    resolve_text = checker._RESOLVE.read_text(encoding="utf-8")
    names = checker._outcome_member_names(resolve_text, [])
    assert "ACTIVE" in names
    assert names >= _NON_ACTIVE  # every non-ACTIVE outcome is enumerated


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
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
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
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
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
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
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
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
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
        "    if result.outcome in (DnssecResult.Outcome.BOGUS,\n"
        "                          DnssecResult.Outcome.UNVALIDATABLE):\n"
        "        return _rejected('dnssec no positive proof')\n"
        "    if not ep.accept_epoch(conn, host, result.record.epoch):\n"
        "        return _rejected('dnssec epoch rollback')\n"
        "    return _trusted('dnssec-validated binding')\n"
    )
    assert checker._check_ladder(text, non_active=_NON_ACTIVE) == []


# --- F-FC-1: per-branch reject-lattice catches mis-mapped / renamed outcomes -


def test_ladder_flags_revoked_mapped_to_trusted_with_unrelated_reject_elsewhere() -> None:
    """The CORE F-FC-1 regression: a branch mapping ``REVOKED -> _trusted`` passes
    the OLD whole-function check as long as SOME other branch calls ``_rejected(``.
    The per-branch lattice must catch the mis-mapped REVOKED branch specifically."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    if result.outcome is DnssecResult.Outcome.REVOKED:\n"
        "        return _trusted('OOPS: revoked wrongly trusted')\n"
        "    if result.outcome is DnssecResult.Outcome.BOGUS:\n"
        "        return _rejected('bogus chain')\n"  # unrelated reject elsewhere
        "    if not ep.accept_epoch(conn, host, result.record.epoch):\n"
        "        return _rejected('rollback')\n"
        "    return _trusted('active')\n"
    )
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
    assert any("REVOKED" in f and "_trusted" in f for f in failures)


def test_ladder_flags_renamed_nonactive_outcome_mapped_to_trusted() -> None:
    """A renamed/added non-ACTIVE outcome mapped to ``_trusted`` is caught because
    the non-ACTIVE set is enumerated from the live enum (here we feed the guard a
    non-ACTIVE set containing the renamed member to simulate the enum drift)."""
    checker = _load_checker()
    non_active = set(_NON_ACTIVE) | {"WITHDRAWN"}  # simulate a renamed/added outcome
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    if result.outcome is DnssecResult.Outcome.WITHDRAWN:\n"
        "        return _trusted('OOPS: a new non-ACTIVE outcome wrongly trusted')\n"
        "    if not ep.accept_epoch(conn, host, result.record.epoch):\n"
        "        return _rejected('rollback')\n"
        "    return _trusted('active')\n"
    )
    failures = checker._check_ladder(text, non_active=non_active)
    assert any("WITHDRAWN" in f and "_trusted" in f for f in failures)


def test_ladder_flags_nonactive_branch_that_neither_rejects_nor_trusts() -> None:
    """A non-ACTIVE branch that just falls through (no reject, no trust) is still a
    fail-open hole — the per-branch lattice must require a reject disposition."""
    checker = _load_checker()
    text = (
        "def resolve_first_trust(conn, *, entity_uri, node_id, candidate_key_fpr,\n"
        "                        resolver, settings, now):\n"
        "    existing = pinstore.get_pin(conn, entity_uri, node_id)\n"
        "    host = host_from_entity_uri(entity_uri)\n"
        "    result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "    if result.outcome is DnssecResult.Outcome.UNVALIDATABLE:\n"
        "        pass\n"  # neither rejects nor trusts -> falls through (fail-open)
        "    if not ep.accept_epoch(conn, host, result.record.epoch):\n"
        "        return _rejected('rollback')\n"
        "    return _trusted('active')\n"
    )
    failures = checker._check_ladder(text, non_active=_NON_ACTIVE)
    assert any("UNVALIDATABLE" in f for f in failures)


# --- Recency / asymmetric re-check assertions (I5/I10) -----------------------


def _wrap_engine(body_lines: str) -> str:
    """Wrap recheck-engine body lines in a real ``recheck_relay_binding`` function."""
    indented = "".join("    " + ln + "\n" for ln in body_lines.splitlines())
    return (
        "class RecheckRejected(OriginIdentityError): ...\n"
        "def recheck_relay_binding(conn, *, host=None, entity_uri, node_id, key_fpr,\n"
        "                          resolver, settings, now):\n" + indented
    )


def test_recheck_flags_missing_revoked_reject() -> None:
    """A recheck.py that never hard-rejects a positive withdrawal
    (no relay_origin_revoked audit arg) is incomplete (I5)."""
    checker = _load_checker()
    recheck = _wrap_engine(
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('x')"
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("relay_origin_revoked" in f for f in failures)


def test_recheck_flags_missing_rollback_reject() -> None:
    checker = _load_checker()
    recheck = _wrap_engine(
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('x')"
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("relay_origin_rolled_back" in f for f in failures)


def test_recheck_flags_missing_unreachable_reject() -> None:
    """DNS-unreachable past grace must fail closed (relay_origin_recheck_unreachable)."""
    checker = _load_checker()
    recheck = _wrap_engine(
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_rolled_back")\n'
        "raise RecheckRejected('x')"
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("relay_origin_recheck_unreachable" in f for f in failures)


def test_recheck_flags_missing_typed_raise() -> None:
    """A recheck engine that never raises the typed reject (returns trust instead) is a
    silent-trust hole on the reject branches."""
    checker = _load_checker()
    recheck = _wrap_engine(
        '_audit_relay("relay_origin_revoked")\n'
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "return None"  # no typed raise in the body
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("RecheckRejected" in f for f in failures)


def test_recheck_flags_reject_symbols_only_in_docstring() -> None:
    """F-FC-2: a recheck engine whose reject symbols + ``raise RecheckRejected`` appear
    ONLY in the docstring (the body always returns / HONORS) is a silent-trust hole —
    the AST-scoped check catches it (a docstring substring is not a reject)."""
    checker = _load_checker()
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        "def recheck_relay_binding(conn, *, host=None, entity_uri, node_id, key_fpr,\n"
        "                          resolver, settings, now):\n"
        '    """Prose only: relay_origin_revoked / relay_origin_rolled_back /\n'
        "    relay_origin_recheck_unreachable and raise RecheckRejected are described\n"
        '    here but never reached in the body, which always HONORs."""\n'
        "    return None\n"  # body HONORs unconditionally
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("relay_origin_revoked" in f for f in failures)
    assert any("RecheckRejected" in f for f in failures)


def test_recheck_flags_revoked_branch_that_honors() -> None:
    """F-FC-1 on the engine: a REVOKED branch that HONORs (returns, no raise) instead
    of failing closed is caught by the per-branch lattice."""
    checker = _load_checker()
    recheck = _wrap_engine(
        "result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "if result.outcome is DnssecResult.Outcome.REVOKED:\n"
        "    return None\n"  # OOPS: revoked honored instead of rejected
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('x')"
    )
    failures = checker._check_recheck(recheck, non_active=_NON_ACTIVE)
    assert any("REVOKED" in f for f in failures)


def test_recheck_passes_on_asymmetric_engine() -> None:
    checker = _load_checker()
    recheck = _wrap_engine(
        "result = resolve_dnssec_binding(entity_uri, resolver=resolver)\n"
        "if result.outcome is DnssecResult.Outcome.REVOKED:\n"
        '    _audit_relay("relay_origin_revoked")\n'
        "    raise RecheckRejected('revoked')\n"
        '_audit_relay("relay_origin_rolled_back")\n'
        '_audit_relay("relay_origin_recheck_unreachable")\n'
        "raise RecheckRejected('rollback')"
    )
    assert checker._check_recheck(recheck, non_active=_NON_ACTIVE) == []


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
    assert any("recheck_relay_binding" in f and "dominate" in f.lower() for f in failures)


def test_trusted_gate_flags_second_key_branch_without_recheck() -> None:
    """F-FC-3: the FIRST key-derivation branch is gated, but a SECOND key-return
    branch lacks a recheck. The old global ``min(recheck) > min(key)`` ordering
    passed (a recheck preceded the FIRST key); the per-branch domination must catch
    the ungated second honor point."""
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
        "    if decision.outcome is TrustDecision.Outcome.PENDING_CONFIRM:\n"
        "        keys = _keys_from_manifest(candidate)\n"  # OOPS: honored, no recheck
        "        return keys\n"
    )
    failures = checker._check_trusted_gate(helper)
    assert any("recheck_relay_binding" in f and "dominate" in f.lower() for f in failures)


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
