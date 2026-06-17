"""Tests for the DNSSEC-trust default-off structural guard
(scripts/check_dnssec_trust_default_off.py, plan NF-R5C-2 / TB-4).

The guard fails CI if the DNSSEC first-trust ladder is not default-off + lazy-imported
(Rev 6 I11), if the ladder is reachable with the flag OFF, or if the TRUSTED relay path is
not gated by the fail-closed recency re-check seam (TB-4).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_checker():
    # node/tests/<this file> -> repo root is parents[2]; the guard lives in scripts/.
    script_path = (
        Path(__file__).resolve().parents[2] / "scripts" / "check_dnssec_trust_default_off.py"
    )
    spec = importlib.util.spec_from_file_location("check_dnssec_trust_default_off", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_tree_passes_the_guard() -> None:
    """The live source tree satisfies all four assertions (default-off, lazy-import,
    reachability behind the flag, and the TB-4 recheck gate)."""
    checker = _load_checker()
    assert checker.check() == 0


# --- assert 3: reachability (static, flag-guarded) ---------------------------


def test_reachability_flags_missing_helper() -> None:
    checker = _load_checker()
    text = "def other_helper():\n    return resolve_first_trust(conn)\n"
    failures = checker._check_reachability(text)
    assert failures
    assert any("_dnssec_first_trust_keys" in f for f in failures)


def test_reachability_flags_missing_flag_guard() -> None:
    checker = _load_checker()
    text = "def _dnssec_first_trust_keys(settings):\n    return resolve_first_trust(conn)\n"
    failures = checker._check_reachability(text)
    assert failures
    assert any("flag guard" in f for f in failures)


def test_reachability_flags_ladder_referenced_before_guard() -> None:
    """If `resolve_first_trust` is referenced BEFORE the flag guard, the ladder could be
    reachable with the flag OFF — the guard must catch the ordering inversion."""
    checker = _load_checker()
    text = (
        "def _dnssec_first_trust_keys(settings):\n"
        "    x = resolve_first_trust(conn)\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
    )
    failures = checker._check_reachability(text)
    assert any("BEFORE" in f for f in failures)


def test_reachability_passes_when_guard_precedes_ladder() -> None:
    checker = _load_checker()
    text = (
        "def _dnssec_first_trust_keys(settings):\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
        "    decision = resolve_first_trust(conn)\n"
    )
    assert checker._check_reachability(text) == []


def test_reachability_scope_ignores_earlier_unrelated_mention() -> None:
    """L-2: a `resolve_first_trust` mention OUTSIDE the helper (an earlier docstring
    or a second helper) before the guard must NOT trip the ordering inversion — the
    check is scoped to the helper function body only."""
    checker = _load_checker()
    text = (
        '"""Module docstring mentioning resolve_first_trust up top."""\n'
        "def _earlier_helper():\n"
        "    return resolve_first_trust(other)\n"
        "def _dnssec_first_trust_keys(settings):\n"
        "    if not settings.federation_dnssec_trust_enabled:\n"
        "        return None\n"
        "    decision = resolve_first_trust(conn)\n"
    )
    assert checker._check_reachability(text) == []


# --- assert 4: TB-4 / I5 recency/revocation gate -----------------------------


def test_recheck_gate_flags_missing_recheck_call() -> None:
    checker = _load_checker()
    origin = "keys = _keys_from_manifest(candidate)\nreturn keys\n"  # no recheck gate
    recheck = (
        "class RecheckRejected(Exception): ...\n"
        "def recheck_relay_binding(conn):\n"
        '    _audit_relay("relay_origin_revoked")\n'
        "    raise RecheckRejected()\n"
    )
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("recheck_relay_binding(" in f for f in failures)


def test_recheck_gate_flags_recheck_without_positive_revocation() -> None:
    """A recheck.py that never rejects a positive withdrawal (no relay_origin_revoked)
    is incomplete; the guard must reject it."""
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = (
        "class RecheckRejected(Exception): ...\n"
        "def recheck_relay_binding(conn):\n"
        "    raise RecheckRejected()\n"  # no relay_origin_revoked audit
    )
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("relay_origin_revoked" in f for f in failures)


def test_recheck_gate_flags_recheck_without_typed_reject() -> None:
    """A recheck.py that returns instead of raising a typed reject is a silent-trust
    hole; the guard must reject it."""
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = (
        "def recheck_relay_binding(conn):\n"
        '    _audit_relay("relay_origin_revoked")\n'
        "    return None\n"  # no typed raise
    )
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("RecheckRejected" in f for f in failures)


def test_recheck_gate_flags_reject_symbols_only_in_docstring() -> None:
    """F-FC-2 (R3 caveat): a recheck.py whose reject symbols + RecheckRejected appear
    ONLY in the engine docstring (the body always HONORs / returns) is a silent-trust
    hole. The AST-scoped check must catch it — a docstring substring is not a reject."""
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = (
        "class RecheckRejected(Exception): ...\n"
        "def recheck_relay_binding(conn):\n"
        '    """Mentions relay_origin_revoked and raise RecheckRejected in prose only."""\n'
        "    return None\n"  # body HONORS unconditionally; symbols only in docstring
    )
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("relay_origin_revoked" in f for f in failures)
    assert any("RecheckRejected" in f for f in failures)


def test_recheck_gate_passes_on_asymmetric_engine() -> None:
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = (
        "class RecheckRejected(OriginIdentityError): ...\n"
        "def recheck_relay_binding(conn):\n"
        '    _audit_relay("relay_origin_revoked", node_id=node_id, entity_uri=entity_uri)\n'
        "    raise RecheckRejected('revoked')\n"
    )
    assert checker._check_recheck_gate(origin, recheck) == []
