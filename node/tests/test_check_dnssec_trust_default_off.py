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


def test_reachability_flags_missing_flag_guard() -> None:
    checker = _load_checker()
    text = "def helper():\n    return resolve_first_trust(conn)\n"
    failures = checker._check_reachability(text)
    assert failures
    assert any("flag guard" in f for f in failures)


def test_reachability_flags_ladder_referenced_before_guard() -> None:
    """If `resolve_first_trust` is referenced BEFORE the flag guard, the ladder could be
    reachable with the flag OFF — the guard must catch the ordering inversion."""
    checker = _load_checker()
    text = (
        "x = resolve_first_trust(conn)\n"
        "if not settings.federation_dnssec_trust_enabled:\n"
        "    return None\n"
    )
    failures = checker._check_reachability(text)
    assert any("BEFORE" in f for f in failures)


def test_reachability_passes_when_guard_precedes_ladder() -> None:
    checker = _load_checker()
    text = (
        "if not settings.federation_dnssec_trust_enabled:\n"
        "    return None\n"
        "decision = resolve_first_trust(conn)\n"
    )
    assert checker._check_reachability(text) == []


# --- assert 4: TB-4 recheck fail-closed gate ---------------------------------


def test_recheck_gate_flags_missing_recheck_call() -> None:
    checker = _load_checker()
    origin = "keys = _keys_from_manifest(candidate)\nreturn keys\n"  # no recheck gate
    recheck = "class RecheckNotImplemented(Exception): ...\nraise RecheckNotImplemented()\n"
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("recheck_relay_binding(" in f for f in failures)


def test_recheck_gate_flags_non_failclosed_stub() -> None:
    """A recheck.py that does NOT raise the typed error (e.g. returns) is a silent-trust
    hole; the guard must reject it."""
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = "def recheck_relay_binding(*a, **k):\n    return None\n"  # no typed raise
    failures = checker._check_recheck_gate(origin, recheck)
    assert any("RecheckNotImplemented" in f for f in failures)


def test_recheck_gate_passes_on_failclosed_stub() -> None:
    checker = _load_checker()
    origin = "recheck_relay_binding(conn)\n"
    recheck = (
        "class RecheckNotImplemented(Exception): ...\n"
        "def recheck_relay_binding(*a, **k):\n    raise RecheckNotImplemented()\n"
    )
    assert checker._check_recheck_gate(origin, recheck) == []
