#!/usr/bin/env python3
"""CI guard: the DNSSEC first-trust ladder is default-OFF and lazy-imported (Rev 6 I11,
plan NF-R5C-2 / TB-4). Lands in the SAME PR as the 3b ladder wiring.

Asserts four things; any failure exits non-zero (the structural-guard contract):

  1. **Default-off** — ``Settings().federation_dnssec_trust_enabled is False``: a default
     node never enters the DNSSEC first-trust tier.

  2. **Lazy-import (I11)** — importing the relay resolver module graph
     (``stigmem_node.federation.origin_identity``) on a default node does NOT import
     dnspython / the ``[federation-dnssec]`` extra: no ``dns``/``dns.*`` module is in
     ``sys.modules`` afterwards. The DNSSEC validator/resolver are reached only through
     function-local imports on the flag-on path, so a flag-off node loads no DNSSEC code.

  3. **Reachability (static, AST-scoped)** — in ``origin_identity.py`` the ONLY call to the
     first-trust ladder is itself gated by an early
     ``if not settings.federation_dnssec_trust_enabled: return None`` inside the
     ``_dnssec_first_trust_keys`` helper, so a flag-off relay resolution can never reach
     ``resolve_first_trust``. We parse the module and confine the check to that helper's body
     (so an unrelated ``resolve_first_trust`` mention elsewhere — a docstring or a second
     helper — cannot fool the ordering check, L-2), asserting (a) the flag-guard ``If`` node
     exists and (b) it precedes EVERY ``resolve_first_trust`` reference inside the helper.

  4. **Recheck recency/revocation gate (TB-4 / I5)** — the helper routes a TRUSTED ladder
     verdict through ``recheck_relay_binding`` (the I5 recency/revocation seam) BEFORE
     honoring a key, and that seam is the REAL asymmetric engine (3c.2): it hard-rejects on a
     positive withdrawal and fails closed on suppression past grace. This makes the "trust a
     DNSSEC pin with no revocation path" window unreachable STRUCTURALLY, not just by an
     undocumented flag (TB-4). We assert the helper text invokes ``recheck_relay_binding(``
     before honoring TRUSTED AND that ``recheck.py`` actually implements the asymmetric
     rejects — it emits ``relay_origin_revoked`` (positive revocation) and raises a typed
     reject (``RecheckRejected``) — WITHOUT requiring the old always-raise stub.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

_HELPER_NAME = "_dnssec_first_trust_keys"

_BASE = Path(__file__).resolve().parent.parent / "node" / "src" / "stigmem_node"
_ORIGIN_IDENTITY = _BASE / "federation" / "origin_identity.py"
_RECHECK = _BASE / "federation" / "dnssec" / "recheck.py"

# A short Python program run in a FRESH interpreter (so this guard's own imports do not
# pollute the measurement): import the relay resolver module on a default node and assert
# (a) the flag default is False and (b) no dnspython module is loaded.
_RUNTIME_PROBE = r"""
import sys
import stigmem_node.federation.origin_identity  # the relay resolver module graph
from stigmem_node.settings import Settings

errors = []
if Settings().federation_dnssec_trust_enabled is not False:
    errors.append("federation_dnssec_trust_enabled is not False by default")

dns_mods = sorted(m for m in sys.modules if m == "dns" or m.startswith("dns."))
if dns_mods:
    errors.append(
        "dnspython imported at relay-module load (I11 violation): " + ", ".join(dns_mods)
    )

if errors:
    for e in errors:
        sys.stderr.write("  - " + e + "\n")
    sys.exit(1)
sys.exit(0)
"""


def _check_runtime() -> list[str]:
    """Run the default-off + lazy-import probe in a fresh interpreter."""
    proc = subprocess.run(  # noqa: S603 — fixed argv, our own interpreter + probe
        [sys.executable, "-c", _RUNTIME_PROBE],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        out = (proc.stderr or proc.stdout or "").strip()
        return [
            "default-off / lazy-import runtime probe failed:\n"
            + "\n".join("    " + line for line in out.splitlines())
        ]
    return []


def _find_helper(tree: ast.AST) -> ast.FunctionDef | None:
    """Return the ``_dnssec_first_trust_keys`` function node, or None if absent."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == _HELPER_NAME:
            return node
    return None


def _flag_guard_line(func: ast.FunctionDef) -> int | None:
    """Line of the ``if not settings.federation_dnssec_trust_enabled:`` guard.

    Matches the structural shape (an ``If`` whose test is ``not <...>.
    federation_dnssec_trust_enabled``) rather than a text scan, so a mention of
    the flag in a docstring or comment cannot be mistaken for the guard.
    """
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.UnaryOp)
            and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Attribute)
            and test.operand.attr == "federation_dnssec_trust_enabled"
        ):
            return node.lineno
    return None


def _resolve_first_trust_lines(func: ast.FunctionDef) -> list[int]:
    """Lines of every ``resolve_first_trust`` reference WITHIN the helper.

    Covers both the lazy import and the call site; only references inside the
    helper's own body count, so an unrelated mention elsewhere in the module
    (docstring, a second helper) cannot fool the ordering check.
    """
    lines: list[int] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id == "resolve_first_trust":
            lines.append(node.lineno)
        elif isinstance(node, ast.alias) and node.name == "resolve_first_trust":
            # `from .dnssec.ladder import ... resolve_first_trust` — the alias node
            # carries no lineno on older ASTs; fall back to the enclosing import.
            lines.append(getattr(node, "lineno", func.lineno))
    return lines


def _check_reachability(text: str) -> list[str]:
    """Static reachability: the ladder is reached only behind the flag guard (assert 3).

    Scope-aware (L-2): parse the module and confine the ordering check to the
    ``_dnssec_first_trust_keys`` helper, asserting the flag-guard ``If`` precedes
    EVERY ``resolve_first_trust`` reference inside that function. A robust
    fallback to a string scan is used only when the source cannot be parsed or
    the helper is not present (so the standalone snippet unit tests still apply
    when they wrap the body in the helper)."""
    failures: list[str] = []

    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return [f"origin_identity.py: could not parse for reachability check ({exc})"]

    func = _find_helper(tree)
    if func is None:
        failures.append(
            f"origin_identity.py: missing the `{_HELPER_NAME}` first-trust helper "
            "(reachability check cannot be scoped)"
        )
        return failures

    guard_line = _flag_guard_line(func)
    if guard_line is None:
        failures.append(
            f"{_HELPER_NAME}: missing the flag guard "
            "`if not settings.federation_dnssec_trust_enabled:`"
        )
        return failures  # the ordering check below is meaningless without the guard

    ladder_lines = _resolve_first_trust_lines(func)
    if not ladder_lines:
        failures.append(
            f"{_HELPER_NAME}: expected the helper to reference `resolve_first_trust`"
        )
    elif min(ladder_lines) < guard_line:
        failures.append(
            f"{_HELPER_NAME}: `resolve_first_trust` is referenced BEFORE the "
            "`federation_dnssec_trust_enabled` guard — the ladder may be reachable "
            "with the flag OFF (I11 reachability violation)"
        )
    return failures


_RECHECK_FN = "recheck_relay_binding"


def _recheck_engine_func(recheck_text: str, failures: list[str]) -> ast.FunctionDef | None:
    """The ``recheck_relay_binding`` function node from recheck.py, or None."""
    try:
        tree = ast.parse(recheck_text)
    except SyntaxError as exc:
        failures.append(f"recheck.py: could not parse for the recheck-seam check ({exc})")
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == _RECHECK_FN:
            return node
    failures.append(
        f"recheck.py: missing the `{_RECHECK_FN}` recency/revocation seam (TB-4 / I5)"
    )
    return None


def _engine_audit_string_args(func: ast.FunctionDef) -> set[str]:
    """String-constant FIRST args to ``_audit_relay(...)`` calls inside ``func``."""
    found: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_audit_relay"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.add(node.args[0].value)
    return found


def _engine_raises_typed_reject(func: ast.FunctionDef) -> bool:
    """Whether ``func`` reachably ``raise``s ``RecheckRejected``."""
    for node in ast.walk(func):
        if isinstance(node, ast.Raise) and node.exc is not None:
            callee = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(callee, ast.Name) and callee.id == "RecheckRejected":
                return True
    return False


def _check_recheck_gate(origin_text: str, recheck_text: str) -> list[str]:
    """TB-4 / I5: a TRUSTED verdict is gated by the asymmetric recheck seam (assert 4).

    The recency/revocation re-check is wired before honoring a key, and the seam
    actually IMPLEMENTS the asymmetric rejects (positive revocation hard-reject +
    a typed reject) — not the old always-raise stub. This keeps the "trust a
    DNSSEC pin with no revocation path" window unreachable structurally even
    though the seam now returns (HONOR) on a current binding.

    The recheck.py checks are AST-scoped to the ``recheck_relay_binding`` engine
    (R3 caveat / F-FC-2): the reject audit symbol and the typed raise must appear
    in the FUNCTION BODY (an `_audit_relay(...)` string arg / a real `ast.Raise`),
    never merely as a docstring substring.
    """
    failures: list[str] = []

    if "recheck_relay_binding(" not in origin_text:
        failures.append(
            "origin_identity.py: the DNSSEC first-trust helper must call "
            "`recheck_relay_binding(` before honoring a TRUSTED key (TB-4 / I5)"
        )

    # The typed reject class must be DEFINED (a class def — whole-file is fine).
    if "class RecheckRejected" not in recheck_text:
        failures.append(
            "recheck.py: missing the typed `RecheckRejected` reject (the re-check must raise "
            "a typed error on revoked / rollback / unreachable-past-grace, not return trust)"
        )

    engine = _recheck_engine_func(recheck_text, failures)
    if engine is None:
        return failures

    # The seam must emit the positive-revocation audit as a real `_audit_relay`
    # string arg in its body (not a docstring) — suppression must never masquerade
    # as this positive revocation.
    if "relay_origin_revoked" not in _engine_audit_string_args(engine):
        failures.append(
            "recheck.py: the recency re-check must reject a positive DNSSEC withdrawal and "
            "emit `relay_origin_revoked` as an `_audit_relay(...)` arg in its body "
            "(I5 asymmetric failure) — not only in a docstring (F-FC-2)"
        )

    # The seam must reachably `raise RecheckRejected` so the call site fails closed
    # cleanly on revoked / rollback / aged / unreachable-past-grace.
    if not _engine_raises_typed_reject(engine):
        failures.append(
            "recheck.py: `recheck_relay_binding` must reachably `raise RecheckRejected` in its "
            "body (revoked / rollback / aged / unreachable-past-grace fail closed) — a "
            "docstring mention is not a reject (F-FC-2)"
        )
    return failures


def check() -> int:
    origin_text = _ORIGIN_IDENTITY.read_text(encoding="utf-8")
    recheck_text = _RECHECK.read_text(encoding="utf-8")

    failures: list[str] = []
    failures += _check_runtime()
    failures += _check_reachability(origin_text)
    failures += _check_recheck_gate(origin_text, recheck_text)

    if failures:
        sys.stderr.write("dnssec-trust default-off guard FAILED:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1
    print("dnssec-trust default-off guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
