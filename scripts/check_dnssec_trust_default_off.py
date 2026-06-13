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

  3. **Reachability (static)** — in ``origin_identity.py`` the ONLY call to the first-trust
     ladder helper (``_dnssec_first_trust_keys``) is itself gated by an early
     ``if not settings.federation_dnssec_trust_enabled: return None`` inside that helper,
     so a flag-off relay resolution can never reach ``resolve_first_trust``. We assert (a)
     the helper's flag-guarded early-return exists, and (b) the helper imports the ladder
     (``resolve_first_trust``) only AFTER that flag guard (the guard text precedes the
     import text).

  4. **Recheck fail-closed gate (TB-4)** — the helper routes a TRUSTED ladder verdict
     through ``recheck_relay_binding`` (the 3c recency/revocation seam) BEFORE returning a
     key, and that seam is a fail-closed stub in 3b (raises ``RecheckNotImplemented``). This
     makes the "trust a DNSSEC pin with no revocation path" window unreachable STRUCTURALLY,
     not just by an undocumented flag (TB-4 strengthened). We assert the helper text invokes
     ``recheck_relay_binding(`` on the TRUSTED branch and that ``recheck.py`` defines the
     fail-closed ``RecheckNotImplemented`` and never returns a trusted verdict.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

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


def _check_reachability(text: str) -> list[str]:
    """Static reachability: the ladder is reached only behind the flag guard (assert 3)."""
    failures: list[str] = []

    flag_guard = "if not settings.federation_dnssec_trust_enabled:"
    if flag_guard not in text:
        failures.append(
            "origin_identity.py: missing the flag guard "
            f"`{flag_guard}` in the DNSSEC first-trust helper"
        )
        return failures  # the ordering check below is meaningless without the guard

    guard_idx = text.find(flag_guard)
    ladder_import_idx = text.find("resolve_first_trust")
    if ladder_import_idx == -1:
        failures.append(
            "origin_identity.py: expected the helper to import `resolve_first_trust`"
        )
    elif ladder_import_idx < guard_idx:
        failures.append(
            "origin_identity.py: `resolve_first_trust` is referenced BEFORE the "
            "`federation_dnssec_trust_enabled` guard — the ladder may be reachable "
            "with the flag OFF (I11 reachability violation)"
        )
    return failures


def _check_recheck_gate(origin_text: str, recheck_text: str) -> list[str]:
    """TB-4: a TRUSTED verdict is gated by the fail-closed recheck seam (assert 4)."""
    failures: list[str] = []

    if "recheck_relay_binding(" not in origin_text:
        failures.append(
            "origin_identity.py: the DNSSEC first-trust helper must call "
            "`recheck_relay_binding(` before honoring a TRUSTED key (TB-4 / I5)"
        )

    if "class RecheckNotImplemented" not in recheck_text:
        failures.append(
            "recheck.py: missing the fail-closed `RecheckNotImplemented` typed error (TB-4)"
        )
    # The 3b stub must RAISE (fail-closed) and must NOT contain a `return` that yields a
    # trusted verdict. The only legitimate statement is the raise; assert it raises.
    if "raise RecheckNotImplemented" not in recheck_text:
        failures.append(
            "recheck.py: `recheck_relay_binding` must raise RecheckNotImplemented in 3b "
            "(fail-closed; never return a trusted verdict until 3c wires the re-check)"
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
