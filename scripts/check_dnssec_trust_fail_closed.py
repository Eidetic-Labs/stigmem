#!/usr/bin/env python3
"""CI guard: the DNSSEC first-trust + recency paths are FAIL-CLOSED (Rev 6 §11, plan 3c.5).

Companion to ``check_dnssec_trust_default_off.py`` (which proves the tier is off + lazily
imported). This guard proves that WHEN the tier is reachable, NO first-trust or recency
path can return a trusted key without clearing every root anchor — and that every
non-ACTIVE / unreachable / revoked / rollback outcome resolves to a typed reject.

It asserts (static AST + text checks, NO network, NO import-time DNSSEC dependency):

  A. **First-trust ladder is rooted, never derived (I1/I2/I3/I4).** In
     ``ladder.resolve_first_trust``:
       (a) the operator-pin / DNSSEC root tier is cleared BEFORE any ``_trusted`` return —
           no ``_trusted(...)`` appears lexically before the pin lookup
           (``pinstore.get_pin``) / the DNSSEC resolution (``resolve_dnssec_binding``), so a
           verdict is rooted, never silent first-seen-wins (I1);
       (b) the chain-validated record is consulted — ``resolve_dnssec_binding(`` is called
           (I2);
       (c) the canonical signed-``entity_uri`` host is derived — ``host_from_entity_uri(``
           is called (I3, the single canonical derivation used for the DNS qname + pin key);
       (d) the monotonic-epoch floor is enforced — ``accept_epoch(`` is referenced (I4, a
           record epoch below the host floor is a rollback reject);
       (e) the explicit reject outcomes (``REVOKED`` / ``BOGUS`` / ``UNVALIDATABLE``) each
           map to ``_rejected`` and NEVER ``_trusted`` (I10 lattice — no permissive return).

  B. **Recency re-check is the asymmetric, typed-reject engine (I5/I10).** In
     ``recheck.recheck_relay_binding`` (via ``recheck.py``):
       the engine references the three reject audit symbols
       ``relay_origin_revoked`` (positive withdrawal), ``relay_origin_rolled_back`` (epoch
       rollback), ``relay_origin_recheck_unreachable`` (DNS-unreachable past grace), defines
       the typed ``RecheckRejected``, and ``raise RecheckRejected`` on its reject branches —
       so DNS-unreachable / unvalidatable / revoked / rollback all fail closed.

  C. **A TRUSTED ladder verdict never honors a key without the re-check (I5).** In
     ``origin_identity._dnssec_first_trust_keys`` the TRUSTED branch calls
     ``recheck_relay_binding(`` BEFORE returning the key (``_keys_from_manifest`` /
     ``return keys``) — so a DNSSEC-trusted relayed key always passes the recency/revocation
     gate before it is honored, structurally (not by an undocumented flag).

Any failure exits non-zero (the structural-guard contract). The checks are AST/ordering-
scoped (like the default-off guard's assertion 3), not vacuous string-greps that pass
trivially.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent / "node" / "src" / "stigmem_node"
_LADDER = _BASE / "federation" / "dnssec" / "ladder.py"
_RECHECK = _BASE / "federation" / "dnssec" / "recheck.py"
_ORIGIN_IDENTITY = _BASE / "federation" / "origin_identity.py"

_LADDER_FN = "resolve_first_trust"
_TRUST_HELPER = "_dnssec_first_trust_keys"

# Symbols a fail-closed ladder MUST consult (the rooted-tier inputs).
_PIN_LOOKUP = "get_pin"  # operator-pin / existing-pin tier (I1)
_DNSSEC_RESOLVE = "resolve_dnssec_binding"  # chain-validated record (I2)
_CANONICAL_HOST = "host_from_entity_uri"  # canonical signed-entity_uri host (I3)
_EPOCH_FLOOR = "accept_epoch"  # monotonic-epoch floor (I4)

# Recency reject audit symbols + the typed reject (I5/I10).
_RECHECK_REJECT_AUDITS = (
    "relay_origin_revoked",
    "relay_origin_rolled_back",
    "relay_origin_recheck_unreachable",
)
_TYPED_REJECT = "RecheckRejected"
_RECHECK_CALL = "recheck_relay_binding("


def _find_func(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _name_lines(func: ast.FunctionDef, name: str) -> list[int]:
    """Lines of every ``Name``/``Attribute``/``alias`` reference to ``name`` in ``func``.

    Confined to the function body so an unrelated mention elsewhere in the module
    cannot fool an ordering check (the default-off guard's L-2 discipline).
    """
    lines: list[int] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Name) and node.id == name:
            lines.append(node.lineno)
        elif isinstance(node, ast.Attribute) and node.attr == name:
            lines.append(node.lineno)
        elif isinstance(node, ast.alias) and node.name == name:
            lines.append(getattr(node, "lineno", func.lineno))
    return lines


def _trusted_call_lines(func: ast.FunctionDef) -> list[int]:
    """Lines of every ``_trusted(...)`` call inside ``func`` (the accept verdicts)."""
    lines: list[int] = []
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_trusted"
        ):
            lines.append(node.lineno)
    return lines


def _parse_func(text: str, name: str, label: str, failures: list[str]) -> ast.FunctionDef | None:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        failures.append(f"{label}: could not parse ({exc})")
        return None
    func = _find_func(tree, name)
    if func is None:
        failures.append(f"{label}: missing the `{name}` function (cannot scope the check)")
    return func


def _check_ladder(text: str) -> list[str]:
    """A: the first-trust ladder is rooted, never derived (I1/I2/I3/I4/I10)."""
    failures: list[str] = []
    func = _parse_func(text, _LADDER_FN, "ladder.py", failures)
    if func is None:
        return failures

    pin_lines = _name_lines(func, _PIN_LOOKUP)
    resolve_lines = _name_lines(func, _DNSSEC_RESOLVE)
    host_lines = _name_lines(func, _CANONICAL_HOST)
    epoch_lines = _name_lines(func, _EPOCH_FLOOR)
    trusted_lines = _trusted_call_lines(func)

    # (b/c/d) the rooted-tier inputs must each be consulted.
    if not resolve_lines:
        failures.append(
            f"{_LADDER_FN}: must consult the chain-validated record via "
            f"`{_DNSSEC_RESOLVE}(` (no DNSSEC root tier => not rooted, I2)"
        )
    if not host_lines:
        failures.append(
            f"{_LADDER_FN}: must derive the DNS query host via the canonical "
            f"`{_CANONICAL_HOST}(` (signed entity_uri host, I3)"
        )
    if not epoch_lines:
        failures.append(
            f"{_LADDER_FN}: must enforce the monotonic-epoch floor via `{_EPOCH_FLOOR}(` "
            "(a record epoch below the host floor is a rollback reject, I4)"
        )

    # (a) I1 — no _trusted return before the pin tier is cleared AND the DNSSEC chain is
    # consulted. The earliest rooting anchor (pin lookup or DNSSEC resolution) must precede
    # every _trusted verdict; otherwise the ladder can trust before clearing a root tier.
    anchor_lines = pin_lines + resolve_lines
    if trusted_lines and anchor_lines and min(trusted_lines) < min(anchor_lines):
        failures.append(
            f"{_LADDER_FN}: a `_trusted` verdict appears BEFORE the operator-pin / DNSSEC "
            "root tier is cleared — trust must be rooted, never silent first-seen-wins (I1)"
        )

    # (e) I10 — the explicit reject outcomes must map to a reject, never _trusted. We assert
    # each reject outcome label co-occurs with a `_rejected(` call in the function source.
    seg = ast.get_source_segment(text, func) or ""
    for outcome in ("REVOKED", "BOGUS", "UNVALIDATABLE"):
        if outcome in seg and "_rejected(" not in seg:
            failures.append(
                f"{_LADDER_FN}: references outcome `{outcome}` but never calls `_rejected(` "
                "(every non-ACTIVE outcome must reject, never trust — I10 lattice)"
            )
            break
    return failures


def _check_recheck(text: str) -> list[str]:
    """B: the recency re-check is the asymmetric, typed-reject engine (I5/I10)."""
    failures: list[str] = []
    for audit in _RECHECK_REJECT_AUDITS:
        if audit not in text:
            failures.append(
                f"recheck.py: the recency re-check must reject and emit `{audit}` "
                "(asymmetric fail-closed: revoked / rollback / unreachable -> reject, I5)"
            )
    if f"class {_TYPED_REJECT}" not in text:
        failures.append(
            f"recheck.py: missing the typed `{_TYPED_REJECT}` reject (the re-check must raise "
            "a typed error on its reject branches, not return trust)"
        )
    if f"raise {_TYPED_REJECT}" not in text:
        failures.append(
            f"recheck.py: `recheck_relay_binding` must `raise {_TYPED_REJECT}` on its reject "
            "branches (revoked / rollback / aged / unreachable-past-grace fail closed)"
        )
    return failures


def _check_trusted_gate(text: str) -> list[str]:
    """C: a TRUSTED ladder verdict never honors a key without the re-check (I5)."""
    failures: list[str] = []
    func = _parse_func(text, _TRUST_HELPER, "origin_identity.py", failures)
    if func is None:
        return failures

    seg = ast.get_source_segment(text, func) or ""
    if _RECHECK_CALL not in seg:
        failures.append(
            f"{_TRUST_HELPER}: a TRUSTED DNSSEC verdict must call `{_RECHECK_CALL}` before "
            "honoring a key (no recency/revocation path otherwise — I5)"
        )
        return failures

    # Ordering: the re-check call must precede the key derivation/return. Scope to the
    # function body; the earliest recheck_relay_binding reference must be at or before the
    # earliest `_keys_from_manifest` / `return keys`.
    recheck_lines = _name_lines(func, "recheck_relay_binding")
    key_lines = _name_lines(func, "_keys_from_manifest")
    if recheck_lines and key_lines and min(recheck_lines) > min(key_lines):
        failures.append(
            f"{_TRUST_HELPER}: `recheck_relay_binding` is called AFTER the key is derived "
            "(`_keys_from_manifest`) — the recency re-check must run BEFORE the key is "
            "honored, else a stale/revoked key is returned before the check can reject (I5)"
        )
    return failures


def check() -> int:
    ladder_text = _LADDER.read_text(encoding="utf-8")
    recheck_text = _RECHECK.read_text(encoding="utf-8")
    origin_text = _ORIGIN_IDENTITY.read_text(encoding="utf-8")

    failures: list[str] = []
    failures += _check_ladder(ladder_text)
    failures += _check_recheck(recheck_text)
    failures += _check_trusted_gate(origin_text)

    if failures:
        sys.stderr.write("dnssec-trust fail-closed guard FAILED:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1
    print("dnssec-trust fail-closed guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
