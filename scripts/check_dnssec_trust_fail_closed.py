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

_RESOLVE = _BASE / "federation" / "dnssec" / "resolve.py"
_RECHECK_FN = "recheck_relay_binding"
_REJECT_HELPER_FN = "_suppression_disposition"

# Names that constitute a fail-closed disposition (reject / quarantine / pending /
# typed-raise). A non-ACTIVE outcome branch MUST land on one of these and NEVER on
# ``_trusted(``.
_REJECT_CALL_NAMES = frozenset(
    {
        "_rejected",
        "_pending",
        "_quarantine_or_fail_closed",
        "_suppression_disposition",
    }
)
_TRUST_CALL_NAME = "_trusted"


def _outcome_member_names(resolve_text: str, failures: list[str]) -> set[str]:
    """Statically enumerate ``DnssecResult.Outcome`` member names from resolve.py.

    Parses the enum (no import, no dnspython dependency) so a renamed/added
    outcome is reflected automatically — the per-branch reject-lattice check then
    covers it, rather than silently skipping it because the spelling drifted.
    """
    try:
        tree = ast.parse(resolve_text)
    except SyntaxError as exc:
        failures.append(f"resolve.py: could not parse the Outcome enum ({exc})")
        return set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "Outcome":
            for stmt in node.body:
                # ``ACTIVE = "active"`` -> an enum member assignment.
                if isinstance(stmt, ast.Assign):
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            names.add(tgt.id)
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    names.add(stmt.target.id)
    if not names:
        failures.append(
            "resolve.py: could not enumerate `DnssecResult.Outcome` members "
            "(the per-branch reject-lattice check cannot be built)"
        )
    return names


def _outcome_member_in_node(node: ast.AST) -> str | None:
    """If ``node`` is a ``DnssecResult.Outcome.<NAME>`` attribute, return ``<NAME>``."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "Outcome"
    ):
        return node.attr
    return None


def _positively_asserted_outcomes(test: ast.expr) -> set[str]:
    """Outcome member names the ``If`` test positively asserts ``outcome`` equals.

    Recognizes the equality/membership shapes used in the ladder + recheck engine:

      * ``outcome is DnssecResult.Outcome.X``  / ``== X``   -> {X}
      * ``outcome in (DnssecResult.Outcome.X, ...Y)``        -> {X, Y}

    ``is not`` / ``not in`` (e.g. the defensive ``outcome is not ...ACTIVE``) are
    NOT positive assertions and yield ``set()`` — the body there is a catch-all
    reject, not a "this is outcome X" branch, so it is not enforced as one.
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return set()
    op = test.ops[0]
    comparator = test.comparators[0]
    if isinstance(op, (ast.Is, ast.Eq)):
        name = _outcome_member_in_node(comparator)
        return {name} if name else set()
    if isinstance(op, ast.In) and isinstance(comparator, (ast.Tuple, ast.List, ast.Set)):
        found = {
            n
            for elt in comparator.elts
            if (n := _outcome_member_in_node(elt)) is not None
        }
        return found
    return set()


def _body_calls(body: list[ast.stmt]) -> set[str]:
    """The set of bare-``Name`` call targets reachable in ``body`` (e.g. ``_trusted``).

    Walks the branch body (including nested ``If``/loops) so a ``_trusted(...)``
    buried in a nested block is still seen.
    """
    calls: set[str] = set()
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                calls.add(sub.func.id)
    return calls


def _body_raises_recheck_rejected(body: list[ast.stmt]) -> bool:
    """Whether ``body`` reachably ``raise``s ``RecheckRejected`` (the recheck reject)."""
    for stmt in body:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Raise) and sub.exc is not None:
                exc = sub.exc
                callee = exc.func if isinstance(exc, ast.Call) else exc
                if isinstance(callee, ast.Name) and callee.id == _TYPED_REJECT:
                    return True
    return False


def _check_reject_lattice_per_branch(
    func: ast.FunctionDef,
    *,
    non_active: set[str],
    fn_label: str,
    allow_typed_raise: bool,
) -> list[str]:
    """Per-branch reject-lattice (F-FC-1): every NON-ACTIVE outcome branch rejects.

    For each ``If`` whose test positively asserts ``outcome``/``result.outcome``
    equals a non-ACTIVE ``DnssecResult.Outcome`` member, assert the branch body
    lands on a reject/quarantine/fail-closed disposition (one of
    ``_REJECT_CALL_NAMES``, or — when ``allow_typed_raise`` — a ``raise
    RecheckRejected``) and NEVER on ``_trusted(``. This is the load-bearing fix:
    the old check only verified ``_rejected(`` appeared SOMEWHERE in the function,
    so a single mis-mapped branch (``REVOKED -> _trusted``) passed as long as any
    other branch rejected.
    """
    failures: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        asserted = _positively_asserted_outcomes(node.test)
        bad = asserted & non_active
        if not bad:
            continue
        calls = _body_calls(node.body)
        if _TRUST_CALL_NAME in calls:
            failures.append(
                f"{fn_label}: the branch for non-ACTIVE outcome(s) {sorted(bad)} calls "
                f"`{_TRUST_CALL_NAME}(` — a non-ACTIVE outcome must NEVER be trusted "
                "(I10 lattice, F-FC-1)"
            )
            continue
        rejects = bool(calls & _REJECT_CALL_NAMES)
        if allow_typed_raise and _body_raises_recheck_rejected(node.body):
            rejects = True
        if not rejects:
            failures.append(
                f"{fn_label}: the branch for non-ACTIVE outcome(s) {sorted(bad)} does not "
                "reject/quarantine/fail-closed (no "
                f"{sorted(_REJECT_CALL_NAMES)}"
                f"{' / raise ' + _TYPED_REJECT if allow_typed_raise else ''} call) — "
                "every non-ACTIVE outcome must fail closed (I10, F-FC-1)"
            )
    return failures


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


def _check_ladder(text: str, *, non_active: set[str]) -> list[str]:
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

    # (e) I10 — PER-BRANCH reject lattice (F-FC-1). Every `If` that positively
    # asserts ``outcome`` equals a NON-ACTIVE ``DnssecResult.Outcome`` member must
    # reject/quarantine/fail-closed in its body and NEVER call `_trusted(`. The
    # non-ACTIVE set is enumerated from the live enum, so a renamed/added outcome
    # mapped to `_trusted` is caught (not silently skipped). This replaces the old
    # whole-function check (which passed if ANY branch rejected, missing a single
    # mis-mapped branch like ``REVOKED -> _trusted``).
    failures += _check_reject_lattice_per_branch(
        func, non_active=non_active, fn_label=_LADDER_FN, allow_typed_raise=False
    )
    return failures


def _audit_relay_string_args(func: ast.FunctionDef) -> set[str]:
    """String-constant FIRST args to ``_audit_relay(...)`` calls inside ``func``.

    Scopes the reject-audit-symbol check to ACTUAL call args (F-FC-2), so a symbol
    that appears only in a docstring/comment is NOT counted as wired.
    """
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


def _check_recheck(text: str, *, non_active: set[str]) -> list[str]:
    """B: the recency re-check is the asymmetric, typed-reject engine (I5/I10).

    F-FC-2: the reject-audit symbols and the typed raise are asserted against the
    AST of ``recheck_relay_binding`` (+ the suppression reject helper), not a
    whole-file substring — so a docstring-only stub that never reaches a real
    ``raise RecheckRejected`` is caught.

    F-FC-1: the engine's per-branch reject lattice is asserted too — any branch
    that positively tests a non-ACTIVE outcome (e.g. ``REVOKED``) must raise the
    typed reject (or call a fail-closed helper), never honor.
    """
    failures: list[str] = []

    # The typed reject class must be DEFINED (whole-file is fine: a class def).
    if f"class {_TYPED_REJECT}" not in text:
        failures.append(
            f"recheck.py: missing the typed `{_TYPED_REJECT}` reject (the re-check must raise "
            "a typed error on its reject branches, not return trust)"
        )

    engine = _parse_func(text, _RECHECK_FN, "recheck.py", failures)
    if engine is None:
        return failures

    helper_tree = ast.parse(text)
    reject_helper = _find_func(helper_tree, _REJECT_HELPER_FN)

    # F-FC-2: a real `raise RecheckRejected` must be reachable in the engine body
    # (not merely present in the module / a docstring).
    if not _body_raises_recheck_rejected(engine.body):
        failures.append(
            f"recheck.py: `{_RECHECK_FN}` must reachably `raise {_TYPED_REJECT}` in its body "
            "(revoked / rollback / aged / unreachable-past-grace fail closed) — a docstring "
            "mention is not a reject (F-FC-2)"
        )

    # F-FC-2: the reject audit symbols must appear as string-constant ARGS to
    # `_audit_relay(...)` in the engine OR the suppression reject helper — never
    # only in a docstring.
    audit_args = _audit_relay_string_args(engine)
    if reject_helper is not None:
        audit_args |= _audit_relay_string_args(reject_helper)
    for audit in _RECHECK_REJECT_AUDITS:
        if audit not in audit_args:
            failures.append(
                f"recheck.py: the recency re-check must emit `{audit}` as an `_audit_relay(...)` "
                "arg on its reject path (asymmetric fail-closed: revoked / rollback / "
                "unreachable -> reject, I5) — not only in a docstring (F-FC-2)"
            )

    # F-FC-1: per-branch lattice on the engine — a non-ACTIVE outcome branch must
    # fail closed (raise the typed reject or call a fail-closed helper), never honor.
    failures += _check_reject_lattice_per_branch(
        engine, non_active=non_active, fn_label=_RECHECK_FN, allow_typed_raise=True
    )
    return failures


def _honor_point_call_nodes(func: ast.FunctionDef) -> list[ast.Call]:
    """Every ``_keys_from_manifest(...)`` call inside ``func`` (a key-honor point)."""
    return [
        node
        for node in ast.walk(func)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_keys_from_manifest"
    ]


def _unconditional_call_names(stmt: ast.stmt) -> set[str]:
    """Bare-``Name`` call targets that ALWAYS execute when ``stmt`` runs.

    Recurses into unconditional sub-blocks but NOT into conditional ones: an ``If``
    / ``For`` / ``While`` body may be skipped, and a ``Try``'s ``handlers``/``orelse``
    run only on the exception/no-exception path. The ``Try`` ``body`` + ``finalbody``
    and a ``With`` body always run. This means a recheck buried inside a SIBLING
    ``if`` branch is NOT counted as dominating a later key derivation (F-FC-3), while
    a recheck inside a ``try:`` body (the live shape — it raises to fail closed) IS.
    """
    names: set[str] = set()

    def _add_call(node: ast.AST) -> None:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)

    def _visit(node: ast.AST) -> None:
        _add_call(node)
        if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor)):
            return  # conditional / looping -> body not guaranteed
        if isinstance(node, ast.Try):
            for child in node.body + node.finalbody:  # always-run portions only
                _visit(child)
            return
        for child in ast.iter_child_nodes(node):
            _visit(child)

    _visit(stmt)
    return names


def _guaranteed_before_call_names(func: ast.FunctionDef, target: ast.Call) -> set[str]:
    """Bare-``Name`` call targets GUARANTEED to execute before ``target`` on its path.

    Builds a child->parent map, locates the statement enclosing ``target``, then
    ascends: at each enclosing statement block it collects the UNCONDITIONAL calls
    in the EARLIER SIBLING statements (calls not buried inside a nested conditional,
    which would not always run). A ``recheck_relay_binding`` in this set dominates
    ``target``; a key-derivation branch whose only recheck lives in a SIBLING branch
    therefore yields a set WITHOUT it (so a second key-return branch lacking its own
    recheck is caught — F-FC-3).
    """
    parent: dict[int, ast.AST] = {}
    for node in ast.walk(func):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node

    # Climb from the target expression to the enclosing statement, then up the tree.
    cur: ast.AST = target
    names: set[str] = set()
    while id(cur) in parent:
        par = parent[id(cur)]
        # If `par` is a node holding statement bodies, gather earlier-sibling calls.
        for field in ("body", "orelse", "finalbody"):
            block = getattr(par, field, None)
            if isinstance(block, list) and cur in block:
                idx = block.index(cur)
                for stmt in block[:idx]:
                    names |= _unconditional_call_names(stmt)
        cur = par
    return names


def _check_trusted_gate(text: str) -> list[str]:
    """C: a TRUSTED ladder verdict never honors a key without the re-check (I5).

    F-FC-3: per-branch domination. EVERY ``_keys_from_manifest(...)`` key-honor
    point must be dominated by a ``recheck_relay_binding(...)`` call on its OWN
    path (a recheck guaranteed to run before it). The old global
    ``min(recheck) > min(key)`` ordering passed if ANY recheck preceded the FIRST
    key derivation — a SECOND key-return branch with no recheck slipped through.
    """
    failures: list[str] = []
    func = _parse_func(text, _TRUST_HELPER, "origin_identity.py", failures)
    if func is None:
        return failures

    if _RECHECK_CALL not in (ast.get_source_segment(text, func) or ""):
        failures.append(
            f"{_TRUST_HELPER}: a TRUSTED DNSSEC verdict must call `{_RECHECK_CALL}` before "
            "honoring a key (no recency/revocation path otherwise — I5)"
        )
        return failures

    honor_points = _honor_point_call_nodes(func)
    if not honor_points:
        failures.append(
            f"{_TRUST_HELPER}: expected a `_keys_from_manifest(` key-derivation call "
            "(the honor point the re-check must dominate — I5)"
        )
        return failures

    for honor_point in honor_points:
        before = _guaranteed_before_call_names(func, honor_point)
        if "recheck_relay_binding" not in before:
            failures.append(
                f"{_TRUST_HELPER}: a `_keys_from_manifest(` key-honor point (line "
                f"{getattr(honor_point, 'lineno', '?')}) is not dominated by a "
                "`recheck_relay_binding(` call on its path — the recency re-check must run "
                "BEFORE the key is honored on EVERY branch (else a stale/revoked key is "
                "returned before the check can reject — I5, F-FC-3)"
            )
    return failures


def check() -> int:
    ladder_text = _LADDER.read_text(encoding="utf-8")
    recheck_text = _RECHECK.read_text(encoding="utf-8")
    origin_text = _ORIGIN_IDENTITY.read_text(encoding="utf-8")
    resolve_text = _RESOLVE.read_text(encoding="utf-8")

    failures: list[str] = []
    outcome_names = _outcome_member_names(resolve_text, failures)
    non_active = outcome_names - {"ACTIVE"}
    failures += _check_ladder(ladder_text, non_active=non_active)
    failures += _check_recheck(recheck_text, non_active=non_active)
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
