#!/usr/bin/env python3
"""CI guard: the federation v2 signed-origin path must verify each fact's origin signature
BEFORE writing it (Phase 2b). Prevents silent regression of origin-signature enforcement on
the push route, the pull client, and the ingest persistence layer.

Static text checks (cheap, no imports of the app):
  1. routes/federation/replication.py    — push v2 enforcement present:
       verify_origin_signature(  AND  resolve_origin_key(  AND  body.get("v") != 2
  2. federation/federation_pull.py        — pull client verifies: verify_origin_signature(
  3. federation/federation_ingest.py      — INSERT column list contains origin_sig
  4. verify-gates-write (F-5): in federation_pull.py, every ingest_fact() CALL is gated by a
     preceding verify_origin_signature(. The encoded invariant is:
       (a) the first verify_origin_signature( occurrence index < the first ingest_fact( CALL
           occurrence index (no ungated ingest), AND
       (b) there is EXACTLY ONE ingest_fact( CALL site (lines containing 'ingest_fact(' that
           are not import/def lines). After the v2 cutover the per-entry loop ingests through a
           single gated call; a re-introduced unconditional loop would add a second call site
           and trip this guard.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent / "node" / "src" / "stigmem_node"
_REPLICATION = _BASE / "routes" / "federation" / "replication.py"
_PULL = _BASE / "federation" / "federation_pull.py"
_INGEST = _BASE / "federation" / "federation_ingest.py"

# After the Phase 2b cutover, federation_pull.py has exactly one ingest_fact() CALL site.
_EXPECTED_INGEST_CALLS = 1


def markers_present(text: str, markers: list[str]) -> bool:
    """True iff every marker substring is present in text."""
    return all(m in text for m in markers)


def _ingest_call_sites(text: str) -> list[str]:
    """Lines that are ingest_fact() CALL sites, excluding import / def lines."""
    sites = []
    for line in text.splitlines():
        stripped = line.strip()
        if "ingest_fact(" not in stripped:
            continue
        if stripped.startswith(("import ", "from ", "def ")) or "ingest_fact," in stripped:
            continue  # import / re-export / def signature — not a call
        sites.append(stripped)
    return sites


def check_verify_gates_write(pull_text: str) -> bool:
    """F-5 invariant on the pull-client text (callable on arbitrary text for testability):
    exactly one ingest_fact() CALL site, and the first verify_origin_signature( precedes the
    first ingest_fact( call."""
    call_sites = _ingest_call_sites(pull_text)
    if len(call_sites) != _EXPECTED_INGEST_CALLS:
        return False
    first_verify = pull_text.find("verify_origin_signature(")
    first_ingest_call = pull_text.find(call_sites[0])
    if first_verify == -1 or first_ingest_call == -1:
        return False
    return first_verify < first_ingest_call


def check() -> int:
    failures: list[str] = []

    rep = _REPLICATION.read_text(encoding="utf-8")
    if not markers_present(
        rep,
        ["verify_origin_signature(", "resolve_origin_key(", 'body.get("v") != 2'],
    ):
        failures.append(
            "replication.py: push v2 enforcement missing — expected verify_origin_signature(, "
            'resolve_origin_key(, and body.get("v") != 2'
        )

    pull = _PULL.read_text(encoding="utf-8")
    if "verify_origin_signature(" not in pull:
        failures.append("federation_pull.py: pull client must call verify_origin_signature(")

    ingest = _INGEST.read_text(encoding="utf-8")
    if "origin_sig" not in ingest:
        failures.append("federation_ingest.py: facts INSERT column list must include origin_sig")

    if not check_verify_gates_write(pull):
        failures.append(
            "federation_pull.py: verify-gates-write (F-5) violated — expected exactly "
            f"{_EXPECTED_INGEST_CALLS} ingest_fact() call site gated by a preceding "
            "verify_origin_signature("
        )

    if failures:
        sys.stderr.write("federation v2 origin-signature guard FAILED:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1
    print("federation v2 origin-signature guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
