#!/usr/bin/env python3
"""CI guard: relay egress of inbound facts MUST be gated by federation_relay_enabled AND
enforce the origin scope/tenant intersection (Phase 2c W2.3, W6.6, Rev-2).

Prevents a future refactor from silently letting relayed facts egress without the
propagation-grant check. Static text checks (cheap, no imports of the app):

  1. routes/federation/replication.py  — fact relay-egress clause (W2.3):
       federation_relay_enabled  AND  _allowed_output_tenants(peer  AND
       origin_allowed_scopes LIKE  AND  origin_allowed_tenants LIKE
     All four must be present: the flag gates the widened clause; the tenant
     helper resolves the peer's authorised tenant set; the two LIKE expressions
     pin the scope ∈ origin_allowed_scopes and tenant-overlap SQL checks.

  2. lifecycle/tombstones.py  — tombstone + revocation federation-egress (W6.6, Rev-2):
       list_federatable_tombstones  AND  list_federatable_revocations
       relay_enabled: bool  (the relay gate parameter present on both functions)
       _allowed_output_tenants  AND  origin_allowed_tenants LIKE
     Confirms both federatable-egress functions exist and carry the relay gate +
     tenant-intersection enforcement.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent / "node" / "src" / "stigmem_node"
_REPLICATION = _BASE / "routes" / "federation" / "replication.py"
_TOMBSTONES = _BASE / "lifecycle" / "tombstones.py"

# ---------------------------------------------------------------------------
# Shared helper (mirrors check_federation_v2_origin.py)
# ---------------------------------------------------------------------------


def markers_present(text: str, markers: list[str]) -> bool:
    """True iff every marker substring is present in text."""
    return all(m in text for m in markers)


# ---------------------------------------------------------------------------
# Per-file invariant checks (self-testable — accept arbitrary text)
# ---------------------------------------------------------------------------


def check_replication_relay_markers(text: str) -> bool:
    """Replication egress relay-gate invariant (W2.3) on arbitrary text.

    Four stable markers must all be present:
    1. ``federation_relay_enabled``  — the runtime flag that gates the widened clause.
    2. ``_allowed_output_tenants(peer``  — the peer tenant-set resolver call.
    3. ``origin_allowed_scopes LIKE``  — the scope ∈ origin grant SQL check.
    4. ``origin_allowed_tenants LIKE``  — the tenant-overlap SQL check.

    Callable on stripped/fake text for the teeth tests.
    """
    return markers_present(
        text,
        [
            "federation_relay_enabled",
            "_allowed_output_tenants(peer",
            "origin_allowed_scopes LIKE",
            "origin_allowed_tenants LIKE",
        ],
    )


def check_tombstones_relay_markers(text: str) -> bool:
    """Tombstone + revocation federatable-egress relay-gate invariant (W6.6, Rev-2).

    Five stable markers must all be present:
    1. ``list_federatable_tombstones``  — the tombstone federation-egress function.
    2. ``list_federatable_revocations``  — the revocation federation-egress function.
    3. ``relay_enabled: bool``           — the relay-gate parameter on both functions.
    4. ``_allowed_output_tenants``       — the peer tenant-set resolver import/call.
    5. ``origin_allowed_tenants LIKE``   — the tenant-overlap SQL check.

    Callable on stripped/fake text for the teeth tests.
    """
    return markers_present(
        text,
        [
            "list_federatable_tombstones",
            "list_federatable_revocations",
            "relay_enabled: bool",
            "_allowed_output_tenants",
            "origin_allowed_tenants LIKE",
        ],
    )


# ---------------------------------------------------------------------------
# Top-level check
# ---------------------------------------------------------------------------


def check() -> int:
    failures: list[str] = []

    rep = _REPLICATION.read_text(encoding="utf-8")
    if not check_replication_relay_markers(rep):
        missing = [
            m
            for m in [
                "federation_relay_enabled",
                "_allowed_output_tenants(peer",
                "origin_allowed_scopes LIKE",
                "origin_allowed_tenants LIKE",
            ]
            if m not in rep
        ]
        failures.append(
            "replication.py: relay-egress gate missing marker(s): "
            + ", ".join(repr(m) for m in missing)
        )

    tomb = _TOMBSTONES.read_text(encoding="utf-8")
    if not check_tombstones_relay_markers(tomb):
        missing = [
            m
            for m in [
                "list_federatable_tombstones",
                "list_federatable_revocations",
                "relay_enabled: bool",
                "_allowed_output_tenants",
                "origin_allowed_tenants LIKE",
            ]
            if m not in tomb
        ]
        failures.append(
            "tombstones.py: tombstone/revocation relay-egress gate missing marker(s): "
            + ", ".join(repr(m) for m in missing)
        )

    if failures:
        sys.stderr.write("federation relay-egress guard FAILED:\n")
        for f in failures:
            sys.stderr.write(f"  - {f}\n")
        return 1
    print("federation relay-egress guard: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
