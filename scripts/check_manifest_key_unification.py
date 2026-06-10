#!/usr/bin/env python3
"""CI guard: PUT /v1/federation/manifest must reject a manifest whose public_key != the node's
federation key (Phase 2a unification). Prevents silent regression of the laundering precondition fix."""
from __future__ import annotations

import sys
from pathlib import Path

_ROUTE = (
    Path(__file__).resolve().parent.parent
    / "node" / "src" / "stigmem_node" / "routes" / "identity.py"
)


def check() -> int:
    text = _ROUTE.read_text(encoding="utf-8")
    if "get_local_pubkey()" in text and "manifest.public_key != get_local_pubkey()" in text:
        print("manifest key-unification guard: OK")
        return 0
    sys.stderr.write(
        "manifest key-unification guard FAILED — put_manifest must reject "
        "manifest.public_key != get_local_pubkey() (Phase 2a)\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(check())
