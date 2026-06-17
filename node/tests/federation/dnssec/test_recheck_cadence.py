"""Relay-path re-check cadence clamp (Rev 6 I5/§7 — 3c.1).

The re-check cadence is ``clamp(record_DNS_TTL, floor, cap)`` (NF-R5C-5): the
origin's DNS TTL is its own freshness signal, the admin sets the bounds. The
per-origin dedup is anchored on the PERSISTENT pin (``pin.last_validated_at`` +
``_within_cadence``), not an in-memory cache — so the cadence survives restarts.
This module covers the pure ``effective_interval`` clamp; the within-cadence HONOR
(no DNS egress) is exercised end-to-end in ``test_dnssec_recheck.py`` with an
exploding resolver.
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.recheck import effective_interval

_FLOOR = 300
_CAP = 3600


# --- effective_interval clamp ------------------------------------------------


def test_clamp_below_floor_returns_floor() -> None:
    # A short TTL (60s) is clamped UP to the anti-storm floor.
    assert effective_interval(60, floor=_FLOOR, cap=_CAP) == _FLOOR


def test_clamp_within_bounds_returns_ttl() -> None:
    # A TTL inside [floor, cap] is honored as-is (the origin's cadence).
    assert effective_interval(900, floor=_FLOOR, cap=_CAP) == 900


def test_clamp_above_cap_returns_cap() -> None:
    # A long TTL (1 day) is clamped DOWN to the cap.
    assert effective_interval(86400, floor=_FLOOR, cap=_CAP) == _CAP


def test_clamp_at_floor_and_cap_boundaries() -> None:
    assert effective_interval(_FLOOR, floor=_FLOOR, cap=_CAP) == _FLOOR
    assert effective_interval(_CAP, floor=_FLOOR, cap=_CAP) == _CAP


def test_clamp_none_ttl_falls_back_to_floor() -> None:
    # A binding with no TTL (not SECURE-derived) has no freshness signal -> the
    # most conservative cadence, the floor.
    assert effective_interval(None, floor=_FLOOR, cap=_CAP) is _FLOOR


def test_clamp_misconfigured_floor_above_cap_still_floors() -> None:
    # A misconfigured floor > cap must never yield a value below the floor (the
    # anti-storm guarantee). The floor wins.
    assert effective_interval(1000, floor=5000, cap=3600) == 5000
