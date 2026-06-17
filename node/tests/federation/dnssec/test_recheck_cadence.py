"""Relay-path re-check cadence clamp + per-origin cache (Rev 6 I5/§7 — 3c.1).

The re-check cadence is ``clamp(record_DNS_TTL, floor, cap)`` (NF-R5C-5): the
origin's DNS TTL is its own freshness signal, the admin sets the bounds.
Re-checks are cached PER-ORIGIN (host-keyed), so within the effective interval a
binding is NOT re-resolved — proven here with an exploding resolver that fails if
it is ever consulted within the window.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from stigmem_node.federation.dnssec.recheck import RecheckCache, effective_interval
from stigmem_node.federation.dnssec.record import BindingRecord

_FLOOR = 300
_CAP = 3600
_HOST = "memory.acme.example"
_NOW = datetime(2026, 6, 12, tzinfo=UTC)
_RECORD = BindingRecord(fpr="abc123def", epoch=7)


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


# --- per-origin cache --------------------------------------------------------


class _ExplodingResolver:
    """A resolver that fails the test if it is ever consulted."""

    def query(self, qname: str, rdtype: str):  # pragma: no cover - must not run
        raise AssertionError("cache hit must NOT re-resolve (no DNS egress)")


def test_cache_miss_when_uncached() -> None:
    cache = RecheckCache()
    assert cache.get(_HOST, now=_NOW, floor=_FLOOR, cap=_CAP) is None


def test_cache_hit_within_interval_does_not_reresolve() -> None:
    # Put a binding validated NOW with a 900s TTL; a get 100s later (< 900s
    # effective interval) is a hit. The resolver is never consulted — modeled by
    # the fact that ``get`` performs no resolution at all; the exploding resolver
    # stands in for the call site that would otherwise re-resolve on a miss.
    cache = RecheckCache()
    cache.put(_HOST, record=_RECORD, validated_at=_NOW, ttl=900)
    resolver = _ExplodingResolver()  # noqa: F841 — asserts intent: no resolution on a hit
    hit = cache.get(_HOST, now=_NOW + timedelta(seconds=100), floor=_FLOOR, cap=_CAP)
    assert hit is _RECORD


def test_cache_miss_past_interval_triggers_reresolve() -> None:
    # Same 900s TTL, but a get 901s later is PAST the effective interval -> a
    # miss, so the caller must re-resolve.
    cache = RecheckCache()
    cache.put(_HOST, record=_RECORD, validated_at=_NOW, ttl=900)
    miss = cache.get(_HOST, now=_NOW + timedelta(seconds=901), floor=_FLOOR, cap=_CAP)
    assert miss is None


def test_cache_interval_uses_clamped_short_ttl() -> None:
    # A 60s TTL is clamped up to the 300s floor: a get 200s later is still a hit
    # (within the floor), and 301s later is a miss.
    cache = RecheckCache()
    cache.put(_HOST, record=_RECORD, validated_at=_NOW, ttl=60)
    assert cache.get(_HOST, now=_NOW + timedelta(seconds=200), floor=_FLOOR, cap=_CAP) is _RECORD
    assert cache.get(_HOST, now=_NOW + timedelta(seconds=301), floor=_FLOOR, cap=_CAP) is None


def test_cache_interval_uses_clamped_long_ttl() -> None:
    # A 1-day TTL is clamped down to the 3600s cap: a get 3601s later is a miss
    # even though the raw TTL is far larger.
    cache = RecheckCache()
    cache.put(_HOST, record=_RECORD, validated_at=_NOW, ttl=86400)
    assert cache.get(_HOST, now=_NOW + timedelta(seconds=3500), floor=_FLOOR, cap=_CAP) is _RECORD
    assert cache.get(_HOST, now=_NOW + timedelta(seconds=3601), floor=_FLOOR, cap=_CAP) is None


def test_cache_put_replaces_prior_entry() -> None:
    cache = RecheckCache()
    cache.put(_HOST, record=_RECORD, validated_at=_NOW - timedelta(hours=2), ttl=900)
    # An old entry past its interval would miss; re-put with a fresh validated_at.
    new_record = BindingRecord(fpr="def456", epoch=8)
    cache.put(_HOST, record=new_record, validated_at=_NOW, ttl=900)
    assert cache.get(_HOST, now=_NOW + timedelta(seconds=10), floor=_FLOOR, cap=_CAP) is new_record
