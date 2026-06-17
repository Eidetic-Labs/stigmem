"""Relay-path DNSSEC recency/revocation re-check (Rev 6 I5 / build-phase 3c).

Rev 6 I5: a relayed fact's origin key is honored only if a DNSSEC re-check
within the effective interval confirms the binding. The cadence (this module,
3c.1) is ``clamp(record_DNS_TTL, floor, cap)`` — the origin's DNS TTL is its own
freshness signal, the admin sets the bounds — and re-checks are cached
PER-ORIGIN, not per-fact (NF-R5C-5). The asymmetric failure semantics (3c.2)
ride on top of that cadence.

This module owns two pieces:

  * ``effective_interval(ttl, floor, cap)`` — the clamp. A ``None`` TTL (a
    non-SECURE binding has no TTL to clamp) falls back to the floor.
  * ``RecheckCache`` — a per-origin (host-keyed) cache of the last validated
    binding so that, within the effective interval, the binding is NOT
    re-resolved (no DNS egress, no resolver consulted).

The real ``recheck_relay_binding`` body (the asymmetric recency/revocation
engine) lands in 3c.2; until then this stub fails closed (raises
``RecheckNotImplemented``) so the relay wiring honors no DNSSEC pin without a
revocation path (plan TB-4).

No DNSSEC / ``dnspython`` import is reachable from this module (Rev 6 I11): the
clamp + cache are pure arithmetic over already-validated state, and the 3c.2
implementation imports dnspython only through the injected ``resolver`` /
``resolve_dnssec_binding`` (which import it function-locally).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # type-checkers only; never imported at runtime (I11).
    from .record import BindingRecord


class RecheckNotImplemented(Exception):
    """The relay-path DNSSEC recency/revocation re-check (Rev 6 I5) is not wired.

    Retained as the 3c.1 transitional fail-closed marker: the cadence clamp +
    cache land here first, but ``recheck_relay_binding`` still raises this until
    3c.2 fills in the asymmetric re-check. The relay wiring catches it and fails
    closed, so a pinned DNSSEC binding is never honored on a relay without the
    real re-check.
    """


def effective_interval(ttl: int | None, *, floor: int, cap: int) -> int:
    """The relay-path re-check cadence ``clamp(ttl, floor, cap)`` (Rev 6 §7/I5).

    The origin's DNS TTL drives the cadence; the admin-set ``floor`` (anti-storm)
    and ``cap`` (DNS-load bound) clamp it. A ``None`` TTL (a binding that did not
    resolve SECURE, so it carries no TTL) has no freshness signal to honor and
    falls back to the ``floor`` — the most conservative cadence. ``floor`` is
    applied after ``cap`` so a (mis)configured ``floor > cap`` still yields the
    floor (never a value below it), keeping the anti-storm guarantee.
    """
    if ttl is None:
        return floor
    return max(floor, min(ttl, cap))


@dataclass
class _CacheEntry:
    """One per-origin cached re-check: the validated binding + when + its TTL."""

    record: BindingRecord
    validated_at: datetime
    ttl: int | None


class RecheckCache:
    """Per-origin (host-keyed) cache of the last validated relay-path re-check.

    Within ``effective_interval(ttl, floor, cap)`` of an origin's last validated
    re-check, the binding is served from this cache and the resolver is NOT
    consulted (NF-R5C-5: re-checks are per-origin, not per-fact — a page of
    relayed facts from one origin triggers at most one DNS re-resolution per
    cadence window). Past the interval, ``get`` returns ``None`` and the caller
    re-resolves.

    Keyed by the canonical host (Rev 6 I3), shared across the ``node_id``s a host
    serves (the binding is a property of the zone). Caller-owned: a request-scoped
    instance threads through the page loop, mirroring the ``resolve_origin_key_for_relay``
    per-request cache so a stale binding never persists across requests.
    """

    def __init__(self) -> None:
        self._entries: dict[str, _CacheEntry] = {}

    def get(
        self,
        host: str,
        *,
        now: datetime,
        floor: int,
        cap: int,
    ) -> BindingRecord | None:
        """Return the cached binding for ``host`` if still within its interval.

        ``None`` when the host is uncached or its entry is past the effective
        interval (the caller must re-resolve). The interval is derived from the
        CACHED entry's own TTL, so a short-TTL origin re-checks sooner.
        """
        entry = self._entries.get(host)
        if entry is None:
            return None
        interval = effective_interval(entry.ttl, floor=floor, cap=cap)
        if (now - entry.validated_at).total_seconds() < interval:
            return entry.record
        return None

    def put(
        self,
        host: str,
        *,
        record: BindingRecord,
        validated_at: datetime,
        ttl: int | None,
    ) -> None:
        """Record a fresh validated re-check for ``host`` (replaces any prior)."""
        self._entries[host] = _CacheEntry(record=record, validated_at=validated_at, ttl=ttl)


def recheck_relay_binding(
    conn: Any,
    *,
    host: str,
    entity_uri: str,
    node_id: str,
    key_fpr: str,
    resolver: Any,
    settings: Any,
    now: datetime,
) -> None:
    """Re-check a pinned DNSSEC binding's recency/revocation (Rev 6 I5) — 3c.1 stub.

    The cadence clamp (``effective_interval``) + per-origin cache (``RecheckCache``)
    land in this commit; the asymmetric recency/revocation engine lands in 3c.2.
    Until then this raises :class:`RecheckNotImplemented` (fail-closed) so the
    relay wiring honors no DNSSEC pin without a revocation path (plan TB-4). It
    never invokes the injected ``resolver``.
    """
    raise RecheckNotImplemented(
        "DNSSEC relay-path recency/revocation re-check engine is build-phase 3c.2 "
        "(Rev 6 I5); the cadence clamp + cache (3c.1) are in place but the "
        "asymmetric re-check is not yet wired — the relay path fails closed"
    )
