"""DNSSEC relay-path re-check settings (Phase 3 build-phase 3c, Rev 6 §7/I5).

Asserts the four new federation_dnssec_* re-check settings exist with their
documented defaults: the cadence clamp bounds (floor/cap) and the
unreachable/suppression grace (absolute cap + TTL multiple). All default-safe —
they are only consulted on the flag-on relay-path re-check, which is unreachable
on a default node.
"""

from __future__ import annotations

from stigmem_node.settings import Settings


def test_dnssec_recheck_floor_default() -> None:
    """Anti-storm re-check floor defaults to 300s."""
    s = Settings()
    assert s.federation_dnssec_recheck_floor_seconds == 300


def test_dnssec_recheck_cap_default() -> None:
    """Re-check cap defaults to 3600s (1h)."""
    s = Settings()
    assert s.federation_dnssec_recheck_cap_seconds == 3600


def test_dnssec_unreachable_grace_default() -> None:
    """Absolute unreachable/suppression grace cap defaults to 24h (86400s)."""
    s = Settings()
    assert s.federation_dnssec_unreachable_grace_seconds == 86400


def test_dnssec_unreachable_ttl_multiple_default() -> None:
    """The unreachable grace TTL multiple (k) defaults to 4."""
    s = Settings()
    assert s.federation_dnssec_unreachable_ttl_multiple == 4
