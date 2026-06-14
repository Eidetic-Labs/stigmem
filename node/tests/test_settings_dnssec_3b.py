"""DNSSEC first-trust settings (Phase 3 build-phase 3b, Rev 6 §10).

Asserts the four new federation_dnssec_* settings exist and default safe/inert
on a vanilla node: the master gate is OFF, and the rate-cap / TTL / RRSIG-age
ceilings carry the documented defaults. These settings ship in 3b; their
ENFORCEMENT (ladder, quarantine, age-clamp) lands in later 3b tasks. The
recheck floor/cap settings belong to 3c and are intentionally NOT asserted here.
"""

from __future__ import annotations

from stigmem_node.settings import Settings


def test_dnssec_trust_disabled_by_default() -> None:
    """The master gate for the DNSSEC first-trust ladder is OFF by default."""
    s = Settings()
    assert s.federation_dnssec_trust_enabled is False


def test_dnssec_max_rrsig_age_default() -> None:
    """RRSIG-age ceiling defaults to a generous 7 days (in seconds)."""
    s = Settings()
    assert s.federation_dnssec_max_rrsig_age == 7 * 24 * 60 * 60


def test_dnssec_pending_confirm_cap_default() -> None:
    """Per-relay-peer cap on pending_first_trust inserts defaults to 100."""
    s = Settings()
    assert s.federation_dnssec_pending_confirm_cap == 100


def test_dnssec_pending_confirm_ttl_default() -> None:
    """Unconfirmed quarantine rows expire after 7 days by default (in seconds)."""
    s = Settings()
    assert s.federation_dnssec_pending_confirm_ttl == 7 * 24 * 60 * 60
