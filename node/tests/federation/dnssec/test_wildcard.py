"""Wildcard-synthesis rejection test (Rev 6 I3) — commit 3a.6.

A binding TXT synthesized from a ``*`` wildcard must be rejected (BOGUS): the
binding record requires an exact-match RRSIG. The synthesized answer still
verifies cryptographically against the zone DNSKEY, so this proves the
RRSIG-labels check (RFC 4035 §5.3.1) catches what the chain check alone cannot.
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.validator import Validation, validate_binding

from .conftest import HOST


def test_wildcard_synthesized_binding_is_bogus(wildcard_synth):
    res = validate_binding(HOST.rstrip("."), resolver=wildcard_synth)
    assert res.status is Validation.BOGUS, res.detail
    assert "wildcard" in res.detail
