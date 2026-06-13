"""Canonical entity_uri -> DNS host derivation (Rev 6 I3, NF-R5D-1).

The host queried for the DNSSEC binding record MUST come from the signed wire
entity_uri via a single canonical algorithm. The adversarial cases below are
the security contract: a userinfo steer, a non-default port, an IP literal, and
a non-HTTP scheme all return None (the DNSSEC tier is not applicable -> the
caller routes to operator-confirm).
"""

from __future__ import annotations

import pytest

from stigmem_node.federation.dnssec.host import host_from_entity_uri


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("https://memory.acme.example/", "memory.acme.example"),
        ("http://memory.acme.example/x", "memory.acme.example"),
        # case-fold + trailing-dot strip
        ("https://Memory.ACME.example./x", "memory.acme.example"),
        # already an A-label -> unchanged
        ("https://xn--vctim-n4a.example/", "xn--vctim-n4a.example"),
        # IDN (U-label, dotless-i U+0131) -> A-label (punycode)
        ("https://vıctim.example/", "xn--vctim-n4a.example"),
        # 3AC-3: scheme is case-insensitive (RFC 3986) -> recognize + canonicalize.
        ("HTTPS://Memory.ACME.example/", "memory.acme.example"),
        ("HtTp://memory.acme.example/x", "memory.acme.example"),
    ],
)
def test_valid_hosts_canonicalize(uri, expected):
    assert host_from_entity_uri(uri) == expected


@pytest.mark.parametrize(
    "uri",
    [
        "https://victim.com@attacker.com/",  # userinfo steer -> reject
        "https://user:pass@attacker.com/",  # userinfo with password -> reject
        "https://attacker.com:8443/",  # non-default port -> reject
        "http://attacker.com:8080/",  # non-default port -> reject
        "https://192.0.2.5/",  # IPv4 literal -> not applicable
        "https://[2001:db8::1]/",  # IPv6 literal -> not applicable
        "did:web:example",  # non-HTTP scheme -> not applicable
        "urn:stigmem:node:7",  # opaque -> not applicable
        "",  # empty -> not applicable
        "https:///path",  # no host -> not applicable
    ],
)
def test_non_dnssec_capable_returns_none(uri):
    assert host_from_entity_uri(uri) is None
