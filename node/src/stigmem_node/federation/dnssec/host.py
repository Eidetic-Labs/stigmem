"""Canonical entity_uri -> DNS host derivation for the DNSSEC first-trust tier.

Rev 6 I3 (single canonical algorithm, used for BOTH the DNS qname and the pin
key). The host MUST be derived from the signed wire ``entity_uri`` by exactly
this algorithm; the relay-carried manifest is never consulted.

Returns ``None`` when the ``entity_uri`` is not DNSSEC-capable — a non-HTTP
scheme, an IP-literal host, embedded userinfo (``@``), or a non-default port.
A ``None`` result is an expected ladder path (the DNSSEC tier is not
applicable -> the caller routes to operator-confirm), not an error.

Self-certification note (Rev 6 I3 — keep so a future reader does not "fix" the
ordering): the wire ``entity_uri`` is not signature-verified at query time. A
forged ``entity_uri`` can only select a zone the forger controls, yielding
trust in the forger's *own* identity, never a victim's; the ``origin_sig``
check closes the loop after resolution.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_HTTP_SCHEMES = ("https://", "http://")


def host_from_entity_uri(entity_uri: str) -> str | None:
    """Return the canonical DNS host for ``entity_uri``, or ``None``.

    ``None`` means the DNSSEC tier is not applicable for this origin.
    """
    if not entity_uri or not entity_uri.startswith(_HTTP_SCHEMES):
        return None

    parsed = urlparse(entity_uri)

    # Userinfo steer (e.g. https://victim.com@attacker.com/) -> reject (NF-R5D-1).
    if parsed.username is not None or parsed.password is not None:
        return None

    # A non-default port is not part of the DNS name -> reject rather than guess.
    try:
        if parsed.port is not None:
            return None
    except ValueError:
        # Malformed port -> not DNSSEC-capable.
        return None

    host = parsed.hostname  # NEVER parsed.netloc
    if not host:
        return None

    # case-fold + strip a single trailing dot.
    host = host.rstrip(".").lower()
    if not host:
        return None

    # IP-literal host (IPv4 or IPv6; urlparse already strips IPv6 brackets) ->
    # DNSSEC tier not applicable.
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    # IDNA-normalize to A-labels (punycode). An already-encoded xn-- label
    # round-trips unchanged.
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
