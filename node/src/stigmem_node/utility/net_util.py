"""Outbound HTTP safety utilities — SSRF guard (H-SEC-1)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# RFC 1918, loopback, link-local, and IPv6 equivalents.
# Cloud IMDS (169.254.169.254) is covered by 169.254.0.0/16.
_BLOCKED_NETS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def node_url_is_loopback(node_url: str) -> bool:
    """Return True iff *node_url*'s host is a literal loopback host.

    Shared by the startup bind-safety check and the federation approval-time
    SSRF-skip gate so the loopback host set lives in exactly one place.
    """
    try:
        parsed = urlparse(node_url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "::1"}


def assert_safe_url(
    url: str,
    *,
    allow_schemes: frozenset[str] = frozenset({"https"}),
) -> None:
    """Raise ValueError if *url* is unsafe to fetch.

    Checks:
    - scheme is in *allow_schemes*
    - hostname resolves (DNS failure → ValueError)
    - no resolved address falls in RFC 1918, loopback, or link-local ranges

    Residual risk: DNS rebinding window between this check and the actual
    connection. Callers MUST also set follow_redirects=False so redirects
    cannot send the connection to a private address after validation.
    """
    parsed = urlparse(url)
    if parsed.scheme not in allow_schemes:
        raise ValueError(f"Disallowed URL scheme: {parsed.scheme!r}")
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError(f"URL has no hostname: {url!r}")
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname {hostname!r}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        for net in _BLOCKED_NETS:
            if ip in net:
                raise ValueError(f"Blocked private/loopback address for {hostname!r}: {ip}")
