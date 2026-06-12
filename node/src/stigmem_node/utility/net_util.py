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


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True iff *ip* falls in a private/loopback/link-local/IMDS range."""
    return any(ip in net for net in _BLOCKED_NETS)


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
        if _ip_is_blocked(ip):
            raise ValueError(f"Blocked private/loopback address for {hostname!r}: {ip}")


def resolve_pinned_address(
    url: str,
    *,
    allow_schemes: frozenset[str] = frozenset({"https"}),
) -> str:
    """Resolve *url*'s hostname ONCE and return a single safe pinned IP literal.

    Closes the DNS-rebinding TOCTOU (H9 / F-SSRF-1): ``assert_safe_url`` validates
    the resolved addresses but then hands the *hostname* to the HTTP client, which
    re-resolves at connect time — a TTL-0 rebind attacker can serve a public IP at
    validation and a private/loopback/IMDS IP at connect.  Callers must instead
    connect to the *exact* IP this returns (preserving Host header + TLS SNI +
    cert verification against the original hostname).

    Semantics:
    - scheme must be in *allow_schemes* (https-only by default)
    - hostname must resolve (DNS failure → ValueError)
    - if ANY resolved A/AAAA record is private/loopback/link-local/IMDS, the WHOLE
      url is rejected (ValueError).  A rebinder controls which record is served, so
      we never cherry-pick a public record out of a mixed set.
    - returns the first resolved IP (a bare literal, e.g. ``"203.0.113.7"`` or
      ``"2001:db8::1"`` — caller is responsible for bracketing IPv6 in a URL).

    All failure modes raise ValueError so the caller can fail closed.
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

    pinned: str | None = None
    for info in infos:
        addr = str(info[4][0])
        ip = ipaddress.ip_address(addr)
        if _ip_is_blocked(ip):
            # Reject the whole URL — the rebinder chooses which record is served.
            raise ValueError(f"Blocked private/loopback address for {hostname!r}: {ip}")
        if pinned is None:
            pinned = addr

    if pinned is None:
        raise ValueError(f"Hostname {hostname!r} resolved to no addresses")
    return pinned
