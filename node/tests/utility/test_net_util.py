"""Regression tests for H-SEC-1: SSRF guard in assert_safe_url.

Verifies that outbound requests cannot be redirected to private/loopback/
link-local addresses (AWS IMDS, RFC 1918, localhost, IPv6 ULA/LL).
"""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import patch

import pytest

from stigmem_node.net_util import assert_safe_url, resolve_pinned_address
from stigmem_node.utility.net_util import _ip_is_blocked

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_getaddrinfo(ip_str: str):
    """Return a lambda that monkeypatches socket.getaddrinfo to yield *ip_str*."""
    ip = ipaddress.ip_address(ip_str)
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET

    def _mock(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, 6, "", (ip_str, port or 0))]

    return _mock


# ---------------------------------------------------------------------------
# Scheme checks
# ---------------------------------------------------------------------------


def test_ftp_scheme_rejected():
    with pytest.raises(ValueError, match="Disallowed URL scheme"):
        assert_safe_url("ftp://example.com/resource")


def test_file_scheme_rejected():
    with pytest.raises(ValueError, match="Disallowed URL scheme"):
        assert_safe_url("file:///etc/passwd")


def test_no_scheme_rejected():
    with pytest.raises(ValueError, match="Disallowed URL scheme"):
        assert_safe_url("example.com/path")


def test_http_rejected_by_default():
    """HTTP is not in the default allow_schemes — only HTTPS."""
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34")),
        pytest.raises(ValueError, match="Disallowed URL scheme"),
    ):
        assert_safe_url("http://example.com/path")


def test_https_allowed_for_public_ip():
    with patch("socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34")):
        assert_safe_url("https://example.com/path")  # must not raise


def test_http_allowed_when_explicitly_permitted():
    with patch("socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34")):
        assert_safe_url("http://example.com/path", allow_schemes=frozenset({"https", "http"}))


# ---------------------------------------------------------------------------
# Loopback (127/8)
# ---------------------------------------------------------------------------


def test_loopback_127_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://localhost/", allow_schemes=frozenset({"https", "http"}))


def test_loopback_127_0_0_2_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.2")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://internalhost/", allow_schemes=frozenset({"https", "http"}))


def test_ipv6_loopback_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("::1")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://ip6-loopback/", allow_schemes=frozenset({"https", "http"}))


# ---------------------------------------------------------------------------
# AWS IMDS / link-local (169.254/16) — the primary exploit vector in H-SEC-1
# ---------------------------------------------------------------------------


def test_aws_imds_blocked():
    """169.254.169.254 must be unreachable regardless of hostname used."""
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url(
            "http://169.254.169.254/latest/meta-data/",
            allow_schemes=frozenset({"https", "http"}),
        )


def test_link_local_any_host_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("169.254.1.100")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://internal-svc/", allow_schemes=frozenset({"https", "http"}))


# ---------------------------------------------------------------------------
# RFC 1918
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["10.0.0.1", "10.255.255.255"])
def test_rfc1918_10_blocked(ip: str):
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo(ip)),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://corp-internal/", allow_schemes=frozenset({"https", "http"}))


@pytest.mark.parametrize("ip", ["172.16.0.1", "172.31.255.255"])
def test_rfc1918_172_blocked(ip: str):
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo(ip)),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://corp-internal/", allow_schemes=frozenset({"https", "http"}))


@pytest.mark.parametrize("ip", ["192.168.0.1", "192.168.255.255"])
def test_rfc1918_192_blocked(ip: str):
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo(ip)),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://home-router/", allow_schemes=frozenset({"https", "http"}))


# ---------------------------------------------------------------------------
# IPv6 private
# ---------------------------------------------------------------------------


def test_ipv6_ula_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("fd00::1")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://ula-host/", allow_schemes=frozenset({"https", "http"}))


def test_ipv6_link_local_blocked():
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo("fe80::1")),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://ll-host/", allow_schemes=frozenset({"https", "http"}))


# ---------------------------------------------------------------------------
# F-SSRF-3: IPv4-mapped IPv6 / CGNAT / NAT64 must NOT bypass the blocklist.
#
# The guard checked membership in explicit IPv4/IPv6 nets, which an attacker
# sidesteps by serving a AAAA record whose address EMBEDS a blocked IPv4 —
# e.g. ::ffff:169.254.169.254 routes to cloud IMDS on a dual-stack host, yet
# is neither in the IPv4 nets (wrong version) nor the IPv6 nets. Both
# assert_safe_url (creation) and resolve_pinned_address (delivery) share the
# guard, so both were bypassable.
# ---------------------------------------------------------------------------

_EMBEDDED_OR_SHARED_BLOCKED = [
    "::ffff:127.0.0.1",        # IPv4-mapped loopback
    "::ffff:169.254.169.254",  # IPv4-mapped AWS/GCP IMDS
    "::ffff:10.0.0.5",         # IPv4-mapped RFC1918
    "::ffff:192.168.1.1",      # IPv4-mapped RFC1918
    "100.64.0.1",              # RFC 6598 CGNAT shared address space
    "64:ff9b::7f00:1",         # NAT64 well-known prefix embedding 127.0.0.1
]


@pytest.mark.parametrize("ip", _EMBEDDED_OR_SHARED_BLOCKED)
def test_ip_is_blocked_catches_embedded_and_shared(ip: str) -> None:
    assert _ip_is_blocked(ipaddress.ip_address(ip)) is True


@pytest.mark.parametrize("ip", _EMBEDDED_OR_SHARED_BLOCKED)
def test_assert_safe_url_blocks_embedded_and_shared(ip: str) -> None:
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo(ip)),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        assert_safe_url("https://attacker-dns/", allow_schemes=frozenset({"https", "http"}))


@pytest.mark.parametrize("ip", _EMBEDDED_OR_SHARED_BLOCKED)
def test_resolve_pinned_address_blocks_embedded_and_shared(ip: str) -> None:
    with (
        patch("socket.getaddrinfo", _fake_getaddrinfo(ip)),
        pytest.raises(ValueError, match="Blocked private/loopback"),
    ):
        resolve_pinned_address("https://attacker-dns/", allow_schemes=frozenset({"https"}))


def test_public_ipv6_still_allowed() -> None:
    """A genuinely public IPv6 must still pass (no over-blocking)."""
    with patch("socket.getaddrinfo", _fake_getaddrinfo("2606:4700:4700::1111")):
        assert_safe_url("https://public-v6/")  # Cloudflare DNS — must not raise


# ---------------------------------------------------------------------------
# DNS resolution failure
# ---------------------------------------------------------------------------


def test_unresolvable_host_rejected():
    with pytest.raises(ValueError, match="Cannot resolve hostname"):
        assert_safe_url(
            "https://this-host-does-not-exist.invalid/",
            allow_schemes=frozenset({"https", "http"}),
        )


# ---------------------------------------------------------------------------
# Regression: _try_fetch_manifest call site uses assert_safe_url
# ---------------------------------------------------------------------------


def test_try_fetch_manifest_blocks_private_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_try_fetch_manifest must not make any HTTP request for a private URL."""
    import stigmem_node.identity.trust_store as ts

    requests_made: list[str] = []

    def _mock_httpx_get(url: str, **kwargs):
        requests_made.append(url)
        raise AssertionError("httpx.get must not be called for private URLs")

    monkeypatch.setattr("stigmem_node.identity.trust_store.httpx.get", _mock_httpx_get)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        _fake_getaddrinfo("169.254.169.254"),
    )

    result = ts._try_fetch_manifest("http://169.254.169.254")
    assert result is None
    assert requests_made == [], "httpx.get was called despite SSRF guard"


# ---------------------------------------------------------------------------
# Regression: _check_tl_inclusion_for_peer call site uses assert_safe_url
# ---------------------------------------------------------------------------


def test_check_tl_inclusion_blocks_imds_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """_check_tl_inclusion_for_peer must not open an HTTP connection to IMDS."""
    import asyncio

    import stigmem_node.routes._federation_impl as fed_impl

    client_entered: list[str] = []

    class _ShouldNotEnter:
        def __init__(self, **kwargs):
            pass  # instantiation is fine; __aenter__ must never be reached

        async def __aenter__(self):
            client_entered.append("entered")
            raise AssertionError("AsyncClient.__aenter__ must not be called for private URLs")

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("stigmem_node.routes._federation_impl.httpx.AsyncClient", _ShouldNotEnter)
    monkeypatch.setattr(
        "socket.getaddrinfo",
        _fake_getaddrinfo("169.254.169.254"),
    )
    # Stub out audit/DB calls so this pure SSRF test doesn't need a real database.
    monkeypatch.setattr("stigmem_node.routes.federation.write_audit_log", lambda *a, **kw: None)

    asyncio.run(
        fed_impl._check_tl_inclusion_for_peer(
            "stigmem://attacker",
            "http://169.254.169.254/latest/meta-data/",
            "fake-peer-id",
        )
    )

    assert client_entered == [], "httpx.AsyncClient.__aenter__ was reached despite SSRF guard"
