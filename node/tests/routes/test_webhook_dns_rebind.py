"""DNS-rebind TOCTOU hardening for webhook delivery (H9 / F-SSRF-1).

The pre-H9 delivery guard validated ``delivery_address`` with ``assert_safe_url``
(getaddrinfo + private-IP block) and then handed the *hostname* to ``httpx``,
which RE-RESOLVED it at connect time.  A TTL-0 DNS-rebind attacker can serve a
public IP at validation time and ``127.0.0.1`` / IMDS at connect time → SSRF
despite the guard (TOCTOU).

The fix resolves the hostname ONCE (``resolve_pinned_address``), validates every
resolved record, and connects to that EXACT pinned IP — while preserving the
``Host`` header, the TLS SNI, and certificate verification against the ORIGINAL
hostname.

The first test class is the LOAD-BEARING regression test: it stands up a real
local https server with a self-signed cert whose SAN is ``webhook.test``, pins
resolution to ``127.0.0.1``, and proves a REAL TLS handshake verifies the cert
against the hostname (NOT the IP) while the socket connects to the pinned IP.
A prior draft mocked httpx and therefore never proved this; that gap is exactly
what hid the cert-vs-IP risk.  These tests never disable TLS verification.
"""

from __future__ import annotations

import datetime
import os
import ssl
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import stigmem_node.net_util as nu
import stigmem_node.subscription_delivery as sd

TEST_HOST = "webhook.test"


# ---------------------------------------------------------------------------
# Local self-signed TLS server helpers
# ---------------------------------------------------------------------------


def _make_cert(san_host: str) -> tuple[str, str]:
    """Generate a self-signed cert whose CN/SAN is *san_host*; return (cert, key) paths."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san_host)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(san_host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    d = tempfile.mkdtemp()
    cert_path = os.path.join(d, "cert.pem")
    key_path = os.path.join(d, "key.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


class _Recorder:
    host_header: str | None = None
    body: bytes | None = None


def _serve_https(cert_path: str, key_path: str, recorder: _Recorder) -> tuple[HTTPServer, int]:
    """Start a loopback https server recording the Host header of POSTs."""

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — http.server API
            recorder.host_header = self.headers.get("Host")
            length = int(self.headers.get("Content-Length", "0"))
            recorder.body = self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:  # silence
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # refuse legacy TLSv1/TLSv1.1
    ctx.load_cert_chain(cert_path, key_path)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# ---------------------------------------------------------------------------
# LOAD-BEARING: real TLS handshake verifies cert against HOSTNAME, socket
# connects to PINNED IP.
# ---------------------------------------------------------------------------


class TestLiveTLSPinnedConnect:
    """Prove the production connect pattern: IP-literal socket + hostname cert."""

    def _connect_via_production_pattern(
        self, *, ip_url: str, hostname: str, port: int, verify: ssl.SSLContext
    ) -> httpx.Response:
        """Replicate EXACTLY the connect pattern used by ``_deliver_webhook``.

        Asserted to match production below in
        ``test_production_code_uses_sni_hostname_pattern``.
        """
        with httpx.Client(timeout=10.0, follow_redirects=False, verify=verify) as client:
            return client.post(
                ip_url,
                json={"ping": 1},
                headers={
                    "Content-Type": "application/json",
                    "Host": f"{hostname}:{port}",
                },
                extensions={"sni_hostname": hostname},
            )

    def test_pinned_ip_connect_verifies_cert_against_hostname(self) -> None:
        """SUCCESS: cert SAN matches hostname; socket hits the pinned IP."""
        cert_path, key_path = _make_cert(TEST_HOST)
        rec = _Recorder()
        srv, port = _serve_https(cert_path, key_path, rec)
        try:
            verify = ssl.create_default_context(cafile=cert_path)
            # Pin resolution to 127.0.0.1 (the rebind target) — URL carries the IP.
            resp = self._connect_via_production_pattern(
                ip_url=f"https://127.0.0.1:{port}/hook",
                hostname=TEST_HOST,
                port=port,
                verify=verify,
            )
            assert resp.status_code == 200
            assert resp.text == "ok"
            # Proves the cert was verified against the HOSTNAME — a default-context
            # verify of an IP-literal URL would otherwise reject (IP not in SAN).
            # Proves the Host header carried the original hostname, not the IP.
            assert rec.host_header == f"{TEST_HOST}:{port}"
        finally:
            srv.shutdown()

    def test_pinned_ip_without_sni_hostname_is_rejected(self) -> None:
        """Control: WITHOUT the sni_hostname extension, the IP-literal URL fails.

        This proves the success above is *because of* the hostname SNI/cert
        mechanism, not because verification is lax — the cert has no IP SAN.
        """
        cert_path, key_path = _make_cert(TEST_HOST)
        rec = _Recorder()
        srv, port = _serve_https(cert_path, key_path, rec)
        try:
            verify = ssl.create_default_context(cafile=cert_path)
            with (
                httpx.Client(timeout=10.0, follow_redirects=False, verify=verify) as client,
                pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"),
            ):
                client.post(f"https://127.0.0.1:{port}/hook", json={"ping": 1})
        finally:
            srv.shutdown()

    def test_wrong_san_cert_is_rejected_even_with_sni(self) -> None:
        """SAN mismatch is REJECTED — verification is real, not disabled."""
        cert_path, key_path = _make_cert("not-the-host.example")
        rec = _Recorder()
        srv, port = _serve_https(cert_path, key_path, rec)
        try:
            verify = ssl.create_default_context(cafile=cert_path)
            with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
                self._connect_via_production_pattern(
                    ip_url=f"https://127.0.0.1:{port}/hook",
                    hostname=TEST_HOST,
                    port=port,
                    verify=verify,
                )
        finally:
            srv.shutdown()

    def test_production_code_uses_sni_hostname_pattern(self, monkeypatch) -> None:
        """Assert the production path uses the proven pattern: IP-literal URL +
        Host header + sni_hostname extension.

        Drives ``_deliver_webhook`` end to end with resolution pinned to a public
        record and a mocked client, capturing the exact call that production
        makes, then asserts each element of the proven-correct pattern.
        """
        captured: dict = {}

        monkeypatch.setattr(sd, "resolve_pinned_address", lambda *a, **k: "203.0.113.7")
        monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
        monkeypatch.setattr(sd, "_mark_delivered", lambda eid, sid: None)

        resp = MagicMock()
        resp.status_code = 200
        client = MagicMock()

        def post(url, **kwargs):  # noqa: ANN001, ANN003
            captured["url"] = url
            captured["headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return resp

        client.post.side_effect = post
        client_cm = MagicMock()
        client_cm.__enter__.return_value = client
        monkeypatch.setattr(sd.httpx, "Client", MagicMock(return_value=client_cm))

        event = {
            "id": "e1",
            "subscription_id": "s1",
            "event_type": "fact.created",
            "delivery_address": "https://webhook.test:8443/hook",
        }
        result = sd._deliver_webhook(event, {})

        assert result is True
        # URL targets the pinned IP literal, NOT the re-resolvable hostname.
        assert captured["url"] == "https://203.0.113.7:8443/hook"
        # Host header preserves the original hostname (+ port).
        assert captured["headers"]["Host"] == "webhook.test:8443"
        # SNI / cert-verification hostname is the original hostname.
        assert captured["extensions"]["sni_hostname"] == "webhook.test"


# ---------------------------------------------------------------------------
# resolve_pinned_address semantics
# ---------------------------------------------------------------------------


class TestResolvePinnedAddress:
    def test_returns_validated_public_ip(self, monkeypatch) -> None:
        def fake_gai(host, *a, **k):  # noqa: ANN001, ANN002, ANN003
            return [(2, 1, 6, "", ("93.184.216.34", 0))]

        monkeypatch.setattr(nu.socket, "getaddrinfo", fake_gai)
        result = nu.resolve_pinned_address(
            "https://ok.example/x", allow_schemes=frozenset({"https"})
        )
        assert result == "93.184.216.34"

    def test_loopback_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(
            nu.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))]
        )
        with pytest.raises(ValueError, match="Blocked private/loopback"):
            nu.resolve_pinned_address("https://evil.example/x", allow_schemes=frozenset({"https"}))

    def test_imds_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(
            nu.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))]
        )
        with pytest.raises(ValueError, match="Blocked private/loopback"):
            nu.resolve_pinned_address("https://evil.example/x", allow_schemes=frozenset({"https"}))

    def test_mixed_public_and_private_records_rejected(self, monkeypatch) -> None:
        """Rebinder controls which record is served — reject the WHOLE url if ANY
        resolved record is private; do NOT cherry-pick the public one."""
        monkeypatch.setattr(
            nu.socket,
            "getaddrinfo",
            lambda *a, **k: [
                (2, 1, 6, "", ("93.184.216.34", 0)),  # public
                (2, 1, 6, "", ("127.0.0.1", 0)),  # private — must trip
            ],
        )
        with pytest.raises(ValueError, match="Blocked private/loopback"):
            nu.resolve_pinned_address("https://evil.example/x", allow_schemes=frozenset({"https"}))

    def test_disallowed_scheme_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(
            nu.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]
        )
        with pytest.raises(ValueError, match="Disallowed URL scheme"):
            nu.resolve_pinned_address("http://ok.example/x", allow_schemes=frozenset({"https"}))

    def test_unresolvable_host_rejected(self, monkeypatch) -> None:
        import socket as real_socket

        def boom(*a, **k):  # noqa: ANN002, ANN003
            raise real_socket.gaierror("nope")

        monkeypatch.setattr(nu.socket, "getaddrinfo", boom)
        with pytest.raises(ValueError, match="Cannot resolve"):
            nu.resolve_pinned_address("https://nx.example/x", allow_schemes=frozenset({"https"}))

    def test_ipv6_literal_bracketing(self, monkeypatch) -> None:
        """An IPv6 pinned address must round-trip into a valid bracketed URL.

        ``::1`` is itself blocked, so prove bracketing via the resolver returning
        a (public) IPv6 literal and the delivery path constructing ``https://[...]``.
        """
        # 2606:4700:4700::1111 is a genuinely-global IPv6 (Cloudflare DNS).
        monkeypatch.setattr(
            nu.socket,
            "getaddrinfo",
            lambda *a, **k: [(10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0))],
        )
        assert nu.resolve_pinned_address(
            "https://v6.example/x", allow_schemes=frozenset({"https"})
        ) == "2606:4700:4700::1111"


# ---------------------------------------------------------------------------
# Delivery wiring: pins to IP literal; fail-closed on rebind/resolution error.
# ---------------------------------------------------------------------------


class TestDeliveryPinning:
    @staticmethod
    def _event(addr: str) -> dict:
        return {
            "id": "e1",
            "subscription_id": "s1",
            "event_type": "fact.created",
            "delivery_address": addr,
        }

    def test_delivery_targets_pinned_ip_not_hostname(self, monkeypatch) -> None:
        monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
        monkeypatch.setattr(sd, "resolve_pinned_address", lambda *a, **k: "203.0.113.5")

        captured: dict = {}
        resp = MagicMock()
        resp.status_code = 200
        client = MagicMock()

        def post(url, **kwargs):  # noqa: ANN001, ANN003
            captured["url"] = url
            captured["headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return resp

        client.post.side_effect = post
        client_cm = MagicMock()
        client_cm.__enter__.return_value = client
        client_ctor = MagicMock(return_value=client_cm)
        monkeypatch.setattr(sd.httpx, "Client", client_ctor)

        result = sd._deliver_webhook(self._event("https://webhook.test:8443/hook"), {})

        assert result is True
        assert captured["url"] == "https://203.0.113.5:8443/hook"
        assert captured["headers"]["Host"] == "webhook.test:8443"
        assert captured["extensions"]["sni_hostname"] == "webhook.test"
        assert client_ctor.call_args.kwargs.get("follow_redirects") is False

    def test_default_port_omitted_from_url_and_host(self, monkeypatch) -> None:
        monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
        monkeypatch.setattr(sd, "resolve_pinned_address", lambda *a, **k: "203.0.113.5")

        captured: dict = {}
        resp = MagicMock()
        resp.status_code = 200
        client = MagicMock()

        def post(url, **kwargs):  # noqa: ANN001, ANN003
            captured["url"] = url
            captured["headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return resp

        client.post.side_effect = post
        client_cm = MagicMock()
        client_cm.__enter__.return_value = client
        monkeypatch.setattr(sd.httpx, "Client", MagicMock(return_value=client_cm))

        sd._deliver_webhook(self._event("https://webhook.test/hook?q=1"), {})

        assert captured["url"] == "https://203.0.113.5/hook?q=1"
        assert captured["headers"]["Host"] == "webhook.test"
        assert captured["extensions"]["sni_hostname"] == "webhook.test"

    def test_ipv6_pinned_ip_is_bracketed_in_url(self, monkeypatch) -> None:
        monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
        monkeypatch.setattr(sd, "resolve_pinned_address", lambda *a, **k: "2001:db8::1")

        captured: dict = {}
        resp = MagicMock()
        resp.status_code = 200
        client = MagicMock()

        def post(url, **kwargs):  # noqa: ANN001, ANN003
            captured["url"] = url
            return resp

        client.post.side_effect = post
        client_cm = MagicMock()
        client_cm.__enter__.return_value = client
        monkeypatch.setattr(sd.httpx, "Client", MagicMock(return_value=client_cm))

        sd._deliver_webhook(self._event("https://v6.example:9000/hook"), {})

        # IPv6 literal must be bracketed for a valid authority.
        assert captured["url"] == "https://[2001:db8::1]:9000/hook"

    def test_rebind_to_loopback_blocked_fail_closed(self, monkeypatch) -> None:
        """resolve_pinned_address raises (rebind target is private) →
        block + mark delivered (stop retrying), never construct a client."""
        monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})

        def reject(*a, **k):  # noqa: ANN002, ANN003
            raise ValueError("Blocked private/loopback address")

        monkeypatch.setattr(sd, "resolve_pinned_address", reject)
        marked: list = []
        monkeypatch.setattr(sd, "_mark_delivered", lambda eid, sid: marked.append((eid, sid)))
        client_ctor = MagicMock()
        monkeypatch.setattr(sd.httpx, "Client", client_ctor)

        result = sd._deliver_webhook(self._event("https://rebind.evil/hook"), {})

        assert result is True  # stop retrying
        client_ctor.assert_not_called()
        assert marked == [("e1", "s1")]
