"""DNS-rebind TOCTOU hardening for federation client fetches (R-5 / F-SSRF1).

A peer's ``node_url`` is re-fetched on a loop by the federation pull/push client.
Approval-time validation does not bind the resolved IP, so a peer can pass
validation and then DNS-rebind the host to an internal address (IMDS / RFC1918)
for the recurring fetches.

The a11 anti-rebind pin (``resolve_pinned_address``) shipped only on the
webhook/subscription delivery path; these tests pin down its extension to the
federation fetch sites:

1. Production fetch (federation_insecure=False) PINS the host: a peer whose host
   resolves to a private/internal IP at FETCH time is refused (the pin raises and
   the fetch is skipped, returning the old cursor / aborting the push).
2. Loopback dev (federation_insecure=True + loopback host) is NOT pinned — the
   existing federation suite drives ``pull_from_peer_once`` with fake clients and
   loopback/non-resolving peer URLs, and those must stay green.
3. ``trust_store._try_fetch_manifest`` is https-only (F-SSRF2): an ``http://``
   entity_uri is rejected, matching the already-https-only relay sibling
   ``origin_identity._fetch_relay_manifest``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

import stigmem_node.federation.federation_pull as pull_mod

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CapturedResponse:
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        self._body = body
        self.status_code = status
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _RecordingClient:
    """Async client that records the exact get() call arguments."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.calls: list[dict[str, Any]] = []

    async def get(self, url: str, **kwargs: Any) -> _CapturedResponse:
        self.calls.append({"url": url, **kwargs})
        return _CapturedResponse(self._body)


def _peer(node_url: str) -> dict[str, Any]:
    return {
        "id": "p1",
        "node_id": "stigmem://peer-a",
        "node_url": node_url,
        "allowed_scopes": '["public"]',
        "ingest_tenant": "default",
        "pull_tenant": "default",
        "relay_trusted": 0,
    }


@pytest.fixture()
def _prod_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """federation_insecure=False, mtls off, relay off — production fetch mode."""
    fake = MagicMock()
    fake.federation_insecure = False
    fake.mtls_enabled = False
    fake.federation_relay_enabled = False
    monkeypatch.setattr(pull_mod, "settings", fake)


@pytest.fixture()
def _dev_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """federation_insecure=True — loopback dev mode; pinning must be skipped."""
    fake = MagicMock()
    fake.federation_insecure = True
    fake.mtls_enabled = False
    fake.federation_relay_enabled = False
    monkeypatch.setattr(pull_mod, "settings", fake)


# ---------------------------------------------------------------------------
# 1. Rebind refused at FETCH time (production)
# ---------------------------------------------------------------------------


class TestProductionFetchPinned:
    @pytest.mark.asyncio
    async def test_pull_refuses_host_resolving_to_private_ip(
        self, monkeypatch: pytest.MonkeyPatch, _prod_settings: None
    ) -> None:
        """A peer host that resolves to a private/internal IP at fetch time is refused.

        The pin (resolve_pinned_address) raises ValueError for the private rebind
        target; the fetch must be skipped and the old cursor retained — the fake
        client's get() must never be called.
        """
        # Resolve the peer host to a private (RFC1918) address — the rebind target.
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 0))],
        )
        monkeypatch.setattr(pull_mod, "create_peer_token", lambda *a, **k: "tok")
        client = _RecordingClient({"v": 2, "facts": [], "cursor": "new"})

        result = await pull_mod.pull_from_peer_once(
            _peer("https://rebind.evil/"), client, "old-cursor"
        )

        assert result == "old-cursor", "must retain old cursor (fail-closed)"
        assert client.calls == [], "pinned fetch must not reach the client on rebind"

    @pytest.mark.asyncio
    async def test_pull_targets_pinned_ip_for_public_host(
        self, monkeypatch: pytest.MonkeyPatch, _prod_settings: None
    ) -> None:
        """A public host is fetched against the PINNED ip literal, Host + SNI preserved."""
        # 8.8.8.8 is genuinely global (not RFC5737 reserved), so the pin accepts it.
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))],
        )
        monkeypatch.setattr(pull_mod, "create_peer_token", lambda *a, **k: "tok")
        client = _RecordingClient({"v": 2, "facts": [], "cursor": "next"})

        result = await pull_mod.pull_from_peer_once(
            _peer("https://peer.example:8443/"), client, None
        )

        assert result == "next"
        assert len(client.calls) == 1
        call = client.calls[0]
        # URL targets the pinned IP literal, not the re-resolvable hostname.
        assert call["url"].startswith("https://8.8.8.8:8443/")
        assert "/v1/federation/facts" in call["url"]
        # Host header + SNI carry the ORIGINAL hostname.
        assert call["headers"]["Host"] == "peer.example:8443"
        assert call["extensions"]["sni_hostname"] == "peer.example"

    @pytest.mark.asyncio
    async def test_tombstone_pull_refuses_private_rebind(
        self, monkeypatch: pytest.MonkeyPatch, _prod_settings: None
    ) -> None:
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))],  # IMDS
        )
        monkeypatch.setattr(pull_mod, "create_peer_token", lambda *a, **k: "tok")
        client = _RecordingClient({"v": 2, "tombstones": [], "cursor": "new"})

        result = await pull_mod.pull_tombstones_from_peer_once(
            _peer("https://rebind.evil/"), client, "old-tomb-cursor"
        )

        assert result == "old-tomb-cursor"
        assert client.calls == []


# ---------------------------------------------------------------------------
# 2. Loopback dev still works (federation_insecure=True, no pin)
# ---------------------------------------------------------------------------


class TestLoopbackDevBypass:
    @pytest.mark.asyncio
    async def test_pull_under_insecure_does_not_pin_or_resolve(
        self, monkeypatch: pytest.MonkeyPatch, _dev_settings: None
    ) -> None:
        """Under federation_insecure=True the fetch is NOT pinned — the original URL
        is passed straight to the client and getaddrinfo is never called.

        This mirrors how the existing federation suite drives pull_from_peer_once
        with fake clients and non-resolving / loopback peer URLs.
        """

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("getaddrinfo must not be called in insecure dev mode")

        monkeypatch.setattr("stigmem_node.utility.net_util.socket.getaddrinfo", _boom)
        monkeypatch.setattr(pull_mod, "create_peer_token", lambda *a, **k: "tok")
        client = _RecordingClient({"v": 2, "facts": [], "cursor": "c2"})

        result = await pull_mod.pull_from_peer_once(
            _peer("http://relay-b"), client, None
        )

        assert result == "c2"
        assert len(client.calls) == 1
        # Original hostname URL passed through unchanged; no pin extensions added.
        assert client.calls[0]["url"].startswith("http://relay-b/v1/federation/facts")
        assert "extensions" not in client.calls[0]


# ---------------------------------------------------------------------------
# 3. _try_fetch_manifest is https-only (F-SSRF2)
# ---------------------------------------------------------------------------


class TestManifestFetchHttpsOnly:
    def test_http_entity_uri_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An http:// entity_uri must be rejected by the manifest fetch (https-only).

        assert_safe_url is invoked with allow_schemes={"https"} so an http base_url
        raises 'Disallowed URL scheme' and no GET is attempted.
        """
        from stigmem_node.identity import trust_store

        # Resolve to a genuinely-global IP so assert_safe_url's address check would
        # PASS for http — isolating the failure to the https-only SCHEME check.
        # (203.0.113.x is RFC5737 TEST-NET-3, classified is_reserved → would block
        # regardless of scheme and give a false green.)
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))],
        )
        get_calls: list[str] = []

        def _fake_get(url: str, **k: Any) -> Any:
            # If the scheme guard does NOT reject http, the code reaches here and
            # would succeed — proving http was (wrongly) allowed. Return a valid
            # 200 manifest-shaped response so the ONLY way to a None result + an
            # empty call list is the https-only scheme rejection BEFORE the GET.
            get_calls.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.json = lambda: {}
            return resp

        monkeypatch.setattr(trust_store.httpx, "get", _fake_get)

        result = trust_store._try_fetch_manifest("http://peer.example/org/x")

        assert result is None, "http:// entity_uri must be refused"
        assert get_calls == [], "no GET may be attempted for an http:// manifest URL"
