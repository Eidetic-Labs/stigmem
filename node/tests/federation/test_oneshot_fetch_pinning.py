"""DNS-rebind pinning for the one-shot registration/approval well-known fetches (F-SSRF-3).

The registration well-known fetch (``register_peer_impl``) and the approval-time
manifest fetch (``_check_tl_inclusion_for_peer``) were SSRF-guarded with
``assert_safe_url`` but NOT DNS-pinned, leaving the rebind TOCTOU window the
recurring pull fetches already close. These tests pin the pin to both sites:

1. Production fetch (federation_insecure=False) PINS the host: a target that
   rebinds to a private IP at fetch time is refused (the pin raises and no
   connection is made to the private address).
2. A genuinely-public host is fetched against the PINNED ip literal, with Host
   header + TLS SNI preserved.
3. Loopback dev still works: the approval fetch under federation_insecure + a
   loopback node_url is NOT pinned.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

import stigmem_node.routes._federation_impl as impl


class _CapturedResponse:
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        self._body = body
        self.status_code = status

    def json(self) -> dict[str, Any]:
        return self._body


class _RecordingClient:
    """Async client (context-manager) that records the exact get() call arguments."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> _RecordingClient:
        return self

    async def __aexit__(self, *args: object) -> None:
        pass

    async def get(self, url: str, **kwargs: Any) -> _CapturedResponse:
        self.calls.append({"url": url, **kwargs})
        return _CapturedResponse(self._body)


# ---------------------------------------------------------------------------
# 1. Registration well-known fetch (register_peer_impl)
# ---------------------------------------------------------------------------


class TestRegistrationFetchPinned:
    @pytest.mark.asyncio
    async def test_private_rebind_refused_at_fetch_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A registration target that rebinds to a private IP is refused (no GET)."""
        fake = MagicMock()
        fake.federation_insecure = False  # production: pin enforced
        monkeypatch.setattr(impl, "_pinned_well_known_get", impl._pinned_well_known_get)

        client = _RecordingClient({"federation_pubkey": "x"})
        # Resolve the target host to a private (RFC1918) address — the rebind target.
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 0))],
        )

        with pytest.raises(ValueError, match="private/loopback"):
            await impl._pinned_well_known_get(
                client,
                "https://rebind.evil/.well-known/stigmem",
                allow_schemes=frozenset({"https"}),
                skip_pin=fake.federation_insecure,
            )
        assert client.calls == [], "pinned fetch must not reach the client on rebind"

    @pytest.mark.asyncio
    async def test_public_host_targets_pinned_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A public host is fetched against the PINNED ip literal, Host + SNI preserved."""
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))],
        )
        client = _RecordingClient({"federation_pubkey": "x"})

        resp = await impl._pinned_well_known_get(
            client,
            "https://peer.example:8443/.well-known/stigmem",
            allow_schemes=frozenset({"https"}),
            skip_pin=False,
        )
        assert resp.status_code == 200
        assert len(client.calls) == 1
        call = client.calls[0]
        assert call["url"].startswith("https://8.8.8.8:8443/")
        assert call["headers"]["Host"] == "peer.example:8443"
        assert call["extensions"]["sni_hostname"] == "peer.example"

    @pytest.mark.asyncio
    async def test_insecure_skips_pin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Under federation_insecure the registration fetch is NOT pinned (NF-2 bypass)."""

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("getaddrinfo must not be called when pin is skipped")

        monkeypatch.setattr("stigmem_node.utility.net_util.socket.getaddrinfo", _boom)
        client = _RecordingClient({"federation_pubkey": "x"})

        await impl._pinned_well_known_get(
            client,
            "http://test-b-reg/.well-known/stigmem",
            allow_schemes=frozenset({"https"}),
            skip_pin=True,
        )
        assert len(client.calls) == 1
        assert client.calls[0]["url"] == "http://test-b-reg/.well-known/stigmem"
        assert "extensions" not in client.calls[0]


# ---------------------------------------------------------------------------
# 2. Approval-time manifest fetch (_check_tl_inclusion_for_peer)
# ---------------------------------------------------------------------------


class TestApprovalManifestFetchPinned:
    @pytest.mark.asyncio
    async def test_private_rebind_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An approval-time manifest target rebinding to IMDS is refused (no GET)."""
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))],  # IMDS
        )
        client = _RecordingClient({})

        with pytest.raises(ValueError, match="private/loopback"):
            await impl._pinned_well_known_get(
                client,
                "https://rebind.evil/.well-known/stigmem-manifest.json",
                allow_schemes=frozenset({"https", "http"}),
                skip_pin=False,
                follow_redirects=False,
            )
        assert client.calls == []

    @pytest.mark.asyncio
    async def test_loopback_dev_skips_pin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Under federation_insecure + loopback the approval fetch is NOT pinned."""

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("getaddrinfo must not be called for loopback dev")

        monkeypatch.setattr("stigmem_node.utility.net_util.socket.getaddrinfo", _boom)
        client = _RecordingClient({})

        await impl._pinned_well_known_get(
            client,
            "http://localhost:8765/.well-known/stigmem-manifest.json",
            allow_schemes=frozenset({"https", "http"}),
            skip_pin=True,
            follow_redirects=False,
        )
        assert len(client.calls) == 1
        assert client.calls[0]["url"].startswith("http://localhost:8765/")
        assert client.calls[0]["follow_redirects"] is False
        assert "extensions" not in client.calls[0]
