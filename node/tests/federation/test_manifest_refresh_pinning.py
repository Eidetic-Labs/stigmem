"""DNS-rebind pinning for the manifest-refresh + relay-manifest fetches (R-5 / F-SSRF1).

Two manifest fetches resolved a peer/wire-carried host then issued a bare
``httpx.get`` against the hostname, leaving the resolve-then-reconnect TOCTOU the
recurring pull path already closes via ``federation_pull._pinned_get``:

- ``identity.trust_store._try_fetch_manifest`` — reached on the recurring
  ``refresh_peer_manifests`` loop over every stored peer's entity_uri (AM1, the
  R-5 threat class).
- ``federation.origin_identity._fetch_relay_manifest`` — on the attacker-CHOSEN
  wire entity_uri (AM2).

These tests pin both: a host that rebinds to a private IP at fetch time is
refused (no request reaches the client), a genuinely-public host is fetched
against the pinned IP literal with Host + SNI preserved, and the loopback dev
bypass under ``federation_insecure`` still works.
"""

from __future__ import annotations

from typing import Any

import pytest

import stigmem_node.federation.origin_identity as origin_identity
import stigmem_node.identity.trust_store as trust_store


class _CapturedResponse:
    def __init__(self, body: dict[str, Any], status: int = 200) -> None:
        self._body = body
        self.status_code = status

    def json(self) -> dict[str, Any]:
        return self._body


def _recording_get(calls: list[dict[str, Any]], body: dict[str, Any]) -> Any:
    """Return a fake httpx.get that records each call's args."""

    def _get(url: str, **kwargs: Any) -> _CapturedResponse:
        calls.append({"url": url, **kwargs})
        return _CapturedResponse(body)

    return _get


# ---------------------------------------------------------------------------
# AM1 — trust_store._pinned_manifest_get (manifest-refresh loop)
# ---------------------------------------------------------------------------


class TestTrustStoreManifestFetchPinned:
    def test_private_rebind_refused_at_fetch_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A refresh target rebinding to a private IP is refused — no GET issued."""
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(trust_store.httpx, "get", _recording_get(calls, {}))
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("10.0.0.1", 0))],  # RFC1918 rebind target
        )

        with pytest.raises(ValueError, match="private/loopback"):
            trust_store._pinned_manifest_get(
                "https://rebind.evil/.well-known/stigmem-manifest.json",
                timeout=10.0,
                skip_pin=False,
            )
        assert calls == [], "pinned fetch must not reach the client on rebind"

    def test_public_host_targets_pinned_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A public host is fetched against the PINNED ip literal, Host + SNI preserved."""
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(trust_store.httpx, "get", _recording_get(calls, {}))
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))],
        )

        resp = trust_store._pinned_manifest_get(
            "https://peer.example:8443/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=False,
        )
        assert resp.status_code == 200
        assert len(calls) == 1
        call = calls[0]
        assert call["url"].startswith("https://8.8.8.8:8443/")
        assert call["headers"]["Host"] == "peer.example:8443"
        assert call["extensions"]["sni_hostname"] == "peer.example"
        assert call["follow_redirects"] is False

    def test_loopback_dev_skips_pin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Under federation_insecure the refresh fetch is NOT pinned (dev bypass)."""

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("getaddrinfo must not be called when pin is skipped")

        monkeypatch.setattr("stigmem_node.utility.net_util.socket.getaddrinfo", _boom)
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(trust_store.httpx, "get", _recording_get(calls, {}))

        trust_store._pinned_manifest_get(
            "http://localhost:8765/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=True,
        )
        assert len(calls) == 1
        assert calls[0]["url"] == "http://localhost:8765/.well-known/stigmem-manifest.json"
        assert calls[0]["follow_redirects"] is False
        assert "extensions" not in calls[0]


# ---------------------------------------------------------------------------
# AM2 — origin_identity._pinned_relay_manifest_get (wire entity_uri)
# ---------------------------------------------------------------------------


class TestRelayManifestFetchPinned:
    def test_private_rebind_refused_at_fetch_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A wire entity_uri rebinding to IMDS is refused — no GET issued."""
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(origin_identity.httpx, "get", _recording_get(calls, {}))
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))],  # IMDS
        )

        with pytest.raises(ValueError, match="private/loopback"):
            origin_identity._pinned_relay_manifest_get(
                "https://rebind.evil/.well-known/stigmem-manifest.json",
                timeout=10.0,
                skip_pin=False,
            )
        assert calls == [], "pinned fetch must not reach the client on rebind"

    def test_public_host_targets_pinned_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A public host is fetched against the PINNED ip literal, Host + SNI preserved."""
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(origin_identity.httpx, "get", _recording_get(calls, {}))
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("1.1.1.1", 0))],
        )

        resp = origin_identity._pinned_relay_manifest_get(
            "https://origin.example/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=False,
        )
        assert resp.status_code == 200
        assert len(calls) == 1
        call = calls[0]
        assert call["url"].startswith("https://1.1.1.1/")
        assert call["headers"]["Host"] == "origin.example"
        assert call["extensions"]["sni_hostname"] == "origin.example"
        assert call["follow_redirects"] is False

    def test_loopback_dev_skips_pin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Under federation_insecure the relay fetch is NOT pinned (dev bypass)."""

        def _boom(*a: Any, **k: Any) -> None:
            raise AssertionError("getaddrinfo must not be called when pin is skipped")

        monkeypatch.setattr("stigmem_node.utility.net_util.socket.getaddrinfo", _boom)
        calls: list[dict[str, Any]] = []
        monkeypatch.setattr(origin_identity.httpx, "get", _recording_get(calls, {}))

        origin_identity._pinned_relay_manifest_get(
            "http://127.0.0.1:8765/.well-known/stigmem-manifest.json",
            timeout=10.0,
            skip_pin=True,
        )
        assert len(calls) == 1
        assert calls[0]["url"] == "http://127.0.0.1:8765/.well-known/stigmem-manifest.json"
        assert calls[0]["follow_redirects"] is False
        assert "extensions" not in calls[0]
