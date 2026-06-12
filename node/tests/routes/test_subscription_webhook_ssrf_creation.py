"""Creation-time SSRF guard + https-only default for webhook subscriptions.

GHSA-5p3m-vhh6-9236 residual recommendations:
  (1) Validate ``delivery_address`` at subscription CREATION time — reject an
      unsafe webhook URL with 400 rather than silently storing it and blocking
      only at delivery.
  (2) https-only by default — an ``http://`` webhook delivery_address requires
      the explicit operator opt-in ``STIGMEM_WEBHOOK_ALLOW_INSECURE_HTTP=true``.

These complement the already-shipped delivery-time guard (PR #707).
"""

from __future__ import annotations

import stigmem_node.routes.subscriptions as subs_route
import stigmem_node.settings as settings_module
import stigmem_node.subscription_delivery as sd


def _post(client, *, on_change="webhook", delivery_address, target="local"):
    return client.post(
        "/v1/subscriptions",
        json={
            "target": target,
            "on_change": on_change,
            "delivery_address": delivery_address,
        },
    )


def _stored_count(delivery_address: str) -> int:
    import stigmem_node.db as db_mod

    with db_mod.db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM subscriptions WHERE delivery_address=?",
            (delivery_address,),
        ).fetchone()
    return int(row["n"])


# ---------------------------------------------------------------------------
# (a) loopback webhook → 400 at CREATE, row NOT stored
# ---------------------------------------------------------------------------


def test_create_webhook_loopback_rejected_and_not_stored(client) -> None:
    addr = "http://127.0.0.1:9999/x"
    resp = _post(client, delivery_address=addr)
    assert resp.status_code == 400, resp.text
    assert "unsafe webhook delivery_address" in resp.json()["detail"]
    # Reject, not store-then-block: the row must never have been inserted.
    assert _stored_count(addr) == 0


# ---------------------------------------------------------------------------
# (b) private + IMDS addresses → 400
# ---------------------------------------------------------------------------


def test_create_webhook_private_rejected(client) -> None:
    resp = _post(client, delivery_address="http://10.0.0.5/x")
    assert resp.status_code == 400, resp.text
    assert _stored_count("http://10.0.0.5/x") == 0


def test_create_webhook_imds_rejected(client) -> None:
    addr = "http://169.254.169.254/latest/meta-data/"
    resp = _post(client, delivery_address=addr)
    assert resp.status_code == 400, resp.text
    assert _stored_count(addr) == 0


# ---------------------------------------------------------------------------
# (c) safe https → 201 (still works)
# ---------------------------------------------------------------------------


def test_create_webhook_safe_https_allowed(client, monkeypatch) -> None:
    # Avoid network dependence: treat the safe https URL as resolving safely,
    # mirroring the delivery-time tests' assert_safe_url monkeypatch.
    monkeypatch.setattr(subs_route, "assert_safe_url", lambda *a, **k: None)
    resp = _post(client, delivery_address="https://example.com/hook")
    assert resp.status_code == 201, resp.text
    assert resp.json()["delivery_address"] == "https://example.com/hook"


# ---------------------------------------------------------------------------
# (d) https-only default: http to a PUBLIC host → 400 by default;
#     allowed when webhook_allow_insecure_http=True
# ---------------------------------------------------------------------------


def test_create_webhook_http_public_rejected_by_default(client, monkeypatch) -> None:
    # Make resolution/private-range checks pass so the ONLY thing that can fail
    # is the scheme gate — proving https-only is enforced at creation.
    def fake_assert(url, *, allow_schemes=frozenset({"https"})):
        from urllib.parse import urlparse

        if urlparse(url).scheme not in allow_schemes:
            raise ValueError(f"Disallowed URL scheme: {urlparse(url).scheme!r}")

    monkeypatch.setattr(subs_route, "assert_safe_url", fake_assert)
    # default: webhook_allow_insecure_http is False
    monkeypatch.setattr(settings_module.settings, "webhook_allow_insecure_http", False)
    resp = _post(client, delivery_address="http://example.com/hook")
    assert resp.status_code == 400, resp.text
    assert "scheme" in resp.json()["detail"].lower()
    assert _stored_count("http://example.com/hook") == 0


def test_create_webhook_http_public_allowed_with_optin(client, monkeypatch) -> None:
    def fake_assert(url, *, allow_schemes=frozenset({"https"})):
        from urllib.parse import urlparse

        if urlparse(url).scheme not in allow_schemes:
            raise ValueError(f"Disallowed URL scheme: {urlparse(url).scheme!r}")

    monkeypatch.setattr(subs_route, "assert_safe_url", fake_assert)
    monkeypatch.setattr(settings_module.settings, "webhook_allow_insecure_http", True)
    resp = _post(client, delivery_address="http://example.com/hook")
    assert resp.status_code == 201, resp.text
    assert resp.json()["delivery_address"] == "http://example.com/hook"


# ---------------------------------------------------------------------------
# (e) wake subscription with identity-URI delivery_address is NOT SSRF-checked
# ---------------------------------------------------------------------------


def test_create_wake_identity_uri_not_ssrf_checked(client, monkeypatch) -> None:
    # If the wake path were (wrongly) routed through assert_safe_url it would
    # raise on this non-URL identity URI; make assert_safe_url blow up loudly so
    # any accidental call fails the test.
    def boom(*a, **k):
        raise AssertionError("assert_safe_url must not be called for wake subscriptions")

    monkeypatch.setattr(subs_route, "assert_safe_url", boom)
    resp = _post(
        client,
        on_change="wake",
        delivery_address="stigmem://test/agent/alice",
        target="local",
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["on_change"] == "wake"


# ---------------------------------------------------------------------------
# (f) delivery-time https-only by default: an http address that somehow got
#     stored is blocked at delivery under the default setting.
# ---------------------------------------------------------------------------


def test_delivery_blocks_http_scheme_by_default(monkeypatch) -> None:
    # Default setting: webhook_allow_insecure_http is False → https-only.
    monkeypatch.setattr(settings_module.settings, "webhook_allow_insecure_http", False)
    monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
    marked: list = []
    monkeypatch.setattr(sd, "_mark_delivered", lambda eid, sid: marked.append((eid, sid)))

    from unittest.mock import MagicMock

    client_ctor = MagicMock()
    monkeypatch.setattr(sd.httpx, "Client", client_ctor)

    event = {
        "id": "e1",
        "subscription_id": "s1",
        "event_type": "fact.created",
        # public host, but http scheme — blocked by https-only default before any
        # network resolution happens.
        "delivery_address": "http://example.com/hook",
    }
    result = sd._deliver_webhook(event, {})

    assert result is True  # stop retrying — scheme can never become deliverable
    client_ctor.assert_not_called()
    assert marked == [("e1", "s1")]
