"""SSRF guard on webhook delivery (P-CONF-2).

A subscription's delivery_address is operator/attacker-controlled; the delivery
worker must refuse to POST to private/loopback/link-local/IMDS addresses and
must not follow redirects (which could re-target a validated URL).
"""

from unittest.mock import MagicMock

import stigmem_node.subscription_delivery as sd


def _event(addr: str) -> dict:
    return {
        "id": "e1",
        "subscription_id": "s1",
        "event_type": "fact.created",
        "delivery_address": addr,
    }


def test_webhook_blocks_imds_metadata_ip(monkeypatch):
    monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
    marked: list = []
    monkeypatch.setattr(sd, "_mark_delivered", lambda eid, sid: marked.append((eid, sid)))
    client_ctor = MagicMock()
    monkeypatch.setattr(sd.httpx, "Client", client_ctor)

    result = sd._deliver_webhook(_event("http://169.254.169.254/latest/meta-data/"), {})

    assert result is True  # stop retrying — never deliverable
    client_ctor.assert_not_called()  # no HTTP client constructed
    assert marked == [("e1", "s1")]


def test_webhook_blocks_loopback(monkeypatch):
    monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
    monkeypatch.setattr(sd, "_mark_delivered", lambda eid, sid: None)
    client_ctor = MagicMock()
    monkeypatch.setattr(sd.httpx, "Client", client_ctor)

    assert sd._deliver_webhook(_event("http://127.0.0.1:9000/hook"), {}) is True
    client_ctor.assert_not_called()


def test_webhook_sends_to_safe_url_without_following_redirects(monkeypatch):
    monkeypatch.setattr(sd, "_sanitize_payload", lambda e, p: {"ok": 1})
    monkeypatch.setattr(sd, "assert_safe_url", lambda *a, **k: None)  # treat as safe

    resp = MagicMock()
    resp.status_code = 200
    client = MagicMock()
    client.post.return_value = resp
    client_cm = MagicMock()
    client_cm.__enter__.return_value = client
    client_ctor = MagicMock(return_value=client_cm)
    monkeypatch.setattr(sd.httpx, "Client", client_ctor)

    result = sd._deliver_webhook(_event("https://example.com/hook"), {})

    assert result is True
    client.post.assert_called_once()
    assert client_ctor.call_args.kwargs.get("follow_redirects") is False
