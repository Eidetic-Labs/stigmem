"""F-AVAIL-3: rate-limit dimension coverage + subscription count cap."""

import stigmem_node.routes.subscriptions as subs
from stigmem_node.rate_limit import _dimension

# --- rate-limit dimension catch-all ----------------------------------------


def test_known_dimensions_unchanged():
    assert _dimension("/v1/facts", "POST") == "fact_write"
    assert _dimension("/v1/facts", "GET") == "fact_read"
    assert _dimension("/v1/admin/keys", "POST") == "admin_action"


def test_uncovered_endpoints_now_default_covered():
    # Previously returned None (unbounded); now mapped by method.
    assert _dimension("/v1/subscriptions", "POST") == "fact_write"
    assert _dimension("/v1/synthesize", "POST") == "fact_write"
    assert _dimension("/v1/graph", "GET") == "fact_read"
    assert _dimension("/v1/gardens", "DELETE") == "fact_write"


def test_options_still_exempt():
    assert _dimension("/v1/anything", "OPTIONS") is None


# --- subscription count cap ------------------------------------------------


def test_subscription_count_cap(client, monkeypatch):
    monkeypatch.setattr(subs._settings_pkg.settings, "max_subscriptions_per_principal", 2)

    def _create(i: int):
        return client.post(
            "/v1/subscriptions",
            json={
                "target": "user:1",
                "on_change": "webhook",
                "delivery_address": f"https://example.com/hook{i}",
            },
        )

    assert _create(0).status_code == 201
    assert _create(1).status_code == 201
    resp = _create(2)
    assert resp.status_code == 429
    assert "limit reached" in resp.json()["detail"]


def test_subscription_cap_disabled_when_zero(client, monkeypatch):
    monkeypatch.setattr(subs._settings_pkg.settings, "max_subscriptions_per_principal", 0)
    for i in range(3):
        resp = client.post(
            "/v1/subscriptions",
            json={
                "target": "user:1",
                "on_change": "webhook",
                "delivery_address": f"https://example.com/hook{i}",
            },
        )
        assert resp.status_code == 201
