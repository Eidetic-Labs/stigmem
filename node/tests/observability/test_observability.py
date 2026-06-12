"""Observability smoke tests — Phase 13.

Verifies that:
- /metrics returns valid Prometheus text after a smoke workload.
- fact_write, fact_read, recall_ranker_duration, and audit_event counters/histograms
  are present and non-zero after exercising the relevant routes.
- OTel tracing no-ops cleanly when the SDK is absent / disabled.

M11 / F-AVAIL-1 update: /metrics now requires the admin capability by default.
All tests that scrape /metrics must present an admin bearer token.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod

create_api_key = auth_mod.create_api_key

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _metric_lines(metrics_text: str, prefix: str) -> list[str]:
    return [
        line
        for line in metrics_text.splitlines()
        if line.startswith(prefix) and not line.startswith("#")
    ]


def _metric_total(metrics_text: str, prefix: str) -> float:
    return sum(float(line.split()[-1]) for line in _metric_lines(metrics_text, prefix))


def _metrics_headers(admin_key: str) -> dict[str, str]:
    """Return Authorization header for /metrics scrape."""
    return {"Authorization": f"Bearer {admin_key}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_metrics_endpoint_returns_ok(authed_client: tuple[TestClient, str]) -> None:
    """GET /metrics must return 200 with admin credentials (M11: auth required by default)."""
    c, _key = authed_client
    # Mint an admin key in the same DB context as authed_client.
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    resp = c.get("/metrics", headers=_metrics_headers(admin_key))
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/")


@pytest.fixture
def _require_prometheus() -> None:
    """Skip test if prometheus_client is not installed."""
    try:
        import prometheus_client  # noqa: F401
    except ImportError:
        pytest.skip("prometheus_client not installed")


def test_metrics_after_fact_write(
    authed_client: tuple[TestClient, str],
    _require_prometheus: None,
) -> None:
    """stigmem_fact_write_total must increment after POST /v1/facts."""
    c, key = authed_client
    headers = {"Authorization": f"Bearer {key}"}
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    mheaders = _metrics_headers(admin_key)

    before = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_fact_write_total")

    c.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/thing/obs-1",
            "relation": "obs:label",
            "value": {"type": "text", "v": "observability test"},
            "source": "stigmem://test/agent/obs",
            "scope": "local",
        },
        headers=headers,
    )

    after = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_fact_write_total")
    assert after > before, f"stigmem_fact_write_total did not increment: {before} → {after}"


def test_metrics_after_fact_read(
    authed_client: tuple[TestClient, str],
    _require_prometheus: None,
) -> None:
    """stigmem_fact_read_total must increment after GET /v1/facts."""
    c, key = authed_client
    headers = {"Authorization": f"Bearer {key}"}
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    mheaders = _metrics_headers(admin_key)

    before = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_fact_read_total")
    c.get("/v1/facts", headers=headers)
    after = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_fact_read_total")
    assert after > before, f"stigmem_fact_read_total did not increment: {before} → {after}"


def test_metrics_recall_ranker_histogram(
    authed_client: tuple[TestClient, str],
    _require_prometheus: None,
) -> None:
    """stigmem_recall_ranker_duration_seconds_count must increment after POST /v1/recall."""
    c, key = authed_client
    headers = {"Authorization": f"Bearer {key}"}
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    mheaders = _metrics_headers(admin_key)

    def _count(text: str) -> float:
        lines = _metric_lines(text, "stigmem_recall_ranker_duration_seconds_count")
        return sum(float(line.split()[-1]) for line in lines)

    before = _count(c.get("/metrics", headers=mheaders).text)
    c.post(
        "/v1/recall",
        json={"query": "observability test", "scope": "local", "token_budget": 1000},
        headers=headers,
    )
    after = _count(c.get("/metrics", headers=mheaders).text)
    assert after > before, f"recall ranker histogram count did not increment: {before} → {after}"


def test_metrics_audit_event_counter(
    authed_client: tuple[TestClient, str],
    _require_prometheus: None,
) -> None:
    """stigmem_audit_event_total must be present and > 0 after a write."""
    c, key = authed_client
    headers = {"Authorization": f"Bearer {key}"}
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    mheaders = _metrics_headers(admin_key)

    c.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/thing/obs-audit",
            "relation": "obs:label",
            "value": {"type": "text", "v": "audit test"},
            "source": "stigmem://test/agent/obs",
            "scope": "local",
        },
        headers=headers,
    )

    metrics_text = c.get("/metrics", headers=mheaders).text
    lines = _metric_lines(metrics_text, "stigmem_audit_event_total")
    assert lines, "stigmem_audit_event_total not found in /metrics after a write"
    assert any(float(line.split()[-1]) > 0 for line in lines), (
        f"All stigmem_audit_event_total counters are zero: {lines}"
    )


def test_contradiction_counter(
    authed_client: tuple[TestClient, str],
    _require_prometheus: None,
) -> None:
    """stigmem_contradiction_total must increment when two conflicting facts are written."""
    c, key = authed_client
    headers = {"Authorization": f"Bearer {key}"}
    admin_key = create_api_key("agent:metrics-scraper", ["admin"])
    mheaders = _metrics_headers(admin_key)

    payload_a = {
        "entity": "stigmem://test/thing/conflict-obs",
        "relation": "obs:value",
        "value": {"type": "text", "v": "version-A"},
        "source": "stigmem://test/agent/obs",
        "scope": "local",
    }
    payload_b = {**payload_a, "value": {"type": "text", "v": "version-B"}}

    c.post("/v1/facts", json=payload_a, headers=headers)
    before = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_contradiction_total")
    c.post("/v1/facts", json=payload_b, headers=headers)
    after = _metric_total(c.get("/metrics", headers=mheaders).text, "stigmem_contradiction_total")
    assert after > before, f"stigmem_contradiction_total did not increment: {before} → {after}"


def test_tracing_noop_when_disabled() -> None:
    """start_span must not raise even when OTel is disabled."""
    from stigmem_node.tracing import is_enabled, start_span

    assert not is_enabled(), "OTel should be disabled in tests (STIGMEM_OTEL_ENABLED not set)"
    with start_span("test.noop.span") as span:
        span.set_attribute("foo", "bar")
        span.add_event("test_event")
        span.record_exception(ValueError("ignored"))
    # Reaching here without exception confirms the no-op path is safe
