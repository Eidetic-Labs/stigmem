"""Ingest size caps + HTTP body-size limit (F-AVAIL-1)."""

import pytest
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import stigmem_node.body_limit as bl
from stigmem_node.models.facts import AssertRequest, FactValue

# --- Body-size limit middleware (isolated) ---------------------------------


async def _ok(_request):
    return PlainTextResponse("ok")


def _mini_app() -> Starlette:
    app = Starlette(routes=[Route("/x", _ok, methods=["POST"])])
    app.add_middleware(bl.BodySizeLimitMiddleware)
    return app


def test_body_over_limit_rejected(monkeypatch):
    monkeypatch.setattr(bl.settings, "max_request_body_bytes", 100)
    resp = TestClient(_mini_app()).post("/x", content=b"a" * 101)
    assert resp.status_code == 413


def test_body_under_limit_ok(monkeypatch):
    monkeypatch.setattr(bl.settings, "max_request_body_bytes", 100)
    resp = TestClient(_mini_app()).post("/x", content=b"a" * 50)
    assert resp.status_code == 200


def test_body_limit_disabled_when_zero(monkeypatch):
    monkeypatch.setattr(bl.settings, "max_request_body_bytes", 0)
    resp = TestClient(_mini_app()).post("/x", content=b"a" * 10_000)
    assert resp.status_code == 200


# --- Per-field caps (model) ------------------------------------------------


def test_entity_over_max_length_rejected():
    with pytest.raises(ValidationError):
        AssertRequest(
            entity="x" * 3000,
            relation="memory:note",
            value=FactValue(type="string", v="v"),
            source="agent:a",
        )


def test_normal_fields_accepted():
    req = AssertRequest(
        entity="user:1",
        relation="memory:note",
        value=FactValue(type="string", v="v"),
        source="agent:a",
    )
    assert req.entity == "user:1"


# --- Per-value cap (route, default 256 KiB) --------------------------------


def test_assert_oversized_value_rejected(client):
    big = "a" * 300_000  # > 256 KiB default cap, < 1 MiB body limit
    resp = client.post(
        "/v1/facts",
        json={
            "entity": "user:1",
            "relation": "memory:note",
            "value": {"type": "string", "v": big},
            "source": "agent:a",
            "scope": "local",
        },
    )
    assert resp.status_code == 413


def test_assert_normal_value_ok(client):
    resp = client.post(
        "/v1/facts",
        json={
            "entity": "user:1",
            "relation": "memory:note",
            "value": {"type": "string", "v": "ok"},
            "source": "agent:a",
            "scope": "local",
        },
    )
    assert resp.status_code in (200, 201)
