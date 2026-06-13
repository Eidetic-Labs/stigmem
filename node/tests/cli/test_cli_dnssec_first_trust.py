"""CLI tests for the DNSSEC first-trust operator-confirm queue (Rev 6 I9 / 3b.9).

``stigmem federation dnssec {pending,confirm,reject}`` mirror the three admin-API
operations, calling the local node over HTTP (admin:federation) like the
register-peer subcommand. These tests bypass argparse and call the ``_cmd_*``
handlers directly with fabricated argparse.Namespace objects, mocking httpx —
the same pattern as test_cli_handlers_b2.py's federation tests.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

import pytest


def _args(**kwargs: object) -> argparse.Namespace:
    base: dict[str, object] = {"node_url": "http://local", "api_key": "admin-key"}
    base.update(kwargs)
    return argparse.Namespace(**base)


class _FakeResponse:
    def __init__(self, status_code: int, json_body: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}
        self.text = text or json.dumps(self._json)

    def json(self) -> Any:
        return self._json


def _patch_httpx(
    monkeypatch: pytest.MonkeyPatch,
    *,
    get_response: _FakeResponse | None = None,
    post_response: _FakeResponse | None = None,
    raises: Exception | None = None,
) -> dict:
    captured: dict = {}

    def fake_get(url: str, **kw: Any) -> _FakeResponse:
        captured["get_url"] = url
        captured["get_kwargs"] = kw
        if raises is not None:
            raise raises
        assert get_response is not None, f"unexpected GET {url}"
        return get_response

    def fake_post(url: str, **kw: Any) -> _FakeResponse:
        captured["post_url"] = url
        captured["post_json"] = kw.get("json")
        captured["post_kwargs"] = kw
        if raises is not None:
            raise raises
        assert post_response is not None, f"unexpected POST {url}"
        return post_response

    import httpx

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_post)
    return captured


# ---------------------------------------------------------------------------
# pending (list)
# ---------------------------------------------------------------------------


class TestDnssecPending:
    def test_lists_pending_rows(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_pending

        cap = _patch_httpx(
            monkeypatch,
            get_response=_FakeResponse(
                200,
                {
                    "pending": [
                        {
                            "entity_uri": "https://memory.acme.example/",
                            "node_id": "stigmem://node-a",
                            "candidate_key_fpr": "sha256:abc",
                            "source": "unsigned",
                            "relay_peer": "peer-x",
                            "seen_at": "2026-06-13T00:00:00Z",
                        }
                    ]
                },
            ),
        )
        rc = _cmd_federation_dnssec_pending(_args())
        assert rc == 0
        assert cap["get_url"] == "http://local/v1/federation/dnssec/pending"
        assert cap["get_kwargs"]["headers"]["Authorization"] == "Bearer admin-key"
        out = json.loads(capsys.readouterr().out)
        assert out["pending"][0]["candidate_key_fpr"] == "sha256:abc"

    def test_node_unreachable_returns_1(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_pending

        _patch_httpx(monkeypatch, raises=RuntimeError("conn refused"))
        rc = _cmd_federation_dnssec_pending(_args())
        assert rc == 1
        assert "cannot reach node" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# confirm (paste-to-confirm)
# ---------------------------------------------------------------------------


class TestDnssecConfirm:
    def _confirm_args(self, **o: object) -> argparse.Namespace:
        base: dict[str, object] = {
            "entity_uri": "https://memory.acme.example/",
            "node_id": "stigmem://node-a",
            "key_fpr": "sha256:abc",
        }
        base.update(o)
        return _args(**base)

    def test_matching_fpr_confirms_and_pins(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_confirm

        cap = _patch_httpx(
            monkeypatch,
            post_response=_FakeResponse(
                200,
                {
                    "entity_uri": "https://memory.acme.example/",
                    "node_id": "stigmem://node-a",
                    "key_fpr": "sha256:abc",
                    "host": "memory.acme.example",
                },
            ),
        )
        rc = _cmd_federation_dnssec_confirm(self._confirm_args())
        assert rc == 0
        assert cap["post_url"] == "http://local/v1/federation/dnssec/pending/confirm"
        # entity_uri travels in the BODY, never the URL.
        assert cap["post_json"] == {
            "entity_uri": "https://memory.acme.example/",
            "node_id": "stigmem://node-a",
            "key_fpr": "sha256:abc",
        }
        assert "confirmed and pinned" in capsys.readouterr().err

    def test_mismatched_fpr_does_not_trust(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_confirm

        _patch_httpx(monkeypatch, post_response=_FakeResponse(422, {"detail": "no match"}))
        rc = _cmd_federation_dnssec_confirm(self._confirm_args(key_fpr="sha256:wrong"))
        assert rc == 1
        assert "did not match" in capsys.readouterr().err

    def test_absent_row_returns_1(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_confirm

        _patch_httpx(monkeypatch, post_response=_FakeResponse(404, {"detail": "absent"}))
        rc = _cmd_federation_dnssec_confirm(self._confirm_args())
        assert rc == 1
        assert "no such pending" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# reject
# ---------------------------------------------------------------------------


class TestDnssecReject:
    def _reject_args(self, **o: object) -> argparse.Namespace:
        base: dict[str, object] = {
            "entity_uri": "https://memory.acme.example/",
            "node_id": "stigmem://node-a",
        }
        base.update(o)
        return _args(**base)

    def test_reject_clears_row(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_reject

        cap = _patch_httpx(
            monkeypatch,
            post_response=_FakeResponse(
                200,
                {
                    "entity_uri": "https://memory.acme.example/",
                    "node_id": "stigmem://node-a",
                    "rejected": True,
                },
            ),
        )
        rc = _cmd_federation_dnssec_reject(self._reject_args())
        assert rc == 0
        assert cap["post_url"] == "http://local/v1/federation/dnssec/pending/reject"
        assert cap["post_json"] == {
            "entity_uri": "https://memory.acme.example/",
            "node_id": "stigmem://node-a",
        }
        assert "rejected" in capsys.readouterr().err

    def test_reject_absent_row_returns_1(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from stigmem_node.cli import _cmd_federation_dnssec_reject

        _patch_httpx(monkeypatch, post_response=_FakeResponse(404, {"detail": "absent"}))
        rc = _cmd_federation_dnssec_reject(self._reject_args())
        assert rc == 1
        assert "no such pending" in capsys.readouterr().err
