"""Card fast-path enforces garden ACL (audit H1).

The memory-card fast-path aggregates an entity's fact values verbatim and
bypasses the ranker's per-fact garden filter. A non-member of a garden must
not receive a card built from that garden's facts.
"""

from types import SimpleNamespace

import stigmem_node.routes.recall.orchestration as orch


class _Cursor:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def fetchall(self) -> list[dict]:
        return self._rows


class _Conn:
    def __init__(self, garden_ids: list[str]) -> None:
        self._garden_ids = garden_ids

    def execute(self, _sql: str, _params: tuple) -> _Cursor:
        return _Cursor([{"garden_id": g} for g in self._garden_ids])


def _identity() -> SimpleNamespace:
    return SimpleNamespace(tenant_id="default", entity_uri="user:outsider")


def _req() -> SimpleNamespace:
    return SimpleNamespace(scope="local")


def test_card_dropped_when_caller_cannot_see_a_contributing_garden(monkeypatch) -> None:
    monkeypatch.setattr(orch, "_is_tombstoned", lambda *a, **k: False)
    monkeypatch.setattr(orch, "recall_filter_enabled", lambda: True)
    monkeypatch.setattr(orch, "caller_can_see_garden", lambda gid, ident: False)
    # The card must be dropped BEFORE materialization — guard get_fresh_card.
    reached = {"card": False}

    def _boom(*_a, **_k):
        reached["card"] = True
        raise AssertionError("get_fresh_card must not run for a hidden garden")

    monkeypatch.setattr(orch, "get_fresh_card", _boom)

    result = orch._build_card_for_entity("e:secret", ["f1"], _req(), _identity(), _Conn(["G"]), "z")
    assert result is None
    assert reached["card"] is False


def test_card_built_when_caller_sees_all_gardens(monkeypatch) -> None:
    monkeypatch.setattr(orch, "_is_tombstoned", lambda *a, **k: False)
    monkeypatch.setattr(orch, "recall_filter_enabled", lambda: True)
    monkeypatch.setattr(orch, "caller_can_see_garden", lambda gid, ident: True)
    card = SimpleNamespace(
        is_stale=False,
        has_contradictions=False,
        avg_confidence=0.99,
        summary="Entity: e\nFacts:\n  rel: v (conf=0.99)",
        refreshed_at="2026-01-01T00:00:00+00:00",
    )
    monkeypatch.setattr(orch, "get_fresh_card", lambda *a, **k: card)

    result = orch._build_card_for_entity("e:ok", ["f1"], _req(), _identity(), _Conn([]), "z")
    assert result is not None
    sf, owned = result
    assert sf.from_card is True
    assert owned == ["f1"]
