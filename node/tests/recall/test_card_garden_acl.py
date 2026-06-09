"""Card fast-path enforces garden ACL (audit H1).

The memory-card fast-path aggregates an entity's fact values verbatim and
bypasses the ranker's per-fact garden filter. A non-member of a garden must
not receive a card built from that garden's facts.
"""

from types import SimpleNamespace

import stigmem_node.routes.recall.orchestration as orch
import stigmem_node.routes.recall.ranking as ranking
from stigmem_node.fact_visibility import ReadScope


class _Cursor:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def fetchall(self) -> list[dict]:
        return self._rows


class _Conn:
    def __init__(self, garden_ids: list[str]) -> None:
        self._garden_ids = garden_ids

    def execute(self, _sql: str, _params: tuple) -> _Cursor:
        # _caller_sees_all_card_gardens aliases the projected garden as "gid".
        return _Cursor([{"gid": g} for g in self._garden_ids])


def _identity() -> SimpleNamespace:
    return SimpleNamespace(tenant_id="default", entity_uri="user:outsider")


def _req() -> SimpleNamespace:
    return SimpleNamespace(scope="local")


def test_card_dropped_when_caller_cannot_see_a_contributing_garden(monkeypatch) -> None:
    monkeypatch.setattr(orch, "_is_tombstoned", lambda *a, **k: False)
    monkeypatch.setattr(orch, "garden_acl_enforced", lambda: True)
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
    monkeypatch.setattr(orch, "garden_acl_enforced", lambda: True)
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


def test_caller_sees_all_card_gardens_uses_projected_garden(monkeypatch) -> None:
    """A fact promoted into a restricted garden via fact_garden_membership (raw
    facts.garden_id NULL) must still be caught — checking the raw column alone
    served the card to a non-member (audit F-C, bypass of H1)."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE facts (id TEXT, entity TEXT, scope TEXT, tenant_id TEXT,"
        " confidence REAL, valid_until TEXT, quarantine_status TEXT, garden_id TEXT)"
    )
    conn.execute("CREATE TABLE fact_garden_membership (fact_id TEXT, garden_id TEXT)")
    # raw garden_id NULL; the effective garden comes only from the membership table.
    conn.execute(
        "INSERT INTO facts (id, entity, scope, tenant_id, confidence, valid_until,"
        " quarantine_status, garden_id) VALUES ('f1','e:x','local','default',1.0,NULL,NULL,NULL)"
    )
    conn.execute(
        "INSERT INTO fact_garden_membership (fact_id, garden_id) VALUES ('f1','restricted')"
    )
    monkeypatch.setattr(orch, "caller_can_see_garden", lambda gid, ident: False)
    ident = SimpleNamespace(tenant_id="default", entity_uri="user:outsider")

    # The projected garden "restricted" must be detected → caller can NOT see all.
    assert orch._caller_sees_all_card_gardens("e:x", "local", ident, conn, "z") is False


def test_filter_visible_gardens_drops_hidden(monkeypatch) -> None:
    monkeypatch.setattr(
        ranking,
        "caller_read_scope",
        lambda identity: ReadScope(
            tenant_id="t", enforce_gardens=True, visible_gardens=frozenset({"VISIBLE"})
        ),
    )
    facts = {
        "a": SimpleNamespace(garden_id=None),  # no garden → kept
        "b": SimpleNamespace(garden_id="VISIBLE"),  # member → kept
        "c": SimpleNamespace(garden_id="HIDDEN"),  # non-member → dropped
    }
    out = ranking._filter_visible_gardens(facts, _identity())
    assert set(out) == {"a", "b"}


def test_filter_visible_gardens_noop_when_disabled(monkeypatch) -> None:
    monkeypatch.setattr(
        ranking,
        "caller_read_scope",
        lambda identity: ReadScope(
            tenant_id="t", enforce_gardens=False, visible_gardens=frozenset()
        ),
    )
    facts = {"c": SimpleNamespace(garden_id="HIDDEN")}
    out = ranking._filter_visible_gardens(facts, _identity())
    assert set(out) == {"c"}  # unchanged when the recall garden filter is off
