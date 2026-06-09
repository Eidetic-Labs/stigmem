"""Shared fact read-visibility primitive (tenant + projected garden)."""

import types

import stigmem_node.fact_visibility as fv


def test_fact_visible_tenant_isolation() -> None:
    scope = fv.ReadScope(tenant_id="A", enforce_gardens=True, visible_gardens=frozenset({"g1"}))
    assert scope.fact_visible(tenant_id="B", projected_garden_id=None) is False  # other tenant
    assert scope.fact_visible(tenant_id="A", projected_garden_id=None) is True  # own, no garden
    assert scope.fact_visible(tenant_id="A", projected_garden_id="g1") is True  # own, member
    assert scope.fact_visible(tenant_id="A", projected_garden_id="g2") is False  # own, non-member


def test_fact_visible_garden_ignored_when_not_enforced() -> None:
    scope = fv.ReadScope(tenant_id="A", enforce_gardens=False, visible_gardens=frozenset())
    assert scope.fact_visible(tenant_id="A", projected_garden_id="g2") is True  # garden ignored
    assert scope.fact_visible(tenant_id="B", projected_garden_id=None) is False  # tenant still on


def test_caller_read_scope_batches(monkeypatch) -> None:
    monkeypatch.setattr(fv, "garden_acl_enforced", lambda: True)
    monkeypatch.setattr(fv, "caller_visible_gardens", lambda ident: frozenset({"g1"}))
    s = fv.caller_read_scope(types.SimpleNamespace(tenant_id="A", entity_uri="u"))
    assert s.tenant_id == "A"
    assert s.enforce_gardens is True
    assert s.visible_gardens == frozenset({"g1"})


def test_caller_read_scope_no_garden_lookup_when_disabled(monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(fv, "garden_acl_enforced", lambda: False)
    monkeypatch.setattr(fv, "caller_visible_gardens", lambda ident: called.__setitem__("n", 1))
    s = fv.caller_read_scope(types.SimpleNamespace(tenant_id="A", entity_uri="u"))
    assert s.enforce_gardens is False
    assert s.visible_gardens == frozenset()
    assert called["n"] == 0  # no membership query when the boundary is not enforced


def test_visible_facts_where_member() -> None:
    scope = fv.ReadScope(
        tenant_id="A", enforce_gardens=True, visible_gardens=frozenset({"g2", "g1"})
    )
    frag, params = fv.visible_facts_where(scope)
    assert "f.tenant_id = ?" in frag
    assert "IN (?,?)" in frag
    assert params == ["A", "g1", "g2"]  # tenant + sorted gardens


def test_visible_facts_where_member_of_no_garden() -> None:
    scope = fv.ReadScope(tenant_id="A", enforce_gardens=True, visible_gardens=frozenset())
    frag, params = fv.visible_facts_where(scope)
    assert "IS NULL" in frag  # only garden-less facts visible
    assert "IN (" not in frag
    assert params == ["A"]


def test_visible_facts_where_not_enforced() -> None:
    scope = fv.ReadScope(tenant_id="A", enforce_gardens=False, visible_gardens=frozenset())
    frag, params = fv.visible_facts_where(scope)
    assert frag == " AND f.tenant_id = ?"
    assert params == ["A"]
