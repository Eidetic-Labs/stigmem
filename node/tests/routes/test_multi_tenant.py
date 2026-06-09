"""Multi-tenant isolation tests — Tenant A cannot read/write Tenant B data."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
import stigmem_node.tracing as tracing_mod
from stigmem_node.main import create_app
from stigmem_node.plugins.testing import stigmem_plugins

_PLUGIN_SRC = Path(__file__).resolve().parents[3] / "experimental" / "multi-tenant" / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

_PLUGIN = importlib.import_module("stigmem_plugin_multi_tenant")

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings
plugin_manifest = _PLUGIN.plugin_manifest

# ---------------------------------------------------------------------------
# Fixture: two authenticated tenants sharing one DB
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_two_tenants(tmp_path: object) -> Generator[tuple[TestClient, str, str], None, None]:
    """Single DB with two non-default keys and no multi-tenant plugin."""
    db_file = str(tmp_path) + "/mt.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, key_a, key_b

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


@pytest.fixture()
def default_two_tenants_with_gate(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str], None, None]:
    """Single DB with the env gate enabled but no multi-tenant plugin."""
    db_file = str(tmp_path) + "/mt-default-gate.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, key_a, key_b

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


@pytest.fixture()
def two_tenants(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str], None, None]:
    """Single DB, two tenant keys, and the multi-tenant plugin enabled."""
    db_file = str(tmp_path) + "/mt.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    with stigmem_plugins([plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c, key_a, key_b

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


# ---------------------------------------------------------------------------
# Fact isolation
# ---------------------------------------------------------------------------


def test_default_install_collapses_non_default_tenant_keys(
    default_two_tenants: tuple,
) -> None:
    """Without the plugin, all callers resolve into the default tenant."""
    client, key_a, key_b = default_two_tenants

    resp = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/agent/alice",
            "relation": "test:color",
            "value": {"type": "string", "v": "red"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 201
    fact_id = resp.json()["id"]

    me = client.get("/v1/me", headers={"Authorization": f"Bearer {key_a}"})
    assert me.status_code == 200
    assert me.json()["tenant_id"] == "default"

    assert (
        client.get(f"/v1/facts/{fact_id}", headers={"Authorization": f"Bearer {key_b}"}).status_code
        == 200
    )


def test_default_install_ignores_multi_tenant_environment_gate(
    default_two_tenants_with_gate: tuple,
) -> None:
    """The env gate cannot enable non-default tenant resolution by itself."""
    client, key_a, key_b = default_two_tenants_with_gate

    me_a = client.get("/v1/me", headers={"Authorization": f"Bearer {key_a}"})
    me_b = client.get("/v1/me", headers={"Authorization": f"Bearer {key_b}"})

    assert me_a.status_code == 200
    assert me_b.status_code == 200
    assert me_a.json()["tenant_id"] == "default"
    assert me_b.json()["tenant_id"] == "default"


def test_default_install_query_uses_single_default_partition(
    default_two_tenants: tuple,
) -> None:
    """Without the plugin, a non-default key does not create a private partition."""
    client, key_a, key_b = default_two_tenants

    resp = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/default-partition",
            "relation": "test:visible",
            "value": {"type": "string", "v": "shared-default"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 201

    query = client.get("/v1/facts", headers={"Authorization": f"Bearer {key_b}"})

    assert query.status_code == 200
    values = {fact["value"]["v"] for fact in query.json()["facts"]}
    assert values == {"shared-default"}


def test_tenant_a_fact_invisible_to_tenant_b(two_tenants: tuple) -> None:
    """GET /v1/facts/{id} returns 404 for a cross-tenant fact."""
    client, key_a, key_b = two_tenants

    resp = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/agent/alice",
            "relation": "test:color",
            "value": {"type": "string", "v": "red"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 201
    fact_id = resp.json()["id"]

    # Tenant A can read its own fact
    assert (
        client.get(f"/v1/facts/{fact_id}", headers={"Authorization": f"Bearer {key_a}"}).status_code
        == 200
    )

    # Tenant B gets 404
    assert (
        client.get(f"/v1/facts/{fact_id}", headers={"Authorization": f"Bearer {key_b}"}).status_code
        == 404
    )


def test_lint_is_tenant_scoped(two_tenants: tuple) -> None:
    """POST /v1/lint counts and reports only the caller's tenant (audit H4)."""
    client, key_a, key_b = two_tenants

    for key, src, ent, val in [
        (key_a, "agent:alice", "stigmem://test/alice-fact", "alice-only"),
        (key_b, "agent:bob", "stigmem://test/bob-secret", "bob-only"),
    ]:
        resp = client.post(
            "/v1/facts",
            json={
                "entity": ent,
                "relation": "secret:value",
                "value": {"type": "string", "v": val},
                "source": src,
                "scope": "company",
            },
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 201, resp.text

    # Tenant A lints scope "company" — must see only its own fact, not tenant B's.
    r = client.post(
        "/v1/lint",
        json={"scope": "company"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["fact_count"] == 1  # alice's fact only, not bob's
    assert "bob-secret" not in r.text
    assert "bob-only" not in r.text


def test_synthesize_is_tenant_scoped(two_tenants: tuple) -> None:
    """GET /v1/scopes/{scope}/synthesize returns only the caller's tenant content.

    The route previously returned every tenant's full fact content for a scope —
    a Critical cross-tenant disclosure (sibling of H4, found by the adversarial
    review of the Wave-1 fixes).
    """
    client, key_a, key_b = two_tenants

    for key, src, ent, val in [
        (key_a, "agent:alice", "stigmem://test/alice-syn", "alice-only-syn"),
        (key_b, "agent:bob", "stigmem://test/bob-secret-syn", "bob-only-syn"),
    ]:
        resp = client.post(
            "/v1/facts",
            json={
                "entity": ent,
                "relation": "memory:knows",
                "value": {"type": "string", "v": val},
                "source": src,
                "scope": "company",
            },
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 201, resp.text

    r = client.get(
        "/v1/scopes/company/synthesize",
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["fact_count"] == 1  # alice's fact only
    assert "bob-secret-syn" not in r.text  # tenant B's content not disclosed
    assert "bob-only-syn" not in r.text


def test_get_intent_is_tenant_scoped(two_tenants: tuple) -> None:
    """GET /v1/intents/{id} must not reconstruct another tenant's intent
    (cross-tenant sibling, found by the adversarial review)."""
    client, key_a, key_b = two_tenants

    create = client.post(
        "/v1/intents",
        json={
            "id": "intent:bob-secret",
            "from": "stigmem://test/agent/bob",
            "to": ["stigmem://test/agent/carol"],
            "goal": "bob-secret-intent-goal",
        },
        headers={"Authorization": f"Bearer {key_b}"},
    )
    assert create.status_code in (200, 201), create.text

    # Tenant A cannot read tenant B's intent.
    r = client.get("/v1/intents/intent:bob-secret", headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 404
    assert "bob-secret-intent-goal" not in r.text
    # Tenant B can read its own.
    rb = client.get("/v1/intents/intent:bob-secret", headers={"Authorization": f"Bearer {key_b}"})
    assert rb.status_code == 200


def test_instruction_manifest_is_tenant_isolated(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A manifest published for an agent slug in one tenant must not be visible
    to — or collide with — another tenant. Closes the control-plane override
    (adversarial H2-SIBLING-1): the instruction tables were keyed by agent_id
    alone, so tenant A could supersede tenant B's manifest for 'support'.

    Self-contained: needs BOTH the multi-tenant and lazy-instruction plugins.
    """
    feature_src = (
        Path(__file__).resolve().parents[3] / "experimental" / "lazy-instruction-discovery" / "src"
    )
    if str(feature_src) not in sys.path:
        sys.path.insert(0, str(feature_src))
    instr = importlib.import_module("stigmem_plugin_lazy_instruction_discovery")

    db_file = str(tmp_path) + "/mt_instr.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings
    agent = "support"  # non-UUID slug: previously shared across tenants

    def _body(unit: str) -> dict:
        return {
            "version": "v1",
            "entries": [
                {"name": unit, "description": unit, "path": "/dev/null", "load_triggers": {}}
            ],
            "skip_coverage_gate": True,
        }

    try:
        admin_a = create_api_key("agent:admin-a", ["read", "write", "admin"], tenant_id="tenant-a")
        admin_b = create_api_key("agent:admin-b", ["read", "write", "admin"], tenant_id="tenant-b")
        monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
        monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ENABLED", "true")
        monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_MANIFEST_PUBLISH", "true")
        monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_INSTRUCTION_RECALL", "true")
        monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_FILE_PATH_ENTRIES", "true")
        instr_manifest = instr.plugin_manifest()
        with stigmem_plugins([plugin_manifest(), instr_manifest]):
            app = create_app()
            app.include_router(instr_manifest.routes[0])
            with TestClient(app, raise_server_exceptions=True) as client:
                ra = client.put(
                    f"/v1/agents/{agent}/instruction-manifest",
                    json=_body("unit-a"),
                    headers={"Authorization": f"Bearer {admin_a}"},
                )
                assert ra.status_code == 200, ra.text
                # Same agent slug + version in tenant B must NOT be a cross-tenant 409.
                rb = client.put(
                    f"/v1/agents/{agent}/instruction-manifest",
                    json=_body("unit-b-secret"),
                    headers={"Authorization": f"Bearer {admin_b}"},
                )
                assert rb.status_code == 200, rb.text

                ga = client.get(
                    f"/v1/agents/{agent}/instruction-manifest",
                    headers={"Authorization": f"Bearer {admin_a}"},
                )
                assert ga.status_code == 200
                assert [e["name"] for e in ga.json()["entries"]] == ["unit-a"]  # only its own
                assert "unit-b-secret" not in ga.text

                gb = client.get(
                    f"/v1/agents/{agent}/instruction-manifest",
                    headers={"Authorization": f"Bearer {admin_b}"},
                )
                assert gb.status_code == 200
                assert [e["name"] for e in gb.json()["entries"]] == ["unit-b-secret"]
    finally:
        settings_module.settings = original
        auth_mod.settings = original
        db_mod.settings = original


def test_entity_aliases_are_tenant_isolated(two_tenants: tuple) -> None:
    """A semantic alias registered by one tenant must not be listable, deletable,
    or resolvable by another (adversarial entity_aliases / resolver Layer-2)."""
    client, key_a, key_b = two_tenants

    ra = client.post(
        "/v1/aliases",
        json={"raw_uri": "stigmem://test/agent/a-old", "canonical_uri": "stigmem://test/agent/a"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert ra.status_code == 201, ra.text
    raw = ra.json()["raw_uri"]  # normalized form

    # Tenant B does not see it; tenant A does.
    lb = client.get("/v1/aliases", headers={"Authorization": f"Bearer {key_b}"})
    assert lb.status_code == 200
    assert all(r["raw_uri"] != raw for r in lb.json())
    la = client.get("/v1/aliases", headers={"Authorization": f"Bearer {key_a}"})
    assert any(r["raw_uri"] == raw for r in la.json())

    # Tenant B cannot delete tenant A's alias.
    from urllib.parse import quote

    db = client.delete(
        f"/v1/aliases/{quote(raw, safe='')}", headers={"Authorization": f"Bearer {key_b}"}
    )
    assert db.status_code == 404
    # Still present for tenant A.
    la2 = client.get("/v1/aliases", headers={"Authorization": f"Bearer {key_a}"})
    assert any(r["raw_uri"] == raw for r in la2.json())


def test_entity_resolve_is_tenant_scoped(two_tenants: tuple) -> None:
    """GET /v1/entities/resolve must not confirm existence of, or enumerate,
    another tenant's entities (adversarial F-H4-S3 cross-tenant enumeration)."""
    client, key_a, key_b = two_tenants

    client.post(
        "/v1/facts",
        json={
            "entity": "user:zzz-secret-resolve",
            "relation": "memory:knows",
            "value": {"type": "string", "v": "x"},
            "source": "agent:alice",
            "scope": "company",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )

    # Tenant B: exact URI must not be confirmed, and fuzzy must not surface it.
    rb = client.get(
        "/v1/entities/resolve",
        params={"uri": "user:zzz-secret-resolve"},
        headers={"Authorization": f"Bearer {key_b}"},
    )
    assert rb.status_code == 200, rb.text
    body_b = rb.json()
    # Existence not confirmed (Layer 1) and no fuzzy enumeration of A's entities
    # (Layer 3). The query/canonical fields just echo the caller's own input URI.
    assert body_b["layer1_match"] is False
    assert body_b["layer3_candidates"] == []

    # Tenant A resolves its own entity.
    ra = client.get(
        "/v1/entities/resolve",
        params={"uri": "user:zzz-secret-resolve"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert ra.status_code == 200, ra.text
    assert ra.json()["layer1_match"] is True


def test_tenant_b_query_returns_empty(two_tenants: tuple) -> None:
    """GET /v1/facts query for Tenant B returns no Tenant A facts."""
    client, key_a, key_b = two_tenants

    # Tenant A writes a fact
    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/agent/alice",
            "relation": "test:size",
            "value": {"type": "number", "v": 42},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )

    resp = client.get("/v1/facts", headers={"Authorization": f"Bearer {key_b}"})
    assert resp.status_code == 200
    assert resp.json()["facts"] == []


def test_tenants_see_only_their_own_facts(two_tenants: tuple) -> None:
    """Each tenant's query returns only its own facts, not the other's."""
    client, key_a, key_b = two_tenants

    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/x",
            "relation": "test:owner",
            "value": {"type": "string", "v": "alice"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/x",
            "relation": "test:owner",
            "value": {"type": "string", "v": "bob"},
            "source": "agent:bob",
        },
        headers={"Authorization": f"Bearer {key_b}"},
    )

    resp_a = client.get("/v1/facts", headers={"Authorization": f"Bearer {key_a}"})
    resp_b = client.get("/v1/facts", headers={"Authorization": f"Bearer {key_b}"})

    values_a = {f["value"]["v"] for f in resp_a.json()["facts"]}
    values_b = {f["value"]["v"] for f in resp_b.json()["facts"]}

    assert values_a == {"alice"}
    assert values_b == {"bob"}


def test_recall_scoped_by_tenant(two_tenants: tuple) -> None:
    """POST /v1/recall returns only the caller tenant's facts."""
    client, key_a, key_b = two_tenants

    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/recall/a",
            "relation": "memory:note",
            "value": {"type": "string", "v": "a8 tenant alice recall marker"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/recall/b",
            "relation": "memory:note",
            "value": {"type": "string", "v": "a8 tenant bob recall marker"},
            "source": "agent:bob",
        },
        headers={"Authorization": f"Bearer {key_b}"},
    )

    resp_a = client.post(
        "/v1/recall",
        json={"query": "a8 tenant recall marker", "scope": "local"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    resp_b = client.post(
        "/v1/recall",
        json={"query": "a8 tenant recall marker", "scope": "local"},
        headers={"Authorization": f"Bearer {key_b}"},
    )

    assert resp_a.status_code == 200
    assert resp_b.status_code == 200
    values_a = {fact["fact"]["value"]["v"] for fact in resp_a.json()["facts"]}
    values_b = {fact["fact"]["value"]["v"] for fact in resp_b.json()["facts"]}
    assert any("a8 tenant alice recall marker" in value for value in values_a)
    assert all("a8 tenant bob recall marker" not in value for value in values_a)
    assert any("a8 tenant bob recall marker" in value for value in values_b)
    assert all("a8 tenant alice recall marker" not in value for value in values_b)


class _FakeSpan:
    def __init__(self) -> None:
        self.attributes: dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value


class _FakeTracer:
    def __init__(self) -> None:
        self.last_span = _FakeSpan()

    def start_as_current_span(self, _name: str) -> Any:
        from collections.abc import Iterator
        from contextlib import contextmanager

        @contextmanager
        def _cm() -> Iterator[_FakeSpan]:
            yield self.last_span

        return _cm()


def test_recall_trace_span_uses_resolved_tenant(two_tenants: tuple) -> None:
    """Recall tracing labels use the plugin-resolved tenant context."""
    client, key_a, _key_b = two_tenants
    saved_enabled = tracing_mod._OTEL_ENABLED
    saved_tracer = tracing_mod._tracer
    tracer = _FakeTracer()
    tracing_mod._OTEL_ENABLED = True
    tracing_mod._tracer = tracer
    try:
        resp = client.post(
            "/v1/recall",
            json={"query": "trace tenant", "scope": "local"},
            headers={"Authorization": f"Bearer {key_a}"},
        )
    finally:
        tracing_mod._OTEL_ENABLED = saved_enabled
        tracing_mod._tracer = saved_tracer

    assert resp.status_code == 200
    assert tracer.last_span.attributes["stigmem.tenant"] == "tenant-a"


def test_subscription_fan_out_scoped_by_tenant(two_tenants: tuple) -> None:
    """Background subscription fan-out does not enqueue cross-tenant events."""
    client, key_a, key_b = two_tenants

    sub_resp = client.post(
        "/v1/subscriptions",
        json={
            "target": "local",
            "on_change": "webhook",
            "delivery_address": "https://tenant-a.example/hook",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert sub_resp.status_code == 201
    sub_id = sub_resp.json()["id"]

    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/subscription/b",
            "relation": "test:event",
            "value": {"type": "string", "v": "tenant-b event"},
            "source": "agent:bob",
        },
        headers={"Authorization": f"Bearer {key_b}"},
    )
    with db_mod.db() as conn:
        cross_tenant_events = conn.execute(
            "SELECT * FROM subscription_events WHERE subscription_id=?",
            (sub_id,),
        ).fetchall()
    assert cross_tenant_events == []

    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/subscription/a",
            "relation": "test:event",
            "value": {"type": "string", "v": "tenant-a event"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    with db_mod.db() as conn:
        own_events = conn.execute(
            "SELECT * FROM subscription_events WHERE subscription_id=?",
            (sub_id,),
        ).fetchall()
    assert len(own_events) == 1


# ---------------------------------------------------------------------------
# Garden isolation
# ---------------------------------------------------------------------------


def test_default_install_uses_one_garden_namespace(
    default_two_tenants: tuple,
) -> None:
    """Without the plugin, non-default keys share the default garden namespace."""
    client, key_a, key_b = default_two_tenants

    resp = client.post(
        "/v1/gardens",
        json={"slug": "shared-default-garden", "name": "Shared Default", "scope": "company"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 201

    list_resp = client.get("/v1/gardens", headers={"Authorization": f"Bearer {key_b}"})
    get_resp = client.get(
        "/v1/gardens/shared-default-garden",
        headers={"Authorization": f"Bearer {key_b}"},
    )

    assert list_resp.status_code == 200
    assert [garden["slug"] for garden in list_resp.json()] == ["shared-default-garden"]
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Shared Default"


def test_garden_invisible_cross_tenant(two_tenants: tuple) -> None:
    """Tenant B cannot see Tenant A's garden by slug or in listing."""
    client, key_a, key_b = two_tenants

    resp = client.post(
        "/v1/gardens",
        json={"slug": "alpha-garden", "name": "Alpha", "scope": "company"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 201

    # Tenant B listing is empty
    resp_list = client.get("/v1/gardens", headers={"Authorization": f"Bearer {key_b}"})
    assert resp_list.status_code == 200
    assert resp_list.json() == []

    # Tenant B cannot GET by slug
    resp_get = client.get("/v1/gardens/alpha-garden", headers={"Authorization": f"Bearer {key_b}"})
    assert resp_get.status_code == 404


def test_garden_slug_can_be_reused_across_tenants(two_tenants: tuple) -> None:
    """The same slug is usable independently by both tenants."""
    client, key_a, key_b = two_tenants

    r_a = client.post(
        "/v1/gardens",
        json={"slug": "shared-slug", "name": "Tenant A Garden", "scope": "company"},
        headers={"Authorization": f"Bearer {key_a}"},
    )
    r_b = client.post(
        "/v1/gardens",
        json={"slug": "shared-slug", "name": "Tenant B Garden", "scope": "company"},
        headers={"Authorization": f"Bearer {key_b}"},
    )
    assert r_a.status_code == 201
    assert r_b.status_code == 201

    # Each tenant sees only their version
    ga = client.get("/v1/gardens/shared-slug", headers={"Authorization": f"Bearer {key_a}"}).json()
    gb = client.get("/v1/gardens/shared-slug", headers={"Authorization": f"Bearer {key_b}"}).json()
    assert ga["name"] == "Tenant A Garden"
    assert gb["name"] == "Tenant B Garden"


def test_tenant_a_cannot_write_to_tenant_b_garden(two_tenants: tuple) -> None:
    """Tenant A cannot assert a fact into Tenant B's garden URI."""
    client, key_a, key_b = two_tenants

    # Tenant B creates a garden
    r = client.post(
        "/v1/gardens",
        json={"slug": "b-private", "name": "B Private", "scope": "company"},
        headers={"Authorization": f"Bearer {key_b}"},
    )
    assert r.status_code == 201
    garden_id = r.json()["garden_id"]

    # Tenant A tries to write into it — should 404 (garden not visible across tenants)
    resp = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/e",
            "relation": "test:x",
            "value": {"type": "string", "v": "v"},
            "source": "agent:alice",
            "scope": "company",
            "garden_id": garden_id,
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Audit isolation
# ---------------------------------------------------------------------------


def test_default_install_uses_one_audit_partition(default_two_tenants: tuple) -> None:
    """Without the plugin, audit entries are visible within the default tenant."""
    client, key_a, key_b = default_two_tenants

    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/default-audit",
            "relation": "test:audit",
            "value": {"type": "string", "v": "shared"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )

    resp_b = client.get("/v1/audit", headers={"Authorization": f"Bearer {key_b}"})

    assert resp_b.status_code == 200
    assert len(resp_b.json()["entries"]) == 1


def test_audit_scoped_by_tenant(two_tenants: tuple) -> None:
    """Audit log only returns entries for the caller's tenant."""
    client, key_a, key_b = two_tenants

    # Tenant A writes a fact
    client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://test/audit-entity",
            "relation": "test:q",
            "value": {"type": "string", "v": "1"},
            "source": "agent:alice",
        },
        headers={"Authorization": f"Bearer {key_a}"},
    )

    resp_a = client.get("/v1/audit", headers={"Authorization": f"Bearer {key_a}"})
    resp_b = client.get("/v1/audit", headers={"Authorization": f"Bearer {key_b}"})

    assert resp_a.status_code == 200
    assert len(resp_a.json()["entries"]) == 1

    assert resp_b.status_code == 200
    assert resp_b.json()["entries"] == []
