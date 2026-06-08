"""Integration tests for Memory Garden CRUD, ACL enforcement, and membership API (spec §17)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from pytest import MonkeyPatch

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app
from stigmem_node.plugins import PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings
_MEMORY_GARDEN_ACL_SRC = (
    Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl" / "src"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FACT_PAYLOAD = {
    "entity": "stigmem://testnode/agent/alice",
    "relation": "memory:note",
    "value": {"type": "string", "v": "hello garden"},
    "source": "stigmem://testnode/agent/alice",
    "confidence": 1.0,
    "scope": "team",
}


def _make_authed_client(tmp_path: object, node_url: str = "http://testnode"):
    """Return (client, admin_key, reader_key, outsider_key) for an auth-enabled node."""
    db_file = str(tmp_path) + "/garden_test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url=node_url)
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings
    wk_mod.settings = test_settings
    admin_key = create_api_key("stigmem://testnode/agent/admin", ["read", "write"])
    reader_key = create_api_key("stigmem://testnode/agent/reader", ["read", "write"])
    # outsider has read-only so is_node_admin() returns False → garden ACL applies
    outsider_key = create_api_key("stigmem://testnode/agent/outsider", ["read"])
    app = create_app()
    client = TestClient(app, raise_server_exceptions=True)
    client.__enter__()
    return client, admin_key, reader_key, outsider_key, original


def _memory_garden_acl_manifest() -> PluginManifest:
    if str(_MEMORY_GARDEN_ACL_SRC) not in sys.path:
        sys.path.insert(0, str(_MEMORY_GARDEN_ACL_SRC))
    plugin = importlib.import_module("stigmem_plugin_memory_garden_acl")
    return plugin.plugin_manifest()


def _enable_acl_recall_filter(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("STIGMEM_MEMORY_GARDEN_ACL_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_MEMORY_GARDEN_ACL_APPLY_RECALL_FILTER", "true")


# ---------------------------------------------------------------------------
# Garden CRUD
# ---------------------------------------------------------------------------


class TestGardenCRUD:
    def test_create_returns_201(self, client: TestClient) -> None:
        r = client.post(
            "/v1/gardens", json={"slug": "my-garden", "name": "My Garden", "scope": "team"}
        )
        assert r.status_code == 201
        body = r.json()
        assert body["slug"] == "my-garden"
        assert body["name"] == "My Garden"
        assert body["scope"] == "team"
        assert body["id"]
        assert body["garden_id"].startswith("stigmem://")
        assert body["garden_id"].endswith("/garden/my-garden")

    def test_create_auto_adds_creator_as_admin(self, client: TestClient) -> None:
        r = client.post(
            "/v1/gardens", json={"slug": "auto-admin", "name": "Auto Admin", "scope": "local"}
        )
        assert r.status_code == 201
        body = r.json()
        assert len(body["members"]) == 1
        assert body["members"][0]["role"] == "admin"

    def test_create_invalid_slug_rejected(self, client: TestClient) -> None:
        r = client.post(
            "/v1/gardens", json={"slug": "UPPER_CASE", "name": "bad slug", "scope": "local"}
        )
        assert r.status_code == 422

    def test_create_duplicate_slug_409(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "dup-test", "name": "First", "scope": "local"})
        r = client.post(
            "/v1/gardens", json={"slug": "dup-test", "name": "Second", "scope": "local"}
        )
        assert r.status_code == 409

    def test_create_invalid_scope_rejected(self, client: TestClient) -> None:
        r = client.post("/v1/gardens", json={"slug": "bad-scope", "name": "Bad", "scope": "global"})
        assert r.status_code == 422

    def test_list_returns_owned_gardens(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "list-test", "name": "List Test", "scope": "team"})
        r = client.get("/v1/gardens")
        assert r.status_code == 200
        slugs = [g["slug"] for g in r.json()]
        assert "list-test" in slugs

    def test_get_by_slug(self, client: TestClient) -> None:
        client.post(
            "/v1/gardens", json={"slug": "get-test", "name": "Get Test", "scope": "company"}
        )
        r = client.get("/v1/gardens/get-test")
        assert r.status_code == 200
        assert r.json()["slug"] == "get-test"

    def test_get_by_uuid(self, client: TestClient) -> None:
        create_r = client.post(
            "/v1/gardens", json={"slug": "uuid-get", "name": "UUID Get", "scope": "local"}
        )
        garden_uuid = create_r.json()["id"]
        r = client.get(f"/v1/gardens/{garden_uuid}")
        assert r.status_code == 200
        assert r.json()["id"] == garden_uuid

    def test_get_nonexistent_404(self, client: TestClient) -> None:
        r = client.get("/v1/gardens/does-not-exist")
        assert r.status_code == 404

    def test_delete_garden(self, client: TestClient) -> None:
        client.post(
            "/v1/gardens", json={"slug": "to-delete", "name": "Delete Me", "scope": "local"}
        )
        r = client.delete("/v1/gardens/to-delete")
        assert r.status_code == 204
        assert client.get("/v1/gardens/to-delete").status_code == 404

    def test_description_optional(self, client: TestClient) -> None:
        r = client.post(
            "/v1/gardens",
            json={
                "slug": "with-desc",
                "name": "Described",
                "scope": "local",
                "description": "A note",
            },
        )
        assert r.status_code == 201
        assert r.json()["description"] == "A note"


# ---------------------------------------------------------------------------
# Membership API
# ---------------------------------------------------------------------------


class TestMembershipAPI:
    def test_list_members(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "mem-list", "name": "Mem List", "scope": "local"})
        r = client.get("/v1/gardens/mem-list/members")
        assert r.status_code == 200
        assert len(r.json()) == 1  # creator is admin

    def test_add_member(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "add-member", "name": "Add", "scope": "local"})
        r = client.post(
            "/v1/gardens/add-member/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "reader"},
        )
        assert r.status_code == 201
        assert r.json()["role"] == "reader"
        assert r.json()["entity_uri"] == "stigmem://testnode/agent/bob"

    def test_add_member_invalid_role_rejected(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "bad-role", "name": "Bad Role", "scope": "local"})
        r = client.post(
            "/v1/gardens/bad-role/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "superuser"},
        )
        assert r.status_code == 422

    def test_add_duplicate_member_409(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "dup-mem", "name": "Dup", "scope": "local"})
        client.post(
            "/v1/gardens/dup-mem/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "reader"},
        )
        r = client.post(
            "/v1/gardens/dup-mem/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "writer"},
        )
        assert r.status_code == 409

    def test_update_member_role(self, client: TestClient) -> None:
        client.post(
            "/v1/gardens", json={"slug": "role-update", "name": "Role Update", "scope": "local"}
        )
        client.post(
            "/v1/gardens/role-update/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "reader"},
        )
        r = client.patch(
            "/v1/gardens/role-update/members/stigmem://testnode/agent/bob",
            json={"role": "writer"},
        )
        assert r.status_code == 200
        assert r.json()["role"] == "writer"

    def test_remove_member(self, client: TestClient) -> None:
        client.post("/v1/gardens", json={"slug": "rm-member", "name": "Remove", "scope": "local"})
        client.post(
            "/v1/gardens/rm-member/members",
            json={"entity_uri": "stigmem://testnode/agent/bob", "role": "reader"},
        )
        r = client.delete("/v1/gardens/rm-member/members/stigmem://testnode/agent/bob")
        assert r.status_code == 204
        members = client.get("/v1/gardens/rm-member/members").json()
        assert all(m["entity_uri"] != "stigmem://testnode/agent/bob" for m in members)

    def test_cannot_remove_last_admin(self, client: TestClient) -> None:
        client.post(
            "/v1/gardens", json={"slug": "last-admin", "name": "Last Admin", "scope": "local"}
        )
        # Only admin is creator — removing should fail
        creator_uri = client.get("/v1/gardens/last-admin").json()["created_by"]
        r = client.delete(f"/v1/gardens/last-admin/members/{creator_uri}")
        assert r.status_code == 403

    def test_cannot_demote_last_admin(self, client: TestClient) -> None:
        client.post(
            "/v1/gardens", json={"slug": "demote-admin", "name": "Demote Admin", "scope": "local"}
        )
        creator_uri = client.get("/v1/gardens/demote-admin").json()["created_by"]
        r = client.patch(
            f"/v1/gardens/demote-admin/members/{creator_uri}",
            json={"role": "reader"},
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# ACL enforcement — auth-gated garden operations
# ---------------------------------------------------------------------------


class TestGardenACL:
    def test_non_member_cannot_read_garden(self, tmp_path: object) -> None:
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            # Admin creates a garden
            r = client.post(
                "/v1/gardens",
                json={"slug": "private", "name": "Private", "scope": "team"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            assert r.status_code == 201

            # Outsider cannot GET it
            r2 = client.get(
                "/v1/gardens/private",
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r2.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_non_member_cannot_delete_garden(self, tmp_path: object) -> None:
        client, admin_key, _, outsider_key, original = _make_authed_client(tmp_path)
        try:
            client.post(
                "/v1/gardens",
                json={"slug": "del-private", "name": "Del Private", "scope": "team"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            r = client.delete(
                "/v1/gardens/del-private",
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_reader_cannot_add_member(self, tmp_path: object) -> None:
        client, admin_key, reader_key, _, original = _make_authed_client(tmp_path)
        try:
            client.post(
                "/v1/gardens",
                json={"slug": "reader-perm", "name": "Reader Perm", "scope": "team"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            # Add reader as member
            client.post(
                "/v1/gardens/reader-perm/members",
                json={"entity_uri": "stigmem://testnode/agent/reader", "role": "reader"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            # Reader tries to add another member — should fail
            r = client.post(
                "/v1/gardens/reader-perm/members",
                json={"entity_uri": "stigmem://testnode/agent/new", "role": "reader"},
                headers={"Authorization": f"Bearer {reader_key}"},
            )
            assert r.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original


# ---------------------------------------------------------------------------
# ACL enforcement on facts
# ---------------------------------------------------------------------------


class TestGardenFactACL:
    def _create_garden_and_add_reader(
        self, client: TestClient, admin_key: str, reader_key: str, slug: str
    ) -> str:
        """Create a garden, add reader as member. Return garden_id URI."""
        r = client.post(
            "/v1/gardens",
            json={"slug": slug, "name": slug, "scope": "team"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        assert r.status_code == 201
        garden_id_uri = r.json()["garden_id"]
        client.post(
            f"/v1/gardens/{slug}/members",
            json={"entity_uri": "stigmem://testnode/agent/reader", "role": "reader"},
            headers={"Authorization": f"Bearer {admin_key}"},
        )
        return garden_id_uri

    def test_assert_fact_into_garden(self, tmp_path: object) -> None:
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "fact-garden"
            )
            r = client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            assert r.status_code == 201
            # garden_id is stored as internal UUID in the DB
            assert r.json()["garden_id"] is not None
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_non_member_cannot_assert_into_garden(self, tmp_path: object) -> None:
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "write-guard"
            )
            r = client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_reader_cannot_write_to_garden(self, tmp_path: object) -> None:
        client, admin_key, reader_key, _, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "reader-write"
            )
            r = client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {reader_key}"},
            )
            assert r.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_member_can_query_garden_facts(self, tmp_path: object) -> None:
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "query-garden"
            )
            client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            r = client.get(
                "/v1/facts",
                params={"garden_id": garden_uri},
                headers={"Authorization": f"Bearer {reader_key}"},
            )
            assert r.status_code == 200
            assert r.json()["total"] == 1
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_non_member_cannot_query_garden_facts(self, tmp_path: object) -> None:
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "query-guard"
            )
            r = client.get(
                "/v1/facts",
                params={"garden_id": garden_uri},
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_default_global_query_hides_garden_facts_from_non_member(
        self, tmp_path: object
    ) -> None:
        """Default installs filter garden facts from non-members (F-CONF-1)."""
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "hidden-garden"
            )
            client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            # Outsider's global query sees 0 facts — garden ACL recall filtering
            # is core/default-on.
            r = client.get(
                "/v1/facts",
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r.status_code == 200
            assert r.json()["total"] == 0
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_plugin_global_query_hides_garden_facts(
        self, tmp_path: object, monkeypatch: MonkeyPatch
    ) -> None:
        """Plugin-loaded advanced ACL hides garden-tagged facts from non-members."""
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "hidden-garden-plugin"
            )
            client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            _enable_acl_recall_filter(monkeypatch)
            with stigmem_plugins([_memory_garden_acl_manifest()]):
                r = client.get(
                    "/v1/facts",
                    headers={"Authorization": f"Bearer {outsider_key}"},
                )
            assert r.status_code == 200
            assert r.json()["total"] == 0
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_get_fact_enforces_garden_acl(self, tmp_path: object) -> None:
        """GET /v1/facts/:id on a garden fact must 403 for non-members (spec §17.3)."""
        client, admin_key, reader_key, outsider_key, original = _make_authed_client(tmp_path)
        try:
            garden_uri = self._create_garden_and_add_reader(
                client, admin_key, reader_key, "getfact-guard"
            )
            fact_r = client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            fact_id = fact_r.json()["id"]

            # Member can read
            r_member = client.get(
                f"/v1/facts/{fact_id}",
                headers={"Authorization": f"Bearer {reader_key}"},
            )
            assert r_member.status_code == 200

            # Non-member is blocked
            r_out = client.get(
                f"/v1/facts/{fact_id}",
                headers={"Authorization": f"Bearer {outsider_key}"},
            )
            assert r_out.status_code == 403
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original

    def test_scope_mismatch_rejected(self, tmp_path: object) -> None:
        """Fact scope must match garden scope (spec §17.3)."""
        client, admin_key, _, _, original = _make_authed_client(tmp_path)
        try:
            # Garden is 'team', fact scope is 'company' → should fail
            r_garden = client.post(
                "/v1/gardens",
                json={"slug": "scope-mismatch", "name": "Scope Mismatch", "scope": "team"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            garden_uri = r_garden.json()["garden_id"]
            r = client.post(
                "/v1/facts",
                json={**FACT_PAYLOAD, "garden_id": garden_uri, "scope": "company"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            assert r.status_code == 422
        finally:
            settings_module.settings = original
            auth_mod.settings = original
            db_mod.settings = original
            wk_mod.settings = original
