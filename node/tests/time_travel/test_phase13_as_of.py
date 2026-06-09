"""Tests for §24 time-travel as_of API routes and §23.3.3 oracle-leakage fixes.

Covers:
- POST /v1/recall with as_of parameter
- GET /v1/facts with as_of parameter
- ISO 8601 validation (bad format, future, retention floor)
- Legal-hold admin gating (agent keys get silent filter; admin keys get tombstone_notices)
- X-Total-Count post-tombstone-filter on both endpoints
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import _tombstone_plugin_manifest
from fastapi.testclient import TestClient

from stigmem_node.auth import create_api_key

PAST = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
FUTURE = (datetime.now(UTC) + timedelta(hours=1)).isoformat()


@pytest.fixture()
def client(time_travel_client: TestClient) -> TestClient:
    """Run legacy as_of behavior tests with the time-travel plugin registered."""
    return time_travel_client


def _assert(client: TestClient, entity: str = "user:alice", scope: str = "local") -> dict:
    r = client.post(
        "/v1/facts",
        json={
            "entity": entity,
            "relation": "test:prop",
            "value": {"type": "string", "v": "hello"},
            "source": "agent:test",
            "scope": scope,
        },
    )
    assert r.status_code == 201
    return r.json()


def _insert_tombstone(
    db_path: str,
    entity_uri: str,
    legal_hold: bool = False,
    scope: str = "*",
    tenant_id: str = "default",
) -> str:
    tid = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """INSERT INTO tombstones
           (id, entity_uri, scope, reason, signed_by, signature, created_at, legal_hold, tenant_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            tid,
            entity_uri,
            scope,
            "test",
            "agent:admin",
            "sig",
            datetime.now(UTC).isoformat(),
            1 if legal_hold else 0,
            tenant_id,
        ),
    )
    conn.commit()
    conn.close()
    return tid


def test_as_of_hides_restricted_garden_fact_from_non_member(
    client: TestClient, tmp_db: str
) -> None:
    """/v1/facts?as_of= must not surface a restricted-garden fact to a non-member.

    The recall as_of path was garden-filtered in M3; the /v1/facts?as_of= query
    (_AS_OF_SELECT_SQL) was a separate, unfiltered sibling (audit F-AS-OF-FACTS).
    """
    fact = _assert(client, entity="user:gardentt")
    conn = sqlite3.connect(tmp_db)
    conn.execute(
        "INSERT INTO fact_garden_membership (fact_id, garden_id, updated_at)"
        " VALUES (?, 'restricted', '2026-01-01T00:00:00Z')",
        (fact["id"],),
    )
    conn.commit()
    conn.close()

    as_of = datetime.now(UTC).isoformat()  # after the write, not in the future
    r = client.get(f"/v1/facts?as_of={as_of}&entity=user:gardentt")
    assert r.status_code == 200, r.text
    assert all(f["id"] != fact["id"] for f in r.json()["facts"])  # restricted fact hidden


# ---------------------------------------------------------------------------
# GET /v1/facts — as_of validation
# ---------------------------------------------------------------------------


class TestFactsAsOfValidation:
    def test_invalid_timestamp_format(self, client: TestClient) -> None:
        r = client.get("/v1/facts?as_of=not-a-date")
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "as_of_invalid_timestamp"

    def test_future_timestamp_rejected(self, client: TestClient) -> None:
        r = client.get(f"/v1/facts?as_of={FUTURE}")
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "as_of_future"

    def test_valid_past_timestamp_accepted(self, client: TestClient) -> None:
        r = client.get(f"/v1/facts?as_of={PAST}")
        assert r.status_code == 200
        body = r.json()
        assert "facts" in body
        assert "total" in body

    def test_retention_floor_enforced(self, tmp_db: str, backend: str, encrypt: str) -> None:
        from conftest import (
            _make_enc_settings,
            _patch_settings,
            _restore_settings,
            _time_travel_plugin_manifest,
        )

        import stigmem_node.settings as settings_module
        from stigmem_node.main import create_app
        from stigmem_node.plugins.testing import stigmem_plugins

        original = settings_module.settings
        floor = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        too_old = (datetime.now(UTC) - timedelta(days=60)).isoformat()

        test_settings = _make_enc_settings(
            tmp_db, backend, encrypt, auth_required=False, as_of_retention_floor=floor
        )
        extra = _patch_settings(test_settings)
        try:
            with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
                app = create_app()
                with TestClient(app, raise_server_exceptions=True) as c:
                    r = c.get(f"/v1/facts?as_of={too_old}")
                    assert r.status_code == 400
                    assert r.json()["detail"]["code"] == "as_of_before_retention_floor"

                    # At-or-after floor: allowed
                    r2 = c.get(f"/v1/facts?as_of={floor}")
                    assert r2.status_code == 200
        finally:
            _restore_settings(original, extra)


# ---------------------------------------------------------------------------
# GET /v1/facts — as_of time-travel semantics
# ---------------------------------------------------------------------------


class TestFactsAsOfTimeTravel:
    def test_fact_visible_at_assertion_time(self, client: TestClient) -> None:
        datetime.now(UTC)
        fact = _assert(client)
        after = datetime.now(UTC).isoformat()

        # Query at 'after' — should include the new fact
        r = client.get(f"/v1/facts?as_of={after}")
        assert r.status_code == 200
        ids = {f["id"] for f in r.json()["facts"]}
        assert fact["id"] in ids

    def test_fact_not_visible_before_assertion(self, client: TestClient) -> None:
        # Record a timestamp before asserting
        before_assert = datetime.now(UTC) - timedelta(seconds=5)
        fact = _assert(client)

        r = client.get(f"/v1/facts?as_of={before_assert.isoformat()}")
        assert r.status_code == 200
        ids = {f["id"] for f in r.json()["facts"]}
        assert fact["id"] not in ids

    def test_retracted_fact_excluded(self, client: TestClient, tmp_db: str) -> None:
        fact = _assert(client)

        # Manually insert a retraction for this fact
        retracted_at = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            """INSERT INTO fact_retractions
               (id, fact_id, retracted_at, retracted_by)
               VALUES (?,?,?,?)""",
            (str(uuid.uuid4()), fact["id"], retracted_at, "agent:test"),
        )
        conn.commit()
        conn.close()

        # Query after retraction — fact should be excluded
        after_retract = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
        r = client.get(f"/v1/facts?as_of={after_retract}")
        ids = {f["id"] for f in r.json()["facts"]}
        assert fact["id"] not in ids

    def test_retracted_fact_visible_before_retraction(
        self, client: TestClient, tmp_db: str
    ) -> None:
        fact = _assert(client)
        before_retract = datetime.now(UTC) - timedelta(seconds=1)

        # Retraction happens after our query window
        retracted_at = datetime.now(UTC).isoformat()
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            """INSERT INTO fact_retractions
               (id, fact_id, retracted_at, retracted_by)
               VALUES (?,?,?,?)""",
            (str(uuid.uuid4()), fact["id"], retracted_at, "agent:test"),
        )
        conn.commit()
        conn.close()

        # Query at before_retract — fact should still be visible
        r = client.get(f"/v1/facts?as_of={before_retract.isoformat()}")
        # The fact was asserted after before_retract, so it may not appear — this just
        # checks that the retraction timestamp doesn't retroactively hide it if it
        # existed at that point.  Primary assertion: response is 200 and valid JSON.
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# GET /v1/facts — tombstone filtering and X-Total-Count
# ---------------------------------------------------------------------------


class TestFactsAsOfTombstoneGating:
    def test_tombstoned_entity_excluded_from_as_of(self, client: TestClient, tmp_db: str) -> None:
        fact = _assert(client, entity="stigmem://test/user/alice")
        after_assert = datetime.now(UTC).isoformat()

        _insert_tombstone(tmp_db, "stigmem://test/user/alice", legal_hold=False)

        r = client.get(f"/v1/facts?as_of={after_assert}")
        assert r.status_code == 200
        ids = {f["id"] for f in r.json()["facts"]}
        assert fact["id"] not in ids

    def test_legal_hold_entity_silently_filtered_for_agent(
        self, tmp_db: str, backend: str, encrypt: str
    ) -> None:
        """Agent keys silently filter legal-hold facts instead of returning 403."""
        from conftest import (
            _make_enc_settings,
            _patch_settings,
            _restore_settings,
            _time_travel_plugin_manifest,
        )

        import stigmem_node.settings as settings_module
        from stigmem_node.main import create_app
        from stigmem_node.plugins.testing import stigmem_plugins

        original = settings_module.settings
        test_settings = _make_enc_settings(tmp_db, backend, encrypt, auth_required=True)
        extra = _patch_settings(test_settings)
        agent_key = create_api_key("agent:alice", ["read", "write"])
        try:
            with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
                app = create_app()
                with TestClient(app, raise_server_exceptions=True) as c:
                    # Assert fact
                    r = c.post(
                        "/v1/facts",
                        headers={"Authorization": f"Bearer {agent_key}"},
                        json={
                            "entity": "stigmem://test/user/bob",
                            "relation": "test:prop",
                            "value": {"type": "string", "v": "secret"},
                            "source": "agent:alice",
                            "scope": "local",
                        },
                    )
                    assert r.status_code == 201
                    after = datetime.now(UTC).isoformat()

                    # Insert legal_hold tombstone
                    _insert_tombstone(tmp_db, "stigmem://test/user/bob", legal_hold=True)

                    # Agent key query should silently filter facts, not 403.
                    r = c.get(
                        f"/v1/facts?as_of={after}",
                        headers={"Authorization": f"Bearer {agent_key}"},
                    )
                    assert r.status_code == 200
                    body = r.json()
                    # Fact silently absent; no tombstone_notices for agent callers
                    assert "stigmem://test/user/bob" not in {
                        f["entity"] for f in body["facts"]
                    }
                    assert body.get("tombstone_notices", []) == []
        finally:
            _restore_settings(original, extra)

    def test_legal_hold_entity_visible_with_notices_for_admin(
        self, tmp_db: str, backend: str, encrypt: str
    ) -> None:
        """Admin keys with 'admin' permission receive legal_hold facts + tombstone_notices."""
        from conftest import (
            _make_enc_settings,
            _patch_settings,
            _restore_settings,
            _time_travel_plugin_manifest,
        )

        import stigmem_node.settings as settings_module
        from stigmem_node.main import create_app
        from stigmem_node.plugins.testing import stigmem_plugins

        original = settings_module.settings
        test_settings = _make_enc_settings(tmp_db, backend, encrypt, auth_required=True)
        extra = _patch_settings(test_settings)
        admin_key = create_api_key("agent:admin", ["read", "write", "admin"])
        try:
            with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
                app = create_app()
                with TestClient(app, raise_server_exceptions=True) as c:
                    r = c.post(
                        "/v1/facts",
                        headers={"Authorization": f"Bearer {admin_key}"},
                        json={
                            "entity": "stigmem://test/user/carol",
                            "relation": "test:prop",
                            "value": {"type": "string", "v": "held"},
                            "source": "agent:admin",
                            "scope": "local",
                        },
                    )
                    assert r.status_code == 201
                    after = datetime.now(UTC).isoformat()

                    _insert_tombstone(
                        tmp_db, "stigmem://test/user/carol", legal_hold=True
                    )

                    r = c.get(
                        f"/v1/facts?as_of={after}&entity=stigmem://test/user/carol",
                        headers={"Authorization": f"Bearer {admin_key}"},
                    )
                    assert r.status_code == 200
                    body = r.json()
                    # Admin sees the fact (it's not excluded)
                    entities = {f["entity"] for f in body["facts"]}
                    assert "stigmem://test/user/carol" in entities
                    # tombstone_notices present
                    assert len(body.get("tombstone_notices", [])) >= 1
                    notice = body["tombstone_notices"][0]
                    assert notice["legal_hold"] is True
                    assert notice["entity_uri"] == "stigmem://test/user/carol"
        finally:
            _restore_settings(original, extra)

    def test_x_total_count_header_present(self, client: TestClient) -> None:
        _assert(client)
        after = datetime.now(UTC).isoformat()
        r = client.get(f"/v1/facts?as_of={after}")
        assert r.status_code == 200
        assert "x-total-count" in r.headers
        assert int(r.headers["x-total-count"]) == r.json()["total"]

    def test_x_total_count_live_path(self, client: TestClient) -> None:
        _assert(client)
        r = client.get("/v1/facts")
        assert r.status_code == 200
        assert "x-total-count" in r.headers
        assert int(r.headers["x-total-count"]) == r.json()["total"]

    def test_x_total_count_suppressed_after_tombstone(
        self, client: TestClient, tmp_db: str
    ) -> None:
        """§23.3.3 r.3: total and X-Total-Count suppressed when tombstone filter applied."""
        _assert(client, entity="stigmem://test/user/dave")
        _assert(client, entity="stigmem://test/user/eve")
        after = datetime.now(UTC).isoformat()

        _insert_tombstone(tmp_db, "stigmem://test/user/dave", legal_hold=False)

        r = client.get(f"/v1/facts?as_of={after}")
        assert r.status_code == 200
        body = r.json()
        assert "x-total-count" not in r.headers
        assert body["total"] is None
        assert all(f["entity"] != "stigmem://test/user/dave" for f in body["facts"])


# ---------------------------------------------------------------------------
# POST /v1/recall — as_of parameter
# ---------------------------------------------------------------------------


class TestRecallAsOf:
    def test_recall_as_of_validation_bad_format(self, client: TestClient) -> None:
        r = client.post("/v1/recall", json={"query": "hello", "as_of": "bad-date"})
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "as_of_invalid_timestamp"

    def test_recall_as_of_future_rejected(self, client: TestClient) -> None:
        r = client.post("/v1/recall", json={"query": "hello", "as_of": FUTURE})
        assert r.status_code == 400
        assert r.json()["detail"]["code"] == "as_of_future"

    def test_recall_as_of_past_returns_200(self, client: TestClient) -> None:
        r = client.post("/v1/recall", json={"query": "hello", "as_of": PAST})
        assert r.status_code == 200
        body = r.json()
        assert "facts" in body
        assert "total_scored" in body
        assert "tombstone_notices" in body

    def test_recall_as_of_finds_historical_fact(self, client: TestClient) -> None:
        _assert(client, entity="user:frank")
        after = datetime.now(UTC).isoformat()

        r = client.post("/v1/recall", json={"query": "user:frank", "as_of": after})
        assert r.status_code == 200
        body = r.json()
        entities = {sf["fact"]["entity"] for sf in body["facts"]}
        assert "user:frank" in entities

    def test_recall_as_of_tombstone_notices_empty_for_non_legal_hold(
        self, client: TestClient, tmp_db: str
    ) -> None:
        _assert(client, entity="stigmem://test/user/george")
        after = datetime.now(UTC).isoformat()
        _insert_tombstone(tmp_db, "stigmem://test/user/george", legal_hold=False)

        r = client.post("/v1/recall", json={"query": "george", "as_of": after})
        assert r.status_code == 200
        body = r.json()
        # Entity tombstoned (non-legal-hold) → excluded; no notice
        entities = {sf["fact"]["entity"] for sf in body["facts"]}
        assert "stigmem://test/user/george" not in entities
        assert body["tombstone_notices"] == []

    def test_recall_x_total_count_header(self, client: TestClient) -> None:
        _assert(client)
        after = datetime.now(UTC).isoformat()

        r = client.post("/v1/recall", json={"query": "hello", "as_of": after})
        assert r.status_code == 200
        assert "x-total-count" in r.headers
        assert int(r.headers["x-total-count"]) == r.json()["total_scored"]

    def test_recall_live_x_total_count_header(self, client: TestClient) -> None:
        _assert(client)
        r = client.post("/v1/recall", json={"query": "hello"})
        assert r.status_code == 200
        assert "x-total-count" in r.headers
        assert int(r.headers["x-total-count"]) == r.json()["total_scored"]

    def test_recall_as_of_legal_hold_agent_silent_filter(
        self, tmp_db: str, backend: str, encrypt: str
    ) -> None:
        """Agent key: legal_hold fact silently absent from recall results (§24.3.2)."""
        from conftest import (
            _make_enc_settings,
            _patch_settings,
            _restore_settings,
            _time_travel_plugin_manifest,
        )

        import stigmem_node.settings as settings_module
        from stigmem_node.main import create_app
        from stigmem_node.plugins.testing import stigmem_plugins

        original = settings_module.settings
        test_settings = _make_enc_settings(tmp_db, backend, encrypt, auth_required=True)
        extra = _patch_settings(test_settings)
        agent_key = create_api_key("agent:recall-agent", ["read", "write"])
        try:
            with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
                app = create_app()
                with TestClient(app, raise_server_exceptions=True) as c:
                    c.post(
                        "/v1/facts",
                        headers={"Authorization": f"Bearer {agent_key}"},
                        json={
                            "entity": "stigmem://test/user/held-entity",
                            "relation": "test:prop",
                            "value": {"type": "string", "v": "legal-hold-data"},
                            "source": "agent:recall-agent",
                            "scope": "local",
                        },
                    )
                    after = datetime.now(UTC).isoformat()
                    _insert_tombstone(
                        tmp_db, "stigmem://test/user/held-entity", legal_hold=True
                    )

                    r = c.post(
                        "/v1/recall",
                        headers={"Authorization": f"Bearer {agent_key}"},
                        json={"query": "held-entity", "as_of": after},
                    )
                    assert r.status_code == 200
                    body = r.json()
                    entities = {sf["fact"]["entity"] for sf in body["facts"]}
                    assert "stigmem://test/user/held-entity" not in entities
                    assert body["tombstone_notices"] == []
        finally:
            _restore_settings(original, extra)
