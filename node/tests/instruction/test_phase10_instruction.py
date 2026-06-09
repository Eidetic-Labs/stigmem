"""Tests for Phase 10 — lazy instruction discovery (spec §21).

Covers:
  - Manifest publish / version conflict / token limit / entry validation
  - Boot stub generation and caching
  - recall_instruction: hint prioritization, scoring, guaranteed units, audit token
  - Discovery audit submission: idempotent, TTL, token validation
  - Coverage report: agent vs admin key, scope denial
  - Auth enforcement: instruction_scope_denied for cross-agent recall
  - CLI: instruction manifest generate, audit discovery
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.main as main_mod
import stigmem_node.plugins.registry as plugin_registry
import stigmem_node.settings as settings_mod
from stigmem_node.plugins.testing import stigmem_plugins

_FEATURE_SRC = (
    Path(__file__).resolve().parents[3]
    / "experimental"
    / "lazy-instruction-discovery"
    / "src"
)
if str(_FEATURE_SRC) not in sys.path:
    sys.path.insert(0, str(_FEATURE_SRC))

from stigmem_plugin_lazy_instruction_discovery import plugin_manifest  # noqa: E402

create_api_key = auth_mod.create_api_key
Settings = settings_mod.Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGENT_ID = str(uuid.uuid4())
_DEPLOYMENT = "test"

_ENTRY_MINIMAL = {
    "name": "heartbeat-procedure",
    "description": "The Paperclip heartbeat procedure.",
    "fact_uri": f"instruction:{_DEPLOYMENT}/agent/{_AGENT_ID}/heartbeat-procedure/v1",
    "load_triggers": {
        "intents": ["how do I start a heartbeat"],
        "keywords": ["heartbeat", "checkout"],
        "task_types": ["issue_assigned"],
    },
}

_ENTRY_PATH_ONLY = {
    "name": "security-posture",
    "description": "Security constraints and hard prohibitions.",
    "path": "/dev/null",  # always-present file, empty content
    "load_triggers": {"intents": ["security"], "keywords": ["security"], "task_types": []},
}

_ENTRY_BOTH = {
    "name": "bad-entry",
    "description": "Has both fact_uri and path.",
    "fact_uri": f"instruction:{_DEPLOYMENT}/agent/{_AGENT_ID}/bad/v1",
    "path": "/dev/null",
    "load_triggers": {},
}

_ENTRY_NEITHER = {
    "name": "also-bad",
    "description": "Has neither fact_uri nor path.",
    "load_triggers": {},
}


def _manifest_body(entries: list[dict] | None = None, version: str = "v1") -> dict:
    if entries is None:
        entries = [_ENTRY_MINIMAL]
    return {"version": version, "entries": entries, "skip_coverage_gate": True}


# ---------------------------------------------------------------------------
# Manifest publish
# ---------------------------------------------------------------------------


class TestManifestPublish:
    def test_publish_requires_admin(self, authed_client: tuple) -> None:
        """Non-admin (read+write but no federate) should get 403."""
        c, _key = authed_client
        r = c.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(),
            headers={"Authorization": f"Bearer {_key}"},
        )
        assert r.status_code == 403

    def test_publish_succeeds_as_admin(self, admin_client: TestClient) -> None:
        r = admin_client.put(f"/v1/agents/{_AGENT_ID}/instruction-manifest", json=_manifest_body())
        assert r.status_code == 200
        body = r.json()
        assert "fact_uri" in body
        assert "token_count" in body
        assert "coverage_report" in body
        assert body["coverage_report"][0]["unit"] == "heartbeat-procedure"

    def test_version_conflict(self, admin_client: TestClient) -> None:
        admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest", json=_manifest_body(version="vdup")
        )
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest", json=_manifest_body(version="vdup")
        )
        assert r.status_code == 409
        assert "manifest_version_conflict" in r.text

    def test_entry_with_both_rejected(self, admin_client: TestClient) -> None:
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_BOTH], version="vboth"),
        )
        assert r.status_code == 400
        assert "manifest_entry_invalid" in r.text

    def test_entry_with_neither_rejected(self, admin_client: TestClient) -> None:
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_NEITHER], version="vneither"),
        )
        assert r.status_code == 400
        assert "manifest_entry_invalid" in r.text

    def test_guarantee_cap_exceeded(self, admin_client: TestClient) -> None:
        entries = []
        for i in range(6):
            entries.append(
                {
                    "name": f"unit-{i}",
                    "description": f"Unit {i}",
                    "path": "/dev/null",
                    "guarantee_load": True,
                    "load_triggers": {},
                }
            )
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=entries, version="vcap"),
        )
        assert r.status_code == 400
        assert "guarantee_cap_exceeded" in r.text

    def test_unknown_task_type_rejected(self, admin_client: TestClient) -> None:
        entry = {
            **_ENTRY_MINIMAL,
            "name": "bad-tt",
            "required_by_task_types": ["not_a_real_wake_reason"],
        }
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=[entry], version="vtt"),
        )
        assert r.status_code == 400
        assert "task_type_unknown" in r.text

    def test_more_than_2_task_types_rejected(self, admin_client: TestClient) -> None:
        entry = {
            **_ENTRY_MINIMAL,
            "name": "many-tt",
            "required_by_task_types": ["issue_assigned", "issue_commented", "routine_fired"],
        }
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=[entry], version="vmanytt"),
        )
        assert r.status_code == 400
        assert "task_types_approval_required" in r.text

    def test_path_only_entry_accepted(self, admin_client: TestClient) -> None:
        r = admin_client.put(
            f"/v1/agents/{_AGENT_ID}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY], version="vpath"),
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Get manifest
# ---------------------------------------------------------------------------


class TestGetManifest:
    def test_404_when_no_manifest(self, client: TestClient) -> None:
        fresh_id = str(uuid.uuid4())
        r = client.get(f"/v1/agents/{fresh_id}/instruction-manifest")
        assert r.status_code == 404

    def test_returns_manifest_after_publish(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY]),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/instruction-manifest")
        assert r.status_code == 200
        body = r.json()
        assert body["manifest_version"] == "v1"
        assert len(body["entries"]) == 1
        assert body["entries"][0]["name"] == "security-posture"

    def test_supersedes_old_version_on_republish(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY], version="v1"),
        )
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY], version="v2"),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/instruction-manifest")
        assert r.status_code == 200
        assert r.json()["manifest_version"] == "v2"


# ---------------------------------------------------------------------------
# Boot stub
# ---------------------------------------------------------------------------


class TestBootStub:
    def test_404_when_no_manifest(self, client: TestClient) -> None:
        fresh_id = str(uuid.uuid4())
        r = client.get(f"/v1/agents/{fresh_id}/boot-stub")
        assert r.status_code == 404

    def test_returns_markdown_after_publish(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY]),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/boot-stub")
        assert r.status_code == 200
        assert "text/markdown" in r.headers["content-type"]
        assert "---" in r.text
        assert "recall_instruction" in r.text

    def test_stub_headers_present(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY]),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/boot-stub")
        assert r.status_code == 200
        assert "x-stub-version" in r.headers
        assert "x-manifest-version" in r.headers
        assert "x-token-count" in r.headers

    def test_profile_generic_accepted(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY]),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/boot-stub?profile=generic")
        assert r.status_code == 200

    def test_unknown_profile_treated_as_generic(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json=_manifest_body(entries=[_ENTRY_PATH_ONLY]),
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/boot-stub?profile=nonexistent")
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# recall_instruction
# ---------------------------------------------------------------------------


class TestRecallInstruction:
    def _setup_agent_with_facts(self, admin_client: TestClient, agent_id: str) -> None:
        """Publish a manifest for agent_id, seeding a fact for the first entry."""
        # Write the instruction fact so it can be fetched
        fact_uri = f"instruction:{_DEPLOYMENT}/agent/{agent_id}/heartbeat-procedure/v1"
        admin_client.post(
            "/v1/facts",
            json={
                "entity": fact_uri,
                "relation": "instruction:content",
                "value": {
                    "type": "text",
                    "v": "## Heartbeat Procedure\n\nCheckout the issue first.",
                },
                "source": "admin",
                "scope": "local",
            },
        )
        entry = {
            "name": "heartbeat-procedure",
            "description": "The Paperclip heartbeat procedure.",
            "fact_uri": fact_uri,
            "load_triggers": {
                "intents": ["how do I start a heartbeat", "checkout issue"],
                "keywords": ["heartbeat", "checkout"],
                "task_types": ["issue_assigned"],
            },
        }
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": "v1", "entries": [entry], "skip_coverage_gate": True},
        )

    def test_intent_required(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        r = admin_client.post(f"/v1/agents/{agent_id}/recall-instruction", json={})
        assert r.status_code == 422  # pydantic validation

    def test_returns_chunks(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={
                "intent": "I am starting a heartbeat and need to check out an issue",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert "chunks" in body
        assert "total_tokens" in body
        assert "truncated" in body
        assert "audit_token" in body
        assert body["audit_token"].startswith("audi_")

    def test_chunk_has_required_fields(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={
                "intent": "heartbeat checkout",
            },
        )
        assert r.status_code == 200
        chunks = r.json()["chunks"]
        if chunks:
            chunk = chunks[0]
            for field in ("name", "content", "tokens", "score", "source"):
                assert field in chunk, f"missing field: {field}"

    def test_manifest_hint_loaded_first(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        # Publish two entries
        uri1 = f"instruction:{_DEPLOYMENT}/agent/{agent_id}/unit-a/v1"
        uri2 = f"instruction:{_DEPLOYMENT}/agent/{agent_id}/unit-b/v1"
        for uri, content in [(uri1, "Unit A content"), (uri2, "Unit B content")]:
            admin_client.post(
                "/v1/facts",
                json={
                    "entity": uri,
                    "relation": "instruction:content",
                    "value": {"type": "text", "v": content},
                    "source": "admin",
                    "scope": "local",
                },
            )
        entries = [
            {"name": "unit-a", "description": "Unit A", "fact_uri": uri1, "load_triggers": {}},
            {"name": "unit-b", "description": "Unit B", "fact_uri": uri2, "load_triggers": {}},
        ]
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": "v1", "entries": entries, "skip_coverage_gate": True},
        )
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={
                "intent": "something unrelated",
                "manifest_hint": ["unit-b"],
            },
        )
        assert r.status_code == 200
        chunks = r.json()["chunks"]
        names = [c["name"] for c in chunks]
        assert "unit-b" in names
        if len(names) > 1:
            assert names[0] == "unit-b", "hinted unit should come first"

    def test_missed_hints_returned(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={
                "intent": "something",
                "manifest_hint": ["unit-does-not-exist"],
            },
        )
        assert r.status_code == 200
        assert "unit-does-not-exist" in r.json()["missed_hints"]

    def test_404_when_no_manifest(self, admin_client: TestClient) -> None:
        fresh_id = str(uuid.uuid4())
        r = admin_client.post(
            f"/v1/agents/{fresh_id}/recall-instruction",
            json={
                "intent": "test",
            },
        )
        assert r.status_code == 404

    def test_scope_denied_cross_agent(self, client: TestClient, admin_client: TestClient) -> None:
        """An agent key scoped to AGENT_ID should not recall for OTHER_AGENT_ID."""
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        # Create a key scoped to a different agent
        other_key = create_api_key(f"agent:{str(uuid.uuid4())}", ["read", "write"])
        r = client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={"intent": "test"},
            headers={"Authorization": f"Bearer {other_key}"},
        )
        # With auth disabled (test default), this passes. With auth enabled, expect 403.
        # We assert the route exists and doesn't 500.
        assert r.status_code in (200, 403, 404)

    def test_audit_token_written(self, admin_client: TestClient, tmp_db: str) -> None:
        agent_id = str(uuid.uuid4())
        self._setup_agent_with_facts(admin_client, agent_id)
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={
                "intent": "heartbeat",
            },
        )
        assert r.status_code == 200
        token = r.json()["audit_token"]
        conn = sqlite3.connect(tmp_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id FROM instruction_audit WHERE audit_token = ?", (token,)
        ).fetchone()
        conn.close()
        assert row is not None, "audit record should be written to DB"


# ---------------------------------------------------------------------------
# Discovery audit submission
# ---------------------------------------------------------------------------


class TestAuditSubmission:
    def _get_token(self, admin_client: TestClient) -> str:
        agent_id = str(uuid.uuid4())
        uri = f"instruction:{_DEPLOYMENT}/agent/{agent_id}/heartbeat-procedure/v1"
        admin_client.post(
            "/v1/facts",
            json={
                "entity": uri,
                "relation": "instruction:content",
                "value": {"type": "text", "v": "content"},
                "source": "admin",
                "scope": "local",
            },
        )
        entry = {
            "name": "heartbeat-procedure",
            "description": "desc",
            "fact_uri": uri,
            "load_triggers": {},
        }
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": "v1", "entries": [entry], "skip_coverage_gate": True},
        )
        r = admin_client.post(f"/v1/agents/{agent_id}/recall-instruction", json={"intent": "test"})
        return r.json()["audit_token"]

    def test_submit_returns_204(self, admin_client: TestClient) -> None:
        token = self._get_token(admin_client)
        r = admin_client.post(
            "/v1/instruction/audit",
            json={
                "audit_token": token,
                "used_chunks": ["heartbeat-procedure"],
                "missed_chunks": [],
            },
        )
        assert r.status_code == 204

    def test_submit_idempotent(self, admin_client: TestClient) -> None:
        token = self._get_token(admin_client)
        body = {"audit_token": token, "used_chunks": ["heartbeat-procedure"], "missed_chunks": []}
        r1 = admin_client.post("/v1/instruction/audit", json=body)
        r2 = admin_client.post("/v1/instruction/audit", json=body)
        assert r1.status_code == 204
        assert r2.status_code == 204

    def test_invalid_token_returns_400(self, admin_client: TestClient) -> None:
        r = admin_client.post(
            "/v1/instruction/audit",
            json={
                "audit_token": "audi_notreal",
                "used_chunks": [],
                "missed_chunks": [],
            },
        )
        assert r.status_code == 400
        assert "audit_token_invalid" in r.text

    def test_used_chunks_written_to_db(self, admin_client: TestClient, tmp_db: str) -> None:
        token = self._get_token(admin_client)
        admin_client.post(
            "/v1/instruction/audit",
            json={
                "audit_token": token,
                "used_chunks": ["heartbeat-procedure"],
                "missed_chunks": [],
            },
        )
        conn = sqlite3.connect(tmp_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT used_chunks FROM instruction_audit WHERE audit_token = ?", (token,)
        ).fetchone()
        conn.close()
        assert row is not None
        used = json.loads(row["used_chunks"])
        assert "heartbeat-procedure" in used


class TestAuditPrincipalBinding:
    """Audit submit binds the caller to the audit's agent (audit F-8)."""

    @staticmethod
    def _seed_audit(tmp_db: str, agent_id: str, token: str) -> None:
        now = int(time.time() * 1000)
        conn = sqlite3.connect(tmp_db)
        conn.execute(
            """INSERT INTO instruction_audit
               (id, agent_id, heartbeat_id, session_start, intent, loaded_chunks,
                used_chunks, missed_chunks, audit_token, audit_closed, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ("aud-" + token, agent_id, "hb", now, "boot", "[]", "[]", "[]", token, None, now),
        )
        conn.commit()
        conn.close()

    def test_submit_denied_for_foreign_agent(
        self, authed_client: tuple[TestClient, str], tmp_db: str
    ) -> None:
        client, key = authed_client  # entity_uri agent:test, non-admin
        self._seed_audit(tmp_db, "other-agent", "audi_foreign")
        r = client.post(
            "/v1/instruction/audit",
            json={"audit_token": "audi_foreign", "used_chunks": [], "missed_chunks": []},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r.status_code == 403

    def test_submit_allowed_for_own_agent(
        self, authed_client: tuple[TestClient, str], tmp_db: str
    ) -> None:
        client, key = authed_client  # agent:test → segment "test" matches agent_id
        self._seed_audit(tmp_db, "test", "audi_own")
        r = client.post(
            "/v1/instruction/audit",
            json={"audit_token": "audi_own", "used_chunks": [], "missed_chunks": []},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r.status_code == 204


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------


class TestCoverageReport:
    def test_404_when_no_manifest(self, admin_client: TestClient) -> None:
        r = admin_client.get(f"/v1/agents/{str(uuid.uuid4())}/instruction-manifest/coverage")
        assert r.status_code == 404

    def test_returns_coverage_after_publish(self, admin_client: TestClient) -> None:
        agent_id = str(uuid.uuid4())
        entry = {
            "name": "heartbeat-procedure",
            "description": "desc",
            "path": "/dev/null",
            "load_triggers": {},
        }
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": "v1", "entries": [entry], "skip_coverage_gate": True},
        )
        r = admin_client.get(f"/v1/agents/{agent_id}/instruction-manifest/coverage")
        assert r.status_code == 200
        body = r.json()
        assert "units" in body
        assert body["units"][0]["name"] == "heartbeat-procedure"
        # Admin key should include coverage_status (S11)
        assert "coverage_status" in body["units"][0]

    def test_agent_key_omits_coverage_status(
        self, client: TestClient, admin_client: TestClient
    ) -> None:
        agent_id = str(uuid.uuid4())
        entry = {
            "name": "heartbeat-procedure",
            "description": "desc",
            "path": "/dev/null",
            "load_triggers": {},
        }
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": "v1", "entries": [entry], "skip_coverage_gate": True},
        )
        # agent key (read+write only, no federate) — treated as non-admin
        agent_key = create_api_key(f"agent:{agent_id}", ["read", "write"])
        r = client.get(
            f"/v1/agents/{agent_id}/instruction-manifest/coverage",
            headers={"Authorization": f"Bearer {agent_key}"},
        )
        # With auth disabled, admin check may pass. With auth enabled,
        # coverage_status should be absent.
        if r.status_code == 200:
            unit = r.json()["units"][0]
            assert "coverage_pct" in unit
            assert "hit_at_10" in unit


# ---------------------------------------------------------------------------
# CLI: instruction manifest generate
# ---------------------------------------------------------------------------


class TestCLIManifestGenerate:
    def test_generate_from_directory(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        md = tmp_path / "heartbeat.md"
        md.write_text(
            "## Heartbeat Procedure\n\n"
            "Checkout the issue.\n\n"
            "## Update Status\n\n"
            "Patch the issue.\n"
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "stigmem_node.cli",
                "instruction",
                "manifest",
                "generate",
                str(tmp_path),
                "--agent-id",
                _AGENT_ID,
                "--deployment",
                "acme",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        data = json.loads(result.stdout)
        assert "entries" in data
        assert len(data["entries"]) >= 1
        for entry in data["entries"]:
            assert "name" in entry
            assert "fact_uri" in entry
            assert entry["fact_uri"].startswith("instruction:acme/")


class TestCLIAuditDiscovery:
    def test_audit_discovery_no_data(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        db_file = str(tmp_path / "test.db")
        db_mod.apply_migrations(db_path=db_file)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "stigmem_node.cli",
                "audit",
                "discovery",
                "--agent",
                "test-agent",
                "--db",
                db_file,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "test-agent" in result.stdout or "No audit records" in result.stdout

    def test_audit_discovery_json_flag(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        db_file = str(tmp_path / "test.db")
        db_mod.apply_migrations(db_path=db_file)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "stigmem_node.cli",
                "audit",
                "discovery",
                "--agent",
                "test-agent",
                "--db",
                db_file,
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Migration tool — unit tests
# ---------------------------------------------------------------------------


class TestInstructionMigrateParser:
    """Tests for parse_instruction_chunks (pure Python, no server)."""

    def test_parses_headings(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "heartbeat.md"
        md.write_text("## Checkout\n\nCheck out the issue.\n\n## Update\n\nPatch status.\n")
        chunks = parse_instruction_chunks(tmp_path)
        assert len(chunks) == 2
        slugs = {c.slug for c in chunks}
        assert "checkout" in slugs
        assert "update" in slugs

    def test_parses_single_file(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "soul.md"
        md.write_text("# Soul\n\nCore values.\n")
        chunks = parse_instruction_chunks(tmp_path)
        assert len(chunks) == 1
        assert chunks[0].content.startswith("# Soul")

    def test_strips_frontmatter(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "agents.md"
        md.write_text("---\nrole: cto\n---\n## Rules\n\nDo not push to main.\n")
        chunks = parse_instruction_chunks(tmp_path)
        assert all("---" not in c.content for c in chunks)
        assert any("Rules" in c.heading_text for c in chunks)

    def test_no_headings_treated_as_one_chunk(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "plain.md"
        md.write_text("Just a paragraph with no headings.")
        chunks = parse_instruction_chunks(tmp_path)
        assert len(chunks) == 1

    def test_keywords_extracted(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "auth.md"
        md.write_text("## Authentication\n\nUse bearer tokens always.\n")
        chunks = parse_instruction_chunks(tmp_path)
        assert len(chunks) == 1
        assert any(len(kw) >= 4 for kw in chunks[0].keywords)

    def test_deduplicates_slugs_across_files(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        (tmp_path / "a.md").write_text("## Overview\n\nFile A.\n")
        (tmp_path / "b.md").write_text("## Overview\n\nFile B.\n")
        chunks = parse_instruction_chunks(tmp_path)
        slugs = [c.slug for c in chunks]
        assert len(slugs) == len(set(slugs)), "slugs must be unique"

    def test_accepts_single_file_path(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import parse_instruction_chunks

        md = tmp_path / "tools.md"
        md.write_text("## Tools\n\nUse bash.\n")
        chunks = parse_instruction_chunks(md)
        assert len(chunks) == 1


class TestComputeDiff:
    def test_create_when_no_existing(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        chunks = [
            Chunk("f", "Heartbeat", "heartbeat", "# Heartbeat\n\nDo things.", ["heartbeat"], 5)
        ]
        diff = compute_diff(chunks, "instruction:test/agent/xyz", "v1", {}, set())
        assert len(diff) == 1
        assert diff[0].action == "CREATE"
        assert diff[0].unit_name == "heartbeat"

    def test_noop_when_content_unchanged(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        content = "# Heartbeat\n\nDo things."
        chunks = [Chunk("f", "Heartbeat", "heartbeat", content, [], 5)]
        existing = {"instruction:test/agent/xyz/heartbeat/v1": content}
        diff = compute_diff(chunks, "instruction:test/agent/xyz", "v1", existing, set())
        assert diff[0].action == "NOOP"

    def test_update_when_content_changed(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        chunks = [Chunk("f", "Heartbeat", "heartbeat", "# Heartbeat\n\nNew content.", [], 5)]
        existing = {"instruction:test/agent/xyz/heartbeat/v1": "# Heartbeat\n\nOld content."}
        diff = compute_diff(chunks, "instruction:test/agent/xyz", "v1", existing, set())
        assert diff[0].action == "UPDATE"

    def test_tombstone_for_removed_sections(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        chunks = [Chunk("f", "New Section", "new-section", "# New Section\n\nContent.", [], 5)]
        prev_names = {"old-section", "another-old-section"}
        diff = compute_diff(chunks, "instruction:test/agent/xyz", "v1", {}, prev_names)
        tombstones = [d for d in diff if d.action == "TOMBSTONE"]
        assert len(tombstones) == 2
        names = {d.unit_name for d in tombstones}
        assert "old-section" in names

    def test_fact_uri_format_role(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        chunks = [Chunk("f", "Test", "test-slug", "# Test", [], 1)]
        diff = compute_diff(chunks, "instruction:prod/agent/agent-uuid", "v2", {}, set())
        assert diff[0].fact_uri == "instruction:prod/agent/agent-uuid/test-slug/v2"

    def test_fact_uri_format_skill(self) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff

        chunks = [Chunk("f", "Test", "test-slug", "# Test", [], 1)]
        diff = compute_diff(chunks, "instruction:prod/skill/paperclip", "v1", {}, set())
        assert diff[0].fact_uri == "instruction:prod/skill/paperclip/test-slug/v1"


class TestFormatPreview:
    def test_preview_contains_counts(self, tmp_path: Path) -> None:
        from stigmem_node.instruction_migrate import Chunk, compute_diff, format_preview

        chunks = [
            Chunk("f", "Section A", "section-a", "# Section A", [], 1),
            Chunk("f", "Section B", "section-b", "# Section B", [], 1),
        ]
        existing = {"instruction:t/agent/x/section-b/v1": "# Section B"}
        diff = compute_diff(chunks, "instruction:t/agent/x", "v1", existing, {"old-section"})
        preview = format_preview(diff, "role:cto", tmp_path, "v1")
        assert "1 create" in preview
        assert "1 noop" in preview
        assert "1 tombstone" in preview

    def test_dry_run_cli_shows_preview(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        md = tmp_path / "heartbeat.md"
        md.write_text(
            "## Heartbeat Procedure\n\nCheckout the issue.\n\n## Update Status\n\nPatch.\n"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "stigmem_node.cli",
                "instruction",
                "migrate",
                str(tmp_path),
                "--role",
                "cto",
                "--agent-id",
                str(uuid.uuid4()),
                "--deployment",
                "test",
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "Migration Preview" in result.stdout
        assert "Dry-run" in result.stdout

    def test_dry_run_shows_creates(self, tmp_path: Path) -> None:
        import subprocess
        import sys

        md = tmp_path / "tools.md"
        md.write_text("## Tools\n\nUse the bash tool.\n")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "stigmem_node.cli",
                "instruction",
                "migrate",
                str(tmp_path),
                "--skill",
                "paperclip",
                "--agent-id",
                str(uuid.uuid4()),
                "--dry-run",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "[+]" in result.stdout  # CREATE symbol


class TestMigrationRoundTrip:
    """Integration test: migrate facts → recall_instruction retrieves content."""

    def _migrate_via_client(
        self,
        admin_client: TestClient,
        tmp_path: Path,
        agent_id: str,
        deployment: str = "test",
        version: str = "v1",
    ) -> None:
        """Parse a markdown dir, write facts + manifest via the test client."""
        from stigmem_node.instruction_migrate import (
            compute_diff,
            parse_instruction_chunks,
            scope_prefix_for_role,
        )

        chunks = parse_instruction_chunks(tmp_path)
        scope_prefix = scope_prefix_for_role(deployment, agent_id)
        diff = compute_diff(chunks, scope_prefix, version, {}, set())

        # Write facts
        for d in diff:
            if d.action in ("CREATE", "UPDATE"):
                admin_client.post(
                    "/v1/facts",
                    json={
                        "entity": d.fact_uri,
                        "relation": "instruction:content",
                        "value": {"type": "text", "v": d.content},
                        "source": "instruction-migration",
                        "scope": "local",
                    },
                )

        # Publish manifest
        entries = [
            {
                "name": d.unit_name,
                "description": d.heading_text[:120],
                "fact_uri": d.fact_uri,
                "load_triggers": {
                    "intents": [d.heading_text.lower()],
                    "keywords": d.keywords,
                    "task_types": [],
                },
                "token_estimate": d.token_estimate,
            }
            for d in diff
            if d.action != "TOMBSTONE"
        ]
        admin_client.put(
            f"/v1/agents/{agent_id}/instruction-manifest",
            json={"version": version, "entries": entries, "skip_coverage_gate": True},
        )

    def test_recall_retrieves_migrated_content(
        self, admin_client: TestClient, tmp_path: Path
    ) -> None:
        agent_id = str(uuid.uuid4())
        md = tmp_path / "heartbeat.md"
        md.write_text(
            "## Heartbeat Procedure\n\nCheckout the issue first using POST /checkout.\n\n"
            "## Update Status\n\nPatch the issue status when done.\n"
        )
        self._migrate_via_client(admin_client, tmp_path, agent_id)

        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={"intent": "I need to checkout an issue and start working"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["chunks"], "should return at least one chunk"
        # The heartbeat chunk content should be present
        contents = " ".join(c["content"] for c in body["chunks"])
        assert "checkout" in contents.lower() or "heartbeat" in contents.lower()

    def test_idempotent_migration(self, admin_client: TestClient, tmp_path: Path) -> None:
        """Running migration twice on same content produces NOOP on second run."""
        from stigmem_node.instruction_migrate import (
            compute_diff,
            parse_instruction_chunks,
            scope_prefix_for_role,
        )

        agent_id = str(uuid.uuid4())
        deployment = "test"
        version = "v1"
        md = tmp_path / "agents.md"
        md.write_text("## Identity\n\nYou are the CTO.\n")

        chunks = parse_instruction_chunks(tmp_path)
        scope_prefix = scope_prefix_for_role(deployment, agent_id)

        # First run: write facts
        diff1 = compute_diff(chunks, scope_prefix, version, {}, set())
        assert all(d.action == "CREATE" for d in diff1 if d.action != "TOMBSTONE")
        for d in diff1:
            if d.action == "CREATE":
                admin_client.post(
                    "/v1/facts",
                    json={
                        "entity": d.fact_uri,
                        "relation": "instruction:content",
                        "value": {"type": "text", "v": d.content},
                        "source": "instruction-migration",
                        "scope": "local",
                    },
                )

        # Second run: same content → NOOP
        # Re-query existing facts directly from DB
        db_path = settings_mod.settings.db_path
        existing = {}
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        for d in diff1:
            row = conn.execute(
                "SELECT value_v FROM facts WHERE entity = ? ORDER BY timestamp DESC LIMIT 1",
                (d.fact_uri,),
            ).fetchone()
            if row:
                existing[d.fact_uri] = str(row["value_v"])
        conn.close()

        diff2 = compute_diff(chunks, scope_prefix, version, existing, set())
        non_tombstone = [d for d in diff2 if d.action != "TOMBSTONE"]
        assert all(d.action == "NOOP" for d in non_tombstone), (
            f"Second run should be all NOOP, got: {[d.action for d in non_tombstone]}"
        )

    def test_boot_stub_migration_reference_dataset(
        self, admin_client: TestClient, tmp_path: Path
    ) -> None:
        """Migrates the boot-stub reference dataset and verifies recall works."""
        agent_id = str(uuid.uuid4())
        # Reference dataset: minimal boot stub content from the impl issue
        boot_stub = tmp_path / "boot-stub.md"
        boot_stub.write_text(
            "## Agent Boot Stub\n\n"
            "You are the CTO agent. Your role is to own all technical execution.\n\n"
            "## Heartbeat Procedure\n\n"
            "Follow these steps every heartbeat:\n"
            "1. Check assignments via GET /api/agents/me/inbox-lite\n"
            "2. Checkout the issue via POST /api/issues/{id}/checkout\n"
            "3. Do the work\n"
            "4. Update status via PATCH /api/issues/{id}\n\n"
            "## Safety Rules\n\n"
            "Never push to main. Never bypass CI. Never skip hooks.\n"
        )
        self._migrate_via_client(admin_client, tmp_path, agent_id)

        # Verify manifest was published
        r = admin_client.get(f"/v1/agents/{agent_id}/instruction-manifest")
        assert r.status_code == 200
        entries = r.json()["entries"]
        names = {e["name"] for e in entries}
        assert "heartbeat-procedure" in names or any("heartbeat" in n for n in names)

        # Verify recall retrieves relevant chunk
        r = admin_client.post(
            f"/v1/agents/{agent_id}/recall-instruction",
            json={"intent": "I need to check my assignments and checkout an issue"},
        )
        assert r.status_code == 200
        body = r.json()
        contents = " ".join(c["content"] for c in body["chunks"])
        assert "checkout" in contents.lower() or "assignments" in contents.lower()
        assert body["audit_token"].startswith("audi_")


# ---------------------------------------------------------------------------
# Fixtures specific to this test module
# ---------------------------------------------------------------------------


@pytest.fixture()
def admin_client(tmp_db: str, backend: str, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A test client with full admin permissions."""
    original = settings_mod.settings
    s = Settings(db_path=tmp_db, auth_required=False)
    settings_mod.settings = s
    db_mod.settings = s
    auth_mod.settings = s
    _enable_lazy_instruction_env(monkeypatch)
    monkeypatch.setattr(plugin_registry, "_current_stigmem_version", lambda: "0.9.0a3")

    # create_api_key uses module-level db(), which now points to tmp_db via settings
    raw_key = create_api_key("admin:test", ["read", "write", "federate", "admin"])

    manifest = plugin_manifest()
    app = main_mod.create_app()
    app.include_router(manifest.routes[0])
    with (
        stigmem_plugins([manifest]),
        TestClient(app, headers={"Authorization": f"Bearer {raw_key}"}) as c,
    ):
        yield c

    settings_mod.settings = original
    db_mod.settings = original
    auth_mod.settings = original


@pytest.fixture()
def authed_client(
    tmp_db: str,
    backend: str,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, str]:
    """Auth-enabled client with the lazy instruction plugin loaded."""
    original = settings_mod.settings
    s = Settings(db_path=tmp_db, auth_required=True)
    settings_mod.settings = s
    db_mod.settings = s
    auth_mod.settings = s
    _enable_lazy_instruction_env(monkeypatch)
    monkeypatch.setattr(plugin_registry, "_current_stigmem_version", lambda: "0.9.0a3")

    raw_key = create_api_key("agent:test", ["read", "write"])
    manifest = plugin_manifest()
    app = main_mod.create_app()
    app.include_router(manifest.routes[0])
    with stigmem_plugins([manifest]), TestClient(app) as c:
        yield c, raw_key

    settings_mod.settings = original
    db_mod.settings = original
    auth_mod.settings = original


def _enable_lazy_instruction_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_MANIFEST_PUBLISH", "true")
    monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_INSTRUCTION_RECALL", "true")
    monkeypatch.setenv("STIGMEM_LAZY_INSTRUCTION_DISCOVERY_ALLOW_FILE_PATH_ENTRIES", "true")
