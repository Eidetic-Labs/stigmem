from __future__ import annotations

import json
import logging
import time
import uuid

import pytest
from conftest import FedNode, make_peer_token

from stigmem_node.db import db as _db_ctx

from .helpers import generate_ed25519_b64, insert_active_peer

logger = logging.getLogger(__name__)


class TestMaliciousPeer:
    """Full acceptance gate for spec §11.2: scope violation + source forgery via push."""

    def _push_node(
        self, fed_node: FedNode, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[str, str, str]:
        """Register an active peer with push enabled. Returns (node_b_id, pub, priv)."""
        import stigmem_node.settings as _settings_mod

        Settings = _settings_mod.Settings

        # Enable push for this test
        original = _settings_mod.settings
        new_settings = Settings(
            db_path=original.db_path,
            auth_required=original.auth_required,
            node_url=original.node_url,
            federation_enabled=original.federation_enabled,
            federation_pubkey=original.federation_pubkey,
            federation_privkey=original.federation_privkey,
            federation_push_enabled=True,
            federation_insecure=True,
        )
        monkeypatch.setattr(_settings_mod, "settings", new_settings)
        for mod_name in [
            "stigmem_node.routes.federation",
            "stigmem_node.federation_ingest",
            "stigmem_node.peer_token",
        ]:
            import importlib

            try:
                mod = importlib.import_module(mod_name)
                if hasattr(mod, "settings"):
                    monkeypatch.setattr(mod, "settings", new_settings)
            except ImportError as exc:
                logger.debug("patchable federation module %s unavailable: %s", mod_name, exc)
                continue

        pub, priv = generate_ed25519_b64()
        node_b_id = f"stigmem://malicious-peer-{uuid.uuid4()}"
        insert_active_peer(
            fed_node.db_path,
            node_b_id,
            "http://malicious-peer",
            pub,
            allowed_scopes=["public"],
        )
        return node_b_id, pub, priv

    def test_scope_violation_rejected_with_audit(
        self, fed_node: FedNode, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§11.2 scenario 1: push fact with disallowed scope → rejected + audit entry."""
        node_b_id, pub, priv = self._push_node(fed_node, monkeypatch)
        token = make_peer_token(priv, node_b_id, fed_node.node_id, ["public", "company"])

        # v2 envelope: the scope check fires before origin verification, so the
        # origin block / signature need not be valid — the scope-violation INTENT
        # is what's under test (reason now surfaces via scope_not_permitted + audit).
        fact = {
            "id": str(uuid.uuid4()),
            "entity": "company:secret",
            "relation": "test:val",
            "value": {"type": "string", "v": "leak"},
            "source": node_b_id,
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{int(time.time() * 1000)}.000",
            "confidence": 1.0,
            "scope": "company",  # peer only allows "public"
            "valid_until": None,
            "cid": "bafytestcid",
        }
        origin = {
            "tenant": "default",
            "node_id": node_b_id,
            "allowed_scopes": ["company"],
            "allowed_tenants": ["default"],
        }
        r = fed_node.client.post(
            "/v1/federation/facts/push",
            json={"v": 2, "facts": [{"fact": fact, "origin": origin, "origin_sig": "x"}]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 202
        data = r.json()
        assert data["rejected"] == 1
        assert data["accepted"] == 0
        assert any(e.get("error") == "scope_not_permitted" for e in data["errors"])

        with _db_ctx() as conn:
            entry = conn.execute(
                "SELECT * FROM federation_audit WHERE event_type = 'scope_violation' LIMIT 1"
            ).fetchone()
        assert entry is not None, "scope_violation audit entry must be written"

    def test_source_forgery_rejected_with_audit(
        self, fed_node: FedNode, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§11.2 scenario 2: push fact with forged source → rejected + rejected_fact audit entry."""
        node_b_id, pub, priv = self._push_node(fed_node, monkeypatch)
        token = make_peer_token(priv, node_b_id, fed_node.node_id, ["public"])

        forged_fact_id = str(uuid.uuid4())
        # v2 envelope: source-non-forgery fires before origin verification, so the
        # origin block / signature need not be valid — the forgery INTENT is the test.
        fact = {
            "id": forged_fact_id,
            "entity": "user:alice",
            "relation": "test:val",
            "value": {"type": "string", "v": "injected"},
            "source": "user:alice",  # not the peer's node_id → forgery
            "timestamp": "2026-05-02T00:00:00Z",
            "hlc": f"{int(time.time() * 1000)}.000",
            "confidence": 1.0,
            "scope": "public",
            "valid_until": None,
            "cid": "bafytestcid",
        }
        origin = {
            "tenant": "default",
            "node_id": node_b_id,
            "allowed_scopes": ["public"],
            "allowed_tenants": ["default"],
        }
        r = fed_node.client.post(
            "/v1/federation/facts/push",
            json={"v": 2, "facts": [{"fact": fact, "origin": origin, "origin_sig": "x"}]},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 202
        data = r.json()
        assert data["rejected"] == 1
        assert data["accepted"] == 0
        assert any(e.get("error") == "source_not_owned" for e in data["errors"])

        with _db_ctx() as conn:
            entry = conn.execute(
                "SELECT detail FROM federation_audit WHERE event_type = 'rejected_fact' LIMIT 1"
            ).fetchone()
        assert entry is not None, "rejected_fact audit entry must be written"
        detail = json.loads(entry["detail"])
        assert detail.get("reason") == "source_not_owned"

        # Forged fact must NOT be in the store
        with _db_ctx() as conn:
            row = conn.execute("SELECT id FROM facts WHERE id = ?", (forged_fact_id,)).fetchone()
        assert row is None, "Forged fact must not be stored"


# ---------------------------------------------------------------------------
# §5.10 — Conflict resolution route
# ---------------------------------------------------------------------------
