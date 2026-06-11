from __future__ import annotations

import base64
import importlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from stigmem_node.auth import Identity
from stigmem_node.db import db
from stigmem_node.models.facts import FactRecord, FactValue
from stigmem_node.models.recall import RecallWeights
from stigmem_node.plugins.testing import stigmem_plugins
from stigmem_node.routes.federation.replication import _push_fact_with_peer_token
from stigmem_node.routes.recall.ranking import _score_candidates

# tests/federation/ is a package but tests/plugins/ is not, so a relative import
# is unavailable; add the federation test dir to the path to reuse its v2 helpers.
_FED_TEST_DIR = Path(__file__).resolve().parents[1] / "federation"
if str(_FED_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_FED_TEST_DIR))
from helpers import make_bound_peer, make_v2_entry  # noqa: E402

_FEATURE_DIR = Path(__file__).resolve().parents[3] / "experimental" / "source-attestation"
_SRC_DIR = _FEATURE_DIR / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

_PLUGIN = importlib.import_module("stigmem_plugin_source_attestation")
plugin_manifest = _PLUGIN.plugin_manifest

FACT = {
    "entity": "stigmem://example.test/user/alice",
    "relation": "memory:role",
    "value": {"type": "string", "v": "writer"},
    "source": "stigmem://example.test/agent/other",
    "confidence": 1.0,
    "scope": "company",
}


def _bound_v2_federated_fact(
    node_id: str, *, scope: str = "public"
) -> tuple[dict, dict, str]:
    """Create a bound peer + signed v2 entry whose source == *node_id*.

    The per-fact origin verification now runs BEFORE the plugin hook, so the
    federated fact must pass it (bound peer + valid origin signature) to reach
    the source-attestation ``federation_inbound_validate`` boundary. Returns the
    (fact, origin, origin_sig) entry triple. Requires an active DB (``client``).
    """
    priv = Ed25519PrivateKey.generate()
    pub = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    with db() as conn:
        make_bound_peer(
            conn,
            node_id=node_id,
            entity_uri=f"https://{node_id.split('/')[-1]}.example",
            pub_b64=pub,
            priv=priv,
        )
        conn.commit()
    fact = {
        "id": "fed-fact-1",
        "entity": "stigmem://peer.example/user/alice",
        "relation": "memory:role",
        "value": {"type": "string", "v": "writer"},
        "source": node_id,
        "timestamp": "2026-06-01T00:00:00Z",
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }
    origin = {
        "tenant": "default",
        "node_id": node_id,
        "allowed_scopes": [scope],
        "allowed_tenants": ["default"],
        "entity_uri": f"https://{node_id.split('/')[-1]}.example",
    }
    entry = make_v2_entry(priv, fact=fact, origin=origin)
    return entry["fact"], entry["origin"], entry["origin_sig"]


def test_default_install_keeps_assert_source_attestation_inert(client: TestClient) -> None:
    response = client.post("/v1/facts", json=FACT)

    assert response.status_code == 201, response.text
    assert response.json()["attested"] is None


def test_default_install_ignores_assertion_environment_gates(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_ASSERT_VALIDATION", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")

    response = client.post("/v1/facts", json=FACT)

    assert response.status_code == 201, response.text
    assert response.json()["attested"] is None


def test_plugin_loaded_enforces_assert_source_mismatch(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_ASSERT_VALIDATION", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")

    with stigmem_plugins([plugin_manifest()]):
        response = client.post("/v1/facts", json=FACT)

    assert response.status_code == 422
    assert "source_attestation_failed" in response.json()["detail"]


def test_plugin_loaded_allows_assert_source_match(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_ASSERT_VALIDATION", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")
    fact = {**FACT, "source": "anon:trusted"}

    with stigmem_plugins([plugin_manifest()]):
        response = client.post("/v1/facts", json=fact)

    assert response.status_code == 201, response.text


def test_plugin_loaded_allows_normalized_assert_source_match(
    client: TestClient,
    monkeypatch,
) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_ASSERT_VALIDATION", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")
    fact = {**FACT, "source": " ANON:TRUSTED "}

    with stigmem_plugins([plugin_manifest()]):
        response = client.post("/v1/facts", json=fact)

    assert response.status_code == 201, response.text


def test_recall_rank_hook_site_is_inert_until_plugin_gate_enabled(migrated_db, monkeypatch) -> None:
    record = _fact_record()
    identity = Identity("stigmem://example.test/agent/caller", ["read"])
    weights = RecallWeights(lexical=0.0, semantic=0.0, graph=0.0, source_trust=1.0, recency=0.0)

    default_scores = _score_candidates(
        {record.id: record},
        {record.id: 0.0},
        {},
        {},
        weights,
        identity,
        depth=1,
    )

    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_APPLY_RECALL_RANK", "true")
    monkeypatch.setattr("stigmem_node.source_trust.compute_source_trust", lambda *_: 0.8)
    with stigmem_plugins([plugin_manifest()]):
        plugin_scores = _score_candidates(
            {record.id: record},
            {record.id: 0.0},
            {},
            {},
            weights,
            identity,
            depth=1,
        )

    assert default_scores[0].score == 0.0
    assert plugin_scores[0].score > default_scores[0].score


def test_default_install_ignores_recall_rank_environment_gates(migrated_db, monkeypatch) -> None:
    record = _fact_record()
    identity = Identity("stigmem://example.test/agent/caller", ["read"])
    weights = RecallWeights(lexical=0.0, semantic=0.0, graph=0.0, source_trust=1.0, recency=0.0)
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_APPLY_RECALL_RANK", "true")

    def fail_if_called(*_args, **_kwargs) -> float:
        raise AssertionError("source trust must remain plugin-owned")

    monkeypatch.setattr("stigmem_node.source_trust.compute_source_trust", fail_if_called)

    default_scores = _score_candidates(
        {record.id: record},
        {record.id: 0.0},
        {},
        {},
        weights,
        identity,
        depth=1,
    )

    assert default_scores[0].score == 0.0


def test_plugin_loaded_ignores_recall_rank_when_source_weight_disabled(
    migrated_db, monkeypatch
) -> None:
    record = _fact_record()
    identity = Identity("stigmem://example.test/agent/caller", ["read"])
    weights = RecallWeights(
        lexical=1.0,
        semantic=0.0,
        graph=0.0,
        source_trust=0.0,
        recency=0.0,
    )
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_APPLY_RECALL_RANK", "true")

    def fail_if_called(*_args, **_kwargs) -> float:
        raise AssertionError("source trust must not run when source_trust weight is zero")

    monkeypatch.setattr("stigmem_node.source_trust.compute_source_trust", fail_if_called)

    with stigmem_plugins([plugin_manifest()]):
        plugin_scores = _score_candidates(
            {record.id: record},
            {record.id: 0.0},
            {},
            {},
            weights,
            identity,
            depth=1,
        )

    assert plugin_scores[0].score == 0.0


def test_default_install_ignores_federation_environment_gates(client, monkeypatch) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_FEDERATION_INBOUND", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")
    node_id = "stigmem://peer.example/node/a"
    fact, origin, origin_sig = _bound_v2_federated_fact(node_id)
    peer = {
        "id": "peer-a",
        "node_id": node_id,
        "allowed_scopes": '["public"]',
    }

    monkeypatch.setattr(
        "stigmem_node.routes.federation.replication._public_module",
        _FederationIngestStub,
    )

    ok, error = _push_fact_with_peer_token(
        fact,
        "public",
        origin,
        origin_sig,
        peer,
        {"scopes": ["public"]},
    )

    assert ok is True
    assert error is None


def test_plugin_loaded_preserves_federated_fact_attestation_boundary(client, monkeypatch) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_FEDERATION_INBOUND", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")
    node_id = "stigmem://peer.example/node/a"
    fact, origin, origin_sig = _bound_v2_federated_fact(node_id)
    peer = {
        "id": "peer-a",
        "node_id": node_id,
        "allowed_scopes": '["public"]',
    }
    _FederationIngestStub.ingested_facts = []

    monkeypatch.setattr(
        "stigmem_node.routes.federation.replication._public_module",
        _FederationIngestStub,
    )
    with stigmem_plugins([plugin_manifest()]):
        ok, error = _push_fact_with_peer_token(
            fact,
            "public",
            origin,
            origin_sig,
            peer,
            {"scopes": ["public"]},
        )

    assert ok is True
    assert error is None
    assert _FederationIngestStub.ingested_facts == [fact]
    assert "attested" not in _FederationIngestStub.ingested_facts[0]


def test_plugin_loaded_preserves_baseline_federation_inbound_match(client, monkeypatch) -> None:
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_ENFORCE_FEDERATION_INBOUND", "true")
    monkeypatch.setenv("STIGMEM_SOURCE_ATTESTATION_WARN_ONLY", "false")
    node_id = "stigmem://peer.example/node/a"
    fact, origin, origin_sig = _bound_v2_federated_fact(node_id)
    peer = {
        "id": "peer-a",
        "node_id": node_id,
        "allowed_scopes": '["public"]',
    }

    monkeypatch.setattr(
        "stigmem_node.routes.federation.replication._public_module",
        _FederationIngestStub,
    )
    with stigmem_plugins([plugin_manifest()]):
        ok, error = _push_fact_with_peer_token(
            fact,
            "public",
            origin,
            origin_sig,
            peer,
            {"scopes": ["public"]},
        )

    assert ok is True
    assert error is None


def _fact_record() -> FactRecord:
    return FactRecord(
        id="fact-1",
        entity="stigmem://example.test/user/alice",
        relation="memory:role",
        value=FactValue(type="string", v="writer"),
        source="stigmem://example.test/agent/source",
        timestamp=datetime.now(UTC).isoformat(),
        confidence=1.0,
        scope="public",
    )


class _FederationIngestStub:
    ingested_facts: list[dict[str, object]] = []

    def ingest_fact(self, fact: dict[str, object], *_args, **_kwargs) -> None:
        self.ingested_facts.append(fact)
        return None

    def write_audit_log(self, *_args, **_kwargs) -> None:
        return None
