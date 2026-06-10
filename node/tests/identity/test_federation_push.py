from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from stigmem_node.identity.manifest import manifest_to_dict
from stigmem_node.main import create_app

from .helpers import (
    Settings,
    apply_migrations,
    gen_keypair,
    make_manifest,
    patched_test_settings,
    seed_fed_keypair,
)


@pytest.fixture()
def push_client(tmp_path: Path) -> Generator[tuple[TestClient, str, str], None, None]:
    """TestClient with federation_push_enabled + node_private_key set.

    Yields (client, issuer_uri, token_json) where token_json is a valid
    write capability token signed by the node key.
    """
    db_file = str(tmp_path / "push_test.db")
    apply_migrations(db_path=db_file)

    priv, pub_b64, priv_b64 = gen_keypair()
    issuer = "anon:trusted"  # matches auth_required=False entity_uri

    # Fed Phase 2a: published manifest public_key must equal this node's federation key.
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        node_private_key=priv_b64,
        federation_push_enabled=True,
        federation_insecure=True,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            # Register manifest so verify_token can resolve issuer
            m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])
            resp = client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            assert resp.status_code == 200, resp.text

            # Issue a write capability token
            resp2 = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": issuer,
                    "verb": "write",
                    "object": "stigmem://facts",
                },
            )
            assert resp2.status_code == 201, resp2.text
            token_json = resp2.json()["token_json"]

            yield client, issuer, token_json


def test_push_facts_capability_token_accepted(
    push_client: tuple[TestClient, str, str],
) -> None:
    """Push facts with a valid write capability token must be accepted (H-SEC-2)."""
    client, issuer, token_json = push_client

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    resp = client.post(
        "/v1/federation/facts/push",
        json={
            "facts": [
                {
                    "id": fact_id,
                    "entity": "test:push-cap",
                    "relation": "test:value",
                    "value": {"type": "string", "v": "hello"},
                    "source": issuer,
                    "timestamp": now,
                    "hlc": None,
                    "confidence": 1.0,
                    "scope": "public",
                    "valid_until": None,
                }
            ]
        },
        headers={"X-Stigmem-Capability": token_json},
    )
    assert resp.status_code == 202, resp.text
    data = resp.json()
    assert data["accepted"] == 1
    assert data["rejected"] == 0


def test_push_facts_capability_token_read_verb_rejected(
    push_client: tuple[TestClient, str, str],
) -> None:
    """A capability token with verb=read must be rejected for push (H-SEC-2)."""
    client, issuer, _ = push_client

    # Issue a read-only token
    resp = client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": issuer,
            "verb": "read",
            "object": "stigmem://facts",
        },
    )
    assert resp.status_code == 201, resp.text
    read_token_json = resp.json()["token_json"]

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    resp2 = client.post(
        "/v1/federation/facts/push",
        json={
            "facts": [
                {
                    "id": fact_id,
                    "entity": "test:push-read-cap",
                    "relation": "test:value",
                    "value": {"type": "string", "v": "rejected"},
                    "source": issuer,
                    "timestamp": now,
                    "hlc": None,
                    "confidence": 1.0,
                    "scope": "public",
                    "valid_until": None,
                }
            ]
        },
        headers={"X-Stigmem-Capability": read_token_json},
    )
    assert resp2.status_code == 403, resp2.text
    assert "insufficient_capability" in resp2.json().get("detail", "")


def test_push_facts_no_auth_rejected(push_client: tuple[TestClient, str, str]) -> None:
    """Push without any auth header must return 401 (H-SEC-2)."""
    client, issuer, _ = push_client

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    resp = client.post(
        "/v1/federation/facts/push",
        json={
            "facts": [
                {
                    "id": fact_id,
                    "entity": "test:no-auth",
                    "relation": "test:value",
                    "value": {"type": "string", "v": "nope"},
                    "source": issuer,
                    "timestamp": now,
                    "hlc": None,
                    "confidence": 1.0,
                    "scope": "public",
                    "valid_until": None,
                }
            ]
        },
    )
    assert resp.status_code == 401, resp.text


# ===========================================================================
# 18. M-SEC-3 — CLI capability subcommand parser structure
# ===========================================================================
