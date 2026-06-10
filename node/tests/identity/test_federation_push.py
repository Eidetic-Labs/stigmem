from __future__ import annotations

import base64
import sqlite3
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import stigmem_node.settings as settings_module
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


def _priv_from_settings() -> Ed25519PrivateKey:
    raw = settings_module.settings.node_private_key
    return Ed25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    )


def _bind_issuer_as_peer(client: TestClient, issuer: str) -> None:
    """Register *issuer* as an active, entity_uri-bound peer using the node's fed key.

    The push fixture already publishes a self-verifying manifest for *issuer* (the
    cap-token subject), so this peer row makes ``resolve_origin_key(issuer)`` succeed.
    """
    db_path = settings_module.settings.db_path
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, entity_uri, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                issuer,
                "http://issuer",
                settings_module.settings.federation_pubkey,
                '["public"]',
                "active",
                issuer,
                "dummy_sig",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _v2_body(issuer: str, fact: dict[str, Any]) -> dict[str, Any]:
    """Wrap *fact* in a signed v2 push body (origin.node_id == cap-token subject).

    Computes the CID exactly as ``_verify_inbound_cid`` does so ingest accepts the
    fact, then signs the origin tuple with the node's federation key.
    """
    from stigmem_node.cid import compute_cid
    from stigmem_node.federation.federation_ingest import _encode_v
    from stigmem_node.federation.origin_signature import sign_origin

    value = fact["value"]
    if not fact.get("cid"):
        fact["cid"] = compute_cid(
            entity=fact["entity"],
            relation=fact["relation"],
            value_type=value["type"],
            value_v=_encode_v(value),
            source=fact["source"],
            scope=fact["scope"],
            confidence=float(fact.get("confidence", 1.0)),
            interpret_as=str(value.get("interpret_as", "content")),
        )
    origin = {
        "tenant": "default",
        "node_id": issuer,
        "allowed_scopes": [fact["scope"]],
        "allowed_tenants": ["default"],
    }
    sig = sign_origin(
        _priv_from_settings(),
        fact_id=fact["id"],
        cid=fact["cid"],
        origin=origin,
        valid_until=fact.get("valid_until"),
    )
    return {"v": 2, "facts": [{"fact": fact, "origin": origin, "origin_sig": sig}]}


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
    # Phase 2b: the cap-token subject must be an entity_uri-bound peer for its
    # origin key to resolve; the fixture already published its manifest.
    _bind_issuer_as_peer(client, issuer)

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    fact = {
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
    resp = client.post(
        "/v1/federation/facts/push",
        json=_v2_body(issuer, fact),
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

    fact = {
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
    resp2 = client.post(
        "/v1/federation/facts/push",
        json=_v2_body(issuer, fact),
        headers={"X-Stigmem-Capability": read_token_json},
    )
    assert resp2.status_code == 403, resp2.text
    assert "insufficient_capability" in resp2.json().get("detail", "")


def test_push_facts_no_auth_rejected(push_client: tuple[TestClient, str, str]) -> None:
    """Push without any auth header must return 401 (H-SEC-2)."""
    client, issuer, _ = push_client

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()

    fact = {
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
    resp = client.post(
        "/v1/federation/facts/push",
        json=_v2_body(issuer, fact),
    )
    assert resp.status_code == 401, resp.text


# ===========================================================================
# 18. M-SEC-3 — CLI capability subcommand parser structure
# ===========================================================================
