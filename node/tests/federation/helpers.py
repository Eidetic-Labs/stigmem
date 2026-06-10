"""Shared helpers for federation integration tests."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_ed25519_b64() -> tuple[str, str]:
    """Return (pubkey_b64url, privkey_b64url) for a new Ed25519 keypair."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return pub_b64, priv_b64


def insert_active_peer(
    db_path: str,
    node_id: str,
    node_url: str,
    pub_b64: str,
    allowed_scopes: list[str] | None = None,
    ingest_tenant: str | None = None,
    pull_tenant: str | None = None,
) -> str:
    """Directly insert an active peer row into the DB (bypasses HTTP verification).

    ``ingest_tenant`` pins the per-peer tenant policy (migration 041); when set,
    inbound facts from this peer are stamped into that tenant by the fail-closed
    resolver.

    ``pull_tenant`` pins the per-peer EGRESS tenant (migration 041); when set,
    the pull endpoint only serves facts belonging to that tenant to this peer.
    """
    peer_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, established_at, declaration_sig, signed_at,
                ingest_tenant, pull_tenant)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                node_id,
                node_url,
                pub_b64,
                json.dumps(allowed_scopes or ["public"]),
                "active",
                "2026-05-02T00:00:00Z",
                "test_dummy_sig",
                "2026-05-02T00:00:00Z",
                ingest_tenant,
                pull_tenant,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return peer_id


def make_federated_fact(
    entity: str = "test:entity",
    relation: str = "test:value",
    value: str = "test-value",
    scope: str = "public",
    hlc_offset_ms: int = 0,
) -> dict[str, Any]:
    base_ms = int(time.time() * 1000)
    return {
        "id": str(uuid.uuid4()),
        "entity": entity,
        "relation": relation,
        "value": {"type": "string", "v": value},
        "source": "stigmem://test-node-b",
        "timestamp": "2026-05-02T00:00:00Z",
        "hlc": f"{base_ms + hlc_offset_ms}.000",
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }
