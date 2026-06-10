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


def make_bound_peer(
    conn: sqlite3.Connection,
    *,
    node_id: str,
    entity_uri: str,
    pub_b64: str,
    priv: Ed25519PrivateKey,
) -> str:
    """Insert an active, entity_uri-bound peer + store its self-verifying manifest.

    Mirrors the 2a ``_store_peer_with_manifest`` pattern so that
    ``resolve_origin_key(node_id)`` returns ``{pub_b64}``: the peer row is active and
    bound to *entity_uri*, and an OrgManifest whose ``public_key == pub_b64`` (signed by
    *priv*, entities include both the entity_uri and node_id) is stored for that
    entity_uri. Validity window is fixed valid (issued 2026-01-01 / expires 2026-12-01).

    The peer row is inserted on the supplied *conn* (caller commits); the manifest is
    stored via ``store_peer_manifest`` on its own connection. Returns the peer id.
    """
    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest
    from stigmem_node.identity.trust_store import store_peer_manifest

    manifest = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(manifest, priv)
    store_peer_manifest(entity_uri, manifest, None, trust_mode="relaxed")

    peer_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO peers
           (id, node_id, node_url, federation_pubkey, allowed_scopes,
            status, entity_uri, declaration_sig, signed_at)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            peer_id,
            node_id,
            "http://x",
            pub_b64,
            json.dumps(["public"]),
            "active",
            entity_uri,
            "test_dummy_sig",
            "2026-01-01T00:00:00Z",
        ),
    )
    return peer_id


def make_v2_entry(
    priv: Ed25519PrivateKey,
    *,
    fact: dict[str, Any],
    origin: dict[str, Any],
) -> dict[str, Any]:
    """Build one v2 envelope entry: ensure the fact's CID, then origin-sign it.

    The CID is computed via ``compute_cid`` with ``value_v = _encode_v(fact["value"])``,
    matching ``_verify_inbound_cid`` exactly so ingest accepts the fact. If the fact
    already carries a ``cid`` it is preserved.
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
    sig = sign_origin(
        priv,
        fact_id=fact["id"],
        cid=fact["cid"],
        origin=origin,
        valid_until=fact.get("valid_until"),
    )
    return {"fact": fact, "origin": origin, "origin_sig": sig}


def make_v2_envelope(
    priv: Ed25519PrivateKey,
    *,
    facts: list[dict[str, Any]],
    origin: dict[str, Any],
    cursor: str | None = None,
    has_more: bool = False,
) -> dict[str, Any]:
    """Build a v2 wire envelope around *facts*, each origin-signed by *priv*."""
    return {
        "v": 2,
        "facts": [make_v2_entry(priv, fact=f, origin=origin) for f in facts],
        "cursor": cursor,
        "has_more": has_more,
    }


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
