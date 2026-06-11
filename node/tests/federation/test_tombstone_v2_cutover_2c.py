"""Phase 2c W6.5 — lockstep v2 tombstone wire cutover + issuer-sig verification on pull.

The tombstone poll GET now emits the v2 envelope (``FederationTombstonesResponseV2``):
each tombstone is wrapped in a ``TombstoneEnvelopeEntry`` carrying a signed origin block.
The pull client (``pull_tombstones_from_peer_once``) parses v2 and, for a DIRECT tombstone
(origin.node_id == sending peer), verifies BOTH the origin-attestation signature AND the
issuer-signer signature BEFORE applying. Relay (origin != sender) is SKIPPED here — the
secure relay chain lands in the next task.

Tests:
  (a) GET returns v=2; a self-originated entry has a fresh origin block (this node's
      node_id/entity_uri) + a valid origin_sig accepted by verify_tombstone_origin_signature.
  (b) the pull client parses v2 + applies a DIRECT tombstone after verifying BOTH sigs;
      the entity is suppressed.
  (c) a tombstone whose ISSUER-signer signature is invalid is REJECTED on the pull path.
  (d) a tombstone whose ORIGIN signature is invalid is REJECTED on the pull path.
  (e) a non-v2 page is dropped.
  (f) a relayed tombstone (origin.node_id != sender) is SKIPPED on pull (not applied).
  (g) end-to-end single-node round-trip: issue tombstone -> GET as v2 -> pull-apply on a
      second node suppresses the entity.
"""

from __future__ import annotations

import asyncio
import base64
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.origin_signature import (
    sign_tombstone_origin,
    verify_tombstone_origin_signature,
)
from stigmem_node.lifecycle.tombstone_signing import _signing_body
from stigmem_node.lifecycle.tombstones import (
    create_tombstone,
    list_tombstones,
)
from stigmem_node.models.tombstones import TombstoneRecord

from .helpers import generate_ed25519_b64, make_bound_peer

_TENANT = "default"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _tombstone_in_db(entity_uri: str) -> bool:
    """True iff a tombstone row exists for *entity_uri* (storage-layer suppression).

    The recall-time ``is_tombstoned`` filter is gated behind the tombstone plugin + env
    flags (``tombstone_filter_enabled``), which the bare ``fed_node`` fixture does not
    enable; the pull path's job is to WRITE the suppression row, so we assert that directly.
    """
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT 1 FROM tombstones WHERE entity_uri = ?", (entity_uri,)
        ).fetchone()
    return row is not None


def _issuer_signed_tombstone(
    issuer_priv: Ed25519PrivateKey,
    *,
    entity_uri: str,
    scope: str = "*",
    signed_by: str,
    key_id: str = "key-1",
) -> TombstoneRecord:
    """Build a TombstoneRecord carrying a valid ISSUER-signer signature."""
    rec = TombstoneRecord(
        id=f"tomb_{uuid.uuid4()}",
        entity_uri=entity_uri,
        scope=scope,
        reason=None,
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    sig = base64.urlsafe_b64encode(issuer_priv.sign(_signing_body(rec))).decode().rstrip("=")
    return rec.model_copy(update={"signature": sig})


# ---------------------------------------------------------------------------
# (a) GET emits v2 with a valid self-originated origin block
# ---------------------------------------------------------------------------


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    """The poll route reads trust_mode from sys.modules['stigmem_node.routes.federation'].
    Set it to 'off' so a peer-JWT Bearer token passes the poll auth without a
    tombstone:read capability token (mirrors the existing tombstone poll tests)."""
    import sys as _sys

    fed_mod = _sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_mod.settings, "trust_mode", "off", raising=False)


def test_get_returns_v2_self_originated_origin_block(fed_node: Any, _trust_off: None) -> None:
    """(a) GET /v1/federation/tombstones returns v=2 with a fresh self-originated origin
    block (this node's node_id/entity_uri) and a valid origin_sig."""
    from conftest import make_peer_token  # noqa: PLC0415

    # A tombstone created locally is self-originated (received_from is NULL).
    create_tombstone(
        "user:alice",
        "*",
        None,
        "stigmem://tombnode/issuer",
        "key-1",
        "issuer-sig",
        tenant_id=_TENANT,
    )

    node_b_pub, node_b_priv = generate_ed25519_b64()
    node_b_id = f"stigmem://test-b-{uuid.uuid4()}"
    from .helpers import insert_active_peer  # noqa: PLC0415

    insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b", node_b_pub)

    token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])
    # tombstone:read capability is checked only when trust_mode != off; fed_node uses a peer
    # JWT in the Authorization header which the poll route accepts via token parsing. The
    # poll route requires a Bearer token; use the peer token.
    resp = fed_node.client.get(
        "/v1/federation/tombstones",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["v"] == 2
    entries = body["tombstones"]
    entry = next(e for e in entries if e["tombstone"]["entity_uri"] == "user:alice")
    origin = entry["origin"]
    # Fresh origin block carries THIS node's identity.
    assert origin["node_id"] == fed_node.node_id
    assert origin["entity_uri"] == fed_node.node_url  # get_node_entity_uri() == node_url here
    # The self-originated origin_sig verifies against THIS node's federation key.
    verify_tombstone_origin_signature(
        entry["origin_sig"],
        tombstone_id=entry["tombstone"]["id"],
        entity_uri="user:alice",
        scope="*",
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
        allowed_pubkeys={fed_node.pub_b64},
    )


# ---------------------------------------------------------------------------
# Shared helpers for the pull-client tests (b)-(f)
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _FakeClient:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body

    async def get(self, *_a: Any, **_k: Any) -> _FakeResponse:
        return _FakeResponse(self._body)


def _build_origin(
    *,
    node_id: str,
    entity_uri: str,
    tenant: str = _TENANT,
    allowed_scopes: list[str] | None = None,
    allowed_tenants: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tenant": tenant,
        "node_id": node_id,
        "allowed_scopes": allowed_scopes if allowed_scopes is not None else ["*"],
        "allowed_tenants": allowed_tenants if allowed_tenants is not None else [tenant],
        "entity_uri": entity_uri,
    }


def _build_v2_tombstone_entry(
    origin_priv: Ed25519PrivateKey,
    *,
    tombstone: TombstoneRecord,
    origin: dict[str, Any],
    origin_sig: str | None = None,
) -> dict[str, Any]:
    if origin_sig is None:
        origin_sig = sign_tombstone_origin(
            origin_priv,
            tombstone_id=tombstone.id,
            entity_uri=tombstone.entity_uri,
            scope=tombstone.scope,
            origin_node_id=origin["node_id"],
            origin_tenant=origin["tenant"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_entity_uri=origin["entity_uri"],
        )
    return {
        "tombstone": tombstone.model_dump(),
        "origin": origin,
        "origin_sig": origin_sig,
    }


def _v2_page(entries: list[dict[str, Any]], cursor: str | None = None) -> dict[str, Any]:
    return {"v": 2, "tombstones": entries, "revocations": [], "cursor": cursor}


def _peer_dict(node_id: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": node_id,
        "node_url": "http://peer",
        "allowed_scopes": json.dumps(["public", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": 0,
    }


@pytest.fixture()
def bound_peer_node(fed_node: Any) -> tuple[Any, str, str, Ed25519PrivateKey, str]:
    """fed_node + an active, entity_uri-bound peer (the SENDER/ORIGIN) whose manifest is
    stored so resolve_origin_key(sender) and get_peer_manifest(signer) both resolve.

    Returns the manifest ``key_id`` too, since the issuer-signer verification resolves the
    pubkey by key_id from the stored manifest (make_bound_peer uses generate_key_id)."""
    from stigmem_node.identity.key_rotation import generate_key_id  # noqa: PLC0415

    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"
    key_id = generate_key_id(sender_priv.public_key())
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        conn.commit()
    return fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id


# ---------------------------------------------------------------------------
# (b) pull client applies a DIRECT tombstone after verifying BOTH sigs
# ---------------------------------------------------------------------------


def test_pull_applies_direct_tombstone_after_both_sigs(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(b) DIRECT tombstone (origin == sender) with valid origin sig + valid issuer sig is
    applied; the entity is suppressed."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    # The issuer IS the sender node here (signed_by == sender_entity_uri, manifest stored).
    rec = _issuer_signed_tombstone(
        sender_priv, entity_uri="user:bob", signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_tombstone_entry(sender_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="c1")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert new_cursor == "c1"
    assert _tombstone_in_db("user:bob") is True


# ---------------------------------------------------------------------------
# (c) invalid ISSUER-signer signature is REJECTED on pull
# ---------------------------------------------------------------------------


def test_pull_rejects_invalid_issuer_signature(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(c) A tombstone whose ISSUER-signer signature is invalid is REJECTED on the pull path
    (proves the new pull-side issuer check)."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    rec = _issuer_signed_tombstone(
        sender_priv, entity_uri="user:carol", signed_by=sender_entity_uri, key_id=key_id
    )
    # Corrupt the issuer signature (origin sig stays valid).
    rec = rec.model_copy(update={"signature": "AAAA" + rec.signature[4:]})
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_tombstone_entry(sender_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry])

    asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert _tombstone_in_db("user:carol") is False


# ---------------------------------------------------------------------------
# (d) invalid ORIGIN signature is REJECTED on pull
# ---------------------------------------------------------------------------


def test_pull_rejects_invalid_origin_signature(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(d) A tombstone whose ORIGIN signature is invalid is REJECTED."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    rec = _issuer_signed_tombstone(
        sender_priv, entity_uri="user:dave", signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    # A garbage origin_sig (issuer sig stays valid).
    entry = _build_v2_tombstone_entry(
        sender_priv, tombstone=rec, origin=origin, origin_sig="not-a-valid-sig"
    )
    page = _v2_page([entry])

    asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert _tombstone_in_db("user:dave") is False


# ---------------------------------------------------------------------------
# (e) non-v2 page is dropped
# ---------------------------------------------------------------------------


def test_pull_drops_non_v2_page(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(e) A non-v2 page is dropped wholesale; nothing applied, cursor not advanced."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    rec = _issuer_signed_tombstone(
        sender_priv, entity_uri="user:erin", signed_by=sender_entity_uri, key_id=key_id
    )
    # v1-shaped page (no "v" key, raw tombstone list).
    v1_page = {
        "tombstones": [rec.model_dump()],
        "revocations": [],
        "cursor": "v1-cursor",
    }
    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(v1_page), "old")
    )
    assert new_cursor == "old"  # cursor unchanged
    assert _tombstone_in_db("user:erin") is False


# ---------------------------------------------------------------------------
# (f) relayed tombstone (origin != sender) is SKIPPED on pull
# ---------------------------------------------------------------------------


def test_pull_skips_relayed_tombstone(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(f) A relayed tombstone (origin.node_id != sender) is SKIPPED — relay not yet
    enabled; the secure relay chain arrives in the next task."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    # Origin is a DIFFERENT node than the sender.
    other_node_id = f"stigmem://other-{uuid.uuid4()}"
    other_entity_uri = "https://other.example"
    rec = _issuer_signed_tombstone(
        sender_priv, entity_uri="user:frank", signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=other_node_id, entity_uri=other_entity_uri)
    entry = _build_v2_tombstone_entry(sender_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="c2")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    # Page cursor still advances (page consumed) but the relayed entry is not applied.
    assert new_cursor == "c2"
    assert _tombstone_in_db("user:frank") is False


# ---------------------------------------------------------------------------
# (g) end-to-end single-node round-trip
# ---------------------------------------------------------------------------


def test_end_to_end_roundtrip_suppresses_entity(fed_node: Any, _trust_off: None) -> None:
    """(g) issue tombstone -> list via GET as v2 -> pull-apply on a second node suppresses
    the entity. The 'second node' here pulls from fed_node's GET output and applies it."""
    from conftest import make_peer_token  # noqa: PLC0415

    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    from .helpers import insert_active_peer  # noqa: PLC0415

    # ---- Node A: issue a tombstone, register a bound peer that is BOTH the GET caller and
    # the origin the pull verifies against. Node A's own federation key is the origin key, so
    # bind node A's identity as a peer on its OWN db (so resolve_origin_key(node_a) resolves).
    create_tombstone(
        "user:grace",
        "*",
        None,
        fed_node.node_url,  # signed_by == node A's entity_uri (issuer == origin == node A)
        "key-1",
        "ignored-on-emit",
        tenant_id=_TENANT,
    )
    # Re-sign the stored issuer signature with node A's key so the issuer check passes on
    # pull (create_tombstone stored a placeholder signature). The issuer verify resolves the
    # pubkey by key_id from node A's stored manifest, so set the row's key_id to node A's
    # manifest key_id and re-sign the body with that key_id baked in.
    from stigmem_node.identity.key_rotation import generate_key_id  # noqa: PLC0415

    priv_a = _priv_from_b64(fed_node.priv_b64)
    node_a_key_id = generate_key_id(priv_a.public_key())
    rows = list_tombstones()
    rec = next(r for r in rows if r.entity_uri == "user:grace")
    rec = rec.model_copy(update={"key_id": node_a_key_id})
    valid_sig = base64.urlsafe_b64encode(priv_a.sign(_signing_body(rec))).decode().rstrip("=")
    with _db_ctx() as conn:
        conn.execute(
            "UPDATE tombstones SET signature = ?, key_id = ? WHERE id = ?",
            (valid_sig, node_a_key_id, rec.id),
        )
        conn.commit()

    # Bind node A's own identity as an active peer + stored manifest so resolve_origin_key
    # (node A) and get_peer_manifest(node A entity_uri) both resolve on the pull path.
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=fed_node.node_id,
            entity_uri=fed_node.node_url,
            pub_b64=fed_node.pub_b64,
            priv=priv_a,
        )
        conn.commit()

    # Register a separate peer for the GET caller auth.
    caller_pub, caller_priv = generate_ed25519_b64()
    caller_id = f"stigmem://caller-{uuid.uuid4()}"
    insert_active_peer(fed_node.db_path, caller_id, "http://caller", caller_pub)
    token = make_peer_token(caller_priv, caller_id, fed_node.node_id, ["public"])
    resp = fed_node.client.get(
        "/v1/federation/tombstones",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["v"] == 2

    # ---- "Node B": feed node A's GET body straight into the pull client. (Same DB here, so
    # this proves the wire round-trip + verification path end-to-end.) First clear the local
    # tombstone so we observe the pull-applied one re-suppressing.
    with _db_ctx() as conn:
        conn.execute("DELETE FROM tombstones WHERE id = ?", (rec.id,))
        conn.commit()
    from stigmem_node.lifecycle.tombstones import invalidate_tombstone_cache

    invalidate_tombstone_cache()
    assert _tombstone_in_db("user:grace") is False

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(fed_node.node_id), _FakeClient(body), None
        )
    )
    assert _tombstone_in_db("user:grace") is True
