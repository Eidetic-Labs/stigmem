"""Phase 2c Rev-2 — lockstep v2 revocation wire cutover + emit + egress gate.

Mirrors the tombstone W6.5 (wire cutover) + W6.6 (egress gate) on the REVOCATION path.
The tombstone poll GET now emits the v2 revocation envelope (``RevocationEnvelopeEntry``):
each revocation is wrapped with a signed origin block. The pull client
(``pull_tombstones_from_peer_once`` -> ``ingest_revocation_entry``) parses v2 and, for a
DIRECT revocation (origin.node_id == sending peer), verifies BOTH the revocation
origin-attestation signature AND the issuer-signer signature BEFORE applying. Relay
(origin != sender) is SKIPPED here — the secure relay chain lands in Rev-3.

A revocation has NO entity_uri/scope of its own — it references a tombstone by
``tombstone_id`` — so its egress gate is TENANT-only (no scope gate).

Tests:
  (a) GET returns enveloped revocations; a self-originated revocation entry has a fresh
      origin block + a valid origin_sig (verify_revocation_origin_signature accepts it).
  (b) the pull client parses + applies a DIRECT revocation after verifying BOTH sigs;
      the referenced tombstone is reinstated (revocation row present in DB).
  (c) an invalid revocation ORIGIN signature is REJECTED on pull.
  (d) an invalid ISSUER-signer signature is REJECTED on pull.
  (e) a relayed revocation (origin.node_id != sender) is SKIPPED (Rev-3 enables it).
  (f) egress gate: relay OFF → only self-originated egress; relay ON → a relayed
      revocation whose origin_allowed_tenants ∩ peer tenants ≠ ∅ egresses, else withheld;
      pagination correct (filter in SQL, no short non-final page).
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from conftest import FedNode, make_peer_token
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.origin_signature import (
    sign_revocation_origin,
    verify_revocation_origin_signature,
)
from stigmem_node.lifecycle.tombstone_signing import _revocation_signing_body
from stigmem_node.models.tombstones import TombstoneRevocationRecord

from .helpers import generate_ed25519_b64, insert_active_peer, make_bound_peer

_TENANT = "default"
_ORIGIN_NODE_ID = "stigmem:node:rev-upstream-origin"
_ORIGIN_TENANT = "acme"
_ORIGIN_ENTITY_URI = "https://rev-upstream-origin.example"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    """trust_mode=off so a peer-JWT Bearer token passes the poll auth (mirrors W6.5/W6.6)."""
    import sys as _sys

    fed_mod = _sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_mod.settings, "trust_mode", "off", raising=False)


def _set_relay_enabled(value: bool) -> None:
    import stigmem_node.settings as _settings_mod

    _settings_mod.settings.federation_relay_enabled = value


def _insert_tombstone(
    db_path: str,
    *,
    tombstone_id: str,
    entity_uri: str,
    signed_by: str = "stigmem://local/issuer",
) -> None:
    """Insert a plain (self) tombstone row the revocation can reference.

    ``signed_by`` is the tombstone's ISSUER. Same-issuer binding (RTBF integrity) requires a
    revocation's ``signed_by`` to match this for it to apply — happy-path callers pass the
    revoking signer's URI here.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tombstone_id,
                entity_uri,
                "*",
                None,
                signed_by,
                "key-1",
                "issuer-sig",
                "2026-06-10T00:00:00Z",
                0,
                _TENANT,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _insert_self_revocation(
    db_path: str, *, tombstone_id: str, created_at: str
) -> str:
    """Insert a SELF-originated revocation (received_from IS NULL)."""
    rev_id = f"tombrevoke_{uuid.uuid4()}"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                rev_id,
                tombstone_id,
                "",
                "stigmem://local/issuer",
                "key-1",
                "issuer-sig",
                created_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return rev_id


def _insert_relayed_revocation(
    db_path: str,
    *,
    tombstone_id: str,
    created_at: str,
    origin_allowed_tenants: list[str],
) -> str:
    """Insert an INBOUND (relayed) revocation row (received_from IS NOT NULL) + origin block.

    origin_allowed_* are stored with the canonical ``json.dumps(sorted([...]))`` encoding
    (the same encoding ingest uses). A stored origin_sig + origin_entity_uri are set so the
    emit path forwards rather than skipping it."""
    rev_id = f"tombrevoke_{uuid.uuid4()}"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at,
                received_from, origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rev_id,
                tombstone_id,
                "",
                _ORIGIN_ENTITY_URI,
                "key-1",
                "issuer-sig",
                created_at,
                "stigmem:node:rev-direct-peer",  # received_from -> relayed
                _ORIGIN_NODE_ID,
                _ORIGIN_TENANT,
                _ORIGIN_ENTITY_URI,
                json.dumps([]),
                json.dumps(sorted(origin_allowed_tenants)),
                f"STORED-ORIGIN-SIG-{rev_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return rev_id


def _issuer_signed_revocation(
    issuer_priv: Ed25519PrivateKey,
    *,
    tombstone_id: str,
    signed_by: str,
    key_id: str,
) -> TombstoneRevocationRecord:
    """Build a TombstoneRevocationRecord carrying a valid ISSUER-signer signature."""
    rec = TombstoneRevocationRecord(
        id=f"tombrevoke_{uuid.uuid4()}",
        tombstone_id=tombstone_id,
        reason="",
        signed_by=signed_by,
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
    )
    sig = base64.urlsafe_b64encode(issuer_priv.sign(_revocation_signing_body(rec))).decode().rstrip(
        "="
    )
    return rec.model_copy(update={"signature": sig})


# ---------------------------------------------------------------------------
# Shared fake client / page helpers (pull tests)
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
    allowed_tenants: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tenant": tenant,
        "node_id": node_id,
        "allowed_scopes": [],
        "allowed_tenants": allowed_tenants if allowed_tenants is not None else [tenant],
        "entity_uri": entity_uri,
    }


def _build_v2_revocation_entry(
    origin_priv: Ed25519PrivateKey,
    *,
    revocation: TombstoneRevocationRecord,
    origin: dict[str, Any],
    origin_sig: str | None = None,
) -> dict[str, Any]:
    if origin_sig is None:
        origin_sig = sign_revocation_origin(
            origin_priv,
            revocation_id=revocation.id,
            tombstone_id=revocation.tombstone_id,
            origin_node_id=origin["node_id"],
            origin_tenant=origin["tenant"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_entity_uri=origin["entity_uri"],
        )
    return {
        "revocation": revocation.model_dump(),
        "origin": origin,
        "origin_sig": origin_sig,
    }


def _v2_page(revocations: list[dict[str, Any]], cursor: str | None = None) -> dict[str, Any]:
    return {"v": 2, "tombstones": [], "revocations": revocations, "cursor": cursor}


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


def _revocation_in_db(rev_id: str) -> bool:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT 1 FROM tombstone_revocations WHERE id = ?", (rev_id,)
        ).fetchone()
    return row is not None


@pytest.fixture()
def bound_peer_node(fed_node: Any) -> tuple[Any, str, str, Ed25519PrivateKey, str]:
    """fed_node + an active, entity_uri-bound peer (the SENDER/ORIGIN) whose manifest is
    stored so resolve_origin_key(sender) and get_peer_manifest(signer) both resolve."""
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
# (a) GET emits enveloped revocations with a valid self-originated origin block
# ---------------------------------------------------------------------------


def test_get_returns_enveloped_self_originated_revocation(
    fed_node: Any, _trust_off: None
) -> None:
    """(a) GET returns enveloped revocations; a self-originated entry carries a fresh origin
    block (this node's node_id/entity_uri) and a valid origin_sig."""
    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:alice")
    rev_id = _insert_self_revocation(
        fed_node.db_path, tombstone_id=tomb_id, created_at="2026-06-10T00:00:01Z"
    )

    node_b_pub, node_b_priv = generate_ed25519_b64()
    node_b_id = f"stigmem://test-b-{uuid.uuid4()}"
    insert_active_peer(fed_node.db_path, node_b_id, "http://testnode-b", node_b_pub)
    token = make_peer_token(node_b_priv, node_b_id, fed_node.node_id, ["public"])

    resp = fed_node.client.get(
        "/v1/federation/tombstones",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["v"] == 2
    entry = next(e for e in body["revocations"] if e["revocation"]["id"] == rev_id)
    origin = entry["origin"]
    assert origin["node_id"] == fed_node.node_id
    assert origin["entity_uri"] == fed_node.node_url
    # The self-originated origin_sig verifies against THIS node's federation key.
    verify_revocation_origin_signature(
        entry["origin_sig"],
        revocation_id=rev_id,
        tombstone_id=tomb_id,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
        allowed_pubkeys={fed_node.pub_b64},
    )


# ---------------------------------------------------------------------------
# (b) pull applies a DIRECT revocation after verifying BOTH sigs
# ---------------------------------------------------------------------------


def test_pull_applies_direct_revocation_after_both_sigs(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(b) DIRECT revocation (origin == sender) with valid origin sig + valid issuer sig is
    applied; the referenced tombstone is reinstated (revocation row present)."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    tomb_id = f"tomb_{uuid.uuid4()}"
    # Same-issuer binding: the tombstone must be issued by the same authority that revokes it.
    _insert_tombstone(
        fed_node.db_path,
        tombstone_id=tomb_id,
        entity_uri="user:bob",
        signed_by=sender_entity_uri,
    )
    rec = _issuer_signed_revocation(
        sender_priv, tombstone_id=tomb_id, signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_revocation_entry(sender_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="c1")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert new_cursor == "c1"
    assert _revocation_in_db(rec.id) is True


# ---------------------------------------------------------------------------
# (c) invalid ORIGIN signature is REJECTED on pull
# ---------------------------------------------------------------------------


def test_pull_rejects_invalid_revocation_origin_signature(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(c) A revocation whose ORIGIN signature is invalid is REJECTED."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:carol")
    rec = _issuer_signed_revocation(
        sender_priv, tombstone_id=tomb_id, signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_revocation_entry(
        sender_priv, revocation=rec, origin=origin, origin_sig="not-a-valid-sig"
    )
    page = _v2_page([entry])

    asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert _revocation_in_db(rec.id) is False


# ---------------------------------------------------------------------------
# (d) invalid ISSUER-signer signature is REJECTED on pull
# ---------------------------------------------------------------------------


def test_pull_rejects_invalid_revocation_issuer_signature(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(d) A revocation whose ISSUER-signer signature is invalid is REJECTED."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:dave")
    rec = _issuer_signed_revocation(
        sender_priv, tombstone_id=tomb_id, signed_by=sender_entity_uri, key_id=key_id
    )
    # Corrupt the issuer signature (origin sig stays valid).
    rec = rec.model_copy(update={"signature": "AAAA" + rec.signature[4:]})
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_revocation_entry(sender_priv, revocation=rec, origin=origin)
    page = _v2_page([entry])

    asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert _revocation_in_db(rec.id) is False


# ---------------------------------------------------------------------------
# (e) relayed revocation (origin != sender) is SKIPPED on pull
# ---------------------------------------------------------------------------


def test_pull_skips_relayed_revocation(
    bound_peer_node: tuple[Any, str, str, Ed25519PrivateKey, str],
) -> None:
    """(e) A relayed revocation (origin.node_id != sender) is SKIPPED — Rev-3 enables it."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    fed_node, sender_node_id, sender_entity_uri, sender_priv, key_id = bound_peer_node
    other_node_id = f"stigmem://other-{uuid.uuid4()}"
    other_entity_uri = "https://other.example"
    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:frank")
    rec = _issuer_signed_revocation(
        sender_priv, tombstone_id=tomb_id, signed_by=sender_entity_uri, key_id=key_id
    )
    origin = _build_origin(node_id=other_node_id, entity_uri=other_entity_uri)
    entry = _build_v2_revocation_entry(sender_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="c2")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(_peer_dict(sender_node_id), _FakeClient(page), None)
    )
    assert new_cursor == "c2"
    assert _revocation_in_db(rec.id) is False


# ---------------------------------------------------------------------------
# (f) egress gate — tenant-only; relay OFF self-only, relay ON tenant-overlap; pagination
# ---------------------------------------------------------------------------


def _register_pull_peer(
    fed_node: FedNode, *, allowed_tenants: list[str]
) -> tuple[str, str]:
    pub_b64, priv_b64 = generate_ed25519_b64()
    node_id = f"stigmem://rev-pull-{uuid.uuid4()}"
    conn = sqlite3.connect(fed_node.db_path)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, declaration_sig, signed_at, pull_tenant, allowed_tenants)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                node_id,
                "http://rev-pull",
                pub_b64,
                json.dumps(["public"]),
                "active",
                "test_dummy_sig",
                "2026-05-02T00:00:00Z",
                _TENANT,
                json.dumps(allowed_tenants),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return node_id, priv_b64


def _poll_revocation_ids(fed_node: FedNode, node_id: str, priv: str, **q: Any) -> set[str]:
    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    url = "/v1/federation/tombstones" + (f"?{qs}" if qs else "")
    r = fed_node.client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return {e["revocation"]["id"] for e in r.json()["revocations"]}


def test_relay_off_withholds_relayed_revocation(fed_node: FedNode, _trust_off: None) -> None:
    """(f) relay OFF — only self-originated (received_from IS NULL) revocations egress."""
    _set_relay_enabled(False)
    self_rev = _insert_self_revocation(
        fed_node.db_path, tombstone_id="tomb-self-f1", created_at="2026-06-10T00:00:01Z"
    )
    relayed_rev = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id="tomb-relayed-f1",
        created_at="2026-06-10T00:00:02Z",
        origin_allowed_tenants=["default"],
    )
    node_id, priv = _register_pull_peer(fed_node, allowed_tenants=["default"])
    ids = _poll_revocation_ids(fed_node, node_id, priv)
    assert self_rev in ids
    assert relayed_rev not in ids


def test_relay_on_egresses_relayed_within_tenant_grant(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(f) relay ON — origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅ → returned."""
    _set_relay_enabled(True)
    relayed_rev = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id="tomb-relayed-f2",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_tenants=["acme", "default"],
    )
    node_id, priv = _register_pull_peer(fed_node, allowed_tenants=["default"])
    assert relayed_rev in _poll_revocation_ids(fed_node, node_id, priv)


def test_relay_on_withholds_tenant_outside_grant(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(f) relay ON — origin_allowed_tenants ∩ peer.allowed_tenants = ∅ → withheld."""
    _set_relay_enabled(True)
    relayed_rev = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id="tomb-relayed-f3",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_tenants=["acme"],  # peer is ["default"] → no overlap
    )
    node_id, priv = _register_pull_peer(fed_node, allowed_tenants=["default"])
    assert relayed_rev not in _poll_revocation_ids(fed_node, node_id, priv)


def test_relay_on_revocation_pagination_filters_in_sql(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(f) relay ON, a mix of pass/withheld relayed revocations spanning >1 page at a small
    limit: every non-final page is FULL (no short page from post-filtering) and exactly the
    eligible revocations come back. Proves the tenant gate is IN SQL (LIMIT post-filter)."""
    _set_relay_enabled(True)
    expected_pass: set[str] = set()
    for i in range(12):
        passes = i % 2 == 0
        rev_id = _insert_relayed_revocation(
            fed_node.db_path,
            tombstone_id=f"tomb-page-{i}",
            created_at=f"2026-06-10T00:00:{i:02d}Z",
            origin_allowed_tenants=(["default"] if passes else ["acme"]),
        )
        if passes:
            expected_pass.add(rev_id)

    node_id, priv = _register_pull_peer(fed_node, allowed_tenants=["default"])

    collected: set[str] = set()
    cursor: str | None = None
    limit = 3
    for _ in range(20):
        token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
        qs = f"limit={limit}" + (f"&since={cursor}" if cursor else "")
        r = fed_node.client.get(
            f"/v1/federation/tombstones?{qs}", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        page_ids = [e["revocation"]["id"] for e in body["revocations"]]
        collected.update(page_ids)
        # The response cursor/has_more are tombstone-driven; revocations paginate by their own
        # created_at via the `since` param. Drive pagination off the last revocation seen.
        if not page_ids:
            break
        cursor = max(
            e["revocation"]["created_at"] for e in body["revocations"]
        )

    assert collected == expected_pass
    assert len(collected) == 6
