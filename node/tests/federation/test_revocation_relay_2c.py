"""Phase 2c Rev-3 — secure RELAYED revocation ingest (origin.node_id != sender).

Rev-2 cut the revocation wire to v2 and handles DIRECT revocations (origin == sender),
SKIPPING relayed ones. This task enables relayed revocations through the secure trust
resolver, mirroring the tombstone relay ingest (W6.7 + W6.8) — closing the
stuck-suppression asymmetry so a relay mesh can propagate tombstone REVERSALS:

  relay OFF → relayed revocation SKIPPED (unchanged Rev-2)
  relay ON + sender NOT relay_trusted → SKIPPED (relay_sender_not_trusted), fail-closed
  relay ON + relay_trusted + origin != sender →
    resolve_origin_key_for_relay (pin/stored/fetch/fail-closed)
    → verify revocation ORIGIN signature (anti-relaunder: rid+tombstone_id bound)
    → verify ISSUER-signer signature (both required)
    → resolve_origin_tenant_for_peer (default-deny; no scope gate — revocations have no scope)
    → apply_inbound_revocation(... origin cols + received_from)

Tests (pull/push a–i, proof j–l):
  (a) relay ON + relay_trusted sender + origin resolvable → APPLIED; origin cols + received_from.
  (b) relay ON + sender NOT relay_trusted → SKIPPED.
  (c) relay OFF → relayed revocation SKIPPED.
  (d) relayed, origin UNREACHABLE + UNPINNED → fail-closed SKIP.
  (e) invalid revocation ORIGIN sig → SKIP.
  (f) invalid ISSUER sig → SKIP (both required).
  (g) anti-relaunder: relay mutated tombstone_id → origin sig fails → SKIP.
  (h) push route: v2 relayed from relay_trusted → applied; untrusted → 4xx; relay-off → 4xx;
      bare revocation → accepted as direct (back-compat).
  (i) direct revocation (origin == sender) still applied (Rev-2 unchanged).
  (j) A→B→C proof: A revokes, B relays, C verifies against A's key + A's issuer sig → applied,
      tombstone REINSTATED at C; origin_node_id == A, received_from == B.
  (k) relay-OFF containment: C drops B's relayed revocation; tombstone stays suppressed at C.
  (l) unanchored fail-closed: no pin + A unreachable → C does not apply.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.lifecycle.tombstones as tombstones_mod
import stigmem_node.routes.federation as fed_mod
import stigmem_node.routes.tombstones as tomb_routes_mod
import stigmem_node.settings as settings_module
from stigmem_node.federation.origin_pins import fingerprint_from_pubkey, put_origin_pin
from stigmem_node.federation.origin_signature import sign_revocation_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest
from stigmem_node.identity.trust_store import store_peer_manifest
from stigmem_node.lifecycle.tombstone_signing import _revocation_signing_body
from stigmem_node.main import _include_plugin_routers, create_app
from stigmem_node.models.tombstones import TombstoneRevocationRecord
from stigmem_node.plugins.discovery import DiscoveredPlugin
from stigmem_node.plugins.testing import stigmem_plugins

from .helpers import generate_ed25519_b64, make_bound_peer

# Single import style for stigmem_node.db: the module alias (db_mod) is required
# because tests monkeypatch db_mod.settings, so bind the db() context manager from it.
_db_ctx = db_mod.db

_TENANT = "default"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


# ---------------------------------------------------------------------------
# Crypto / record builders
# ---------------------------------------------------------------------------


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
    sig = (
        base64.urlsafe_b64encode(issuer_priv.sign(_revocation_signing_body(rec)))
        .decode()
        .rstrip("=")
    )
    return rec.model_copy(update={"signature": sig})


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
    sign_tombstone_id: str | None = None,
) -> dict[str, Any]:
    """Build a v2 revocation wire entry signed by the ORIGIN key.

    ``sign_tombstone_id`` lets a test sign over a DIFFERENT tombstone_id than the
    revocation carries (anti-relaunder: a relay that retargeted which tombstone the
    revocation reverses).
    """
    if origin_sig is None:
        origin_sig = sign_revocation_origin(
            origin_priv,
            revocation_id=revocation.id,
            tombstone_id=(
                sign_tombstone_id if sign_tombstone_id is not None else revocation.tombstone_id
            ),
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


# NB: keyword-only param named ``relay_ok`` (not ``relay_trusted``) on purpose — see the
# explanatory note on _peer_dict in test_ingest_scope_enum_2c.py. CodeQL's clear-text-logging
# sensitive-name heuristic flags a local named ``relay_trusted`` as a secret and taints the
# whole peer dict, yielding false-positive py/clear-text-logging alerts on federation_pull.py
# log lines that print the PUBLIC peer["node_id"]. The dict KEY "relay_trusted" is unchanged.
def _peer_dict(node_id: str, *, relay_ok: int = 0) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": node_id,
        "node_url": "http://peer",
        "allowed_scopes": json.dumps(["public", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": relay_ok,
    }


def _set_relay_enabled(value: bool) -> None:
    settings_module.settings.federation_relay_enabled = value


def _insert_tombstone(
    db_path: str,
    *,
    tombstone_id: str,
    entity_uri: str,
    signed_by: str = "stigmem://local/issuer",
) -> None:
    """Insert a suppressing tombstone. ``signed_by`` is the ISSUER; same-issuer binding
    (RTBF integrity) requires a revocation's ``signed_by`` to match it to apply."""
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


def _revocation_row(rev_id: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstone_revocations WHERE id = ?", (rev_id,)
        ).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------
# Fake pull client
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


@pytest.fixture()
def relay_nodes(
    fed_node: Any,
) -> tuple[Any, str, str, Ed25519PrivateKey, str, str, str, Ed25519PrivateKey, str]:
    """fed_node + a relay SENDER peer + a separate ORIGIN bound-peer (origin != sender).

    Mirrors the W6.7 ``relay_nodes`` fixture for the revocation path. Both are entity_uri-bound
    peers with stored self-verifying manifests so the SENDER's key resolves (it relays) and the
    ORIGIN resolves via the relay resolver's peer path + its issuer-signer manifest is stored.

    Returns:
        (fed_node, sender_node_id, sender_entity_uri, sender_priv, sender_key_id,
         origin_node_id, origin_entity_uri, origin_priv, origin_key_id)
    """
    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"
    sender_key_id = generate_key_id(sender_priv.public_key())

    origin_pub, origin_priv_b64 = generate_ed25519_b64()
    origin_priv = _priv_from_b64(origin_priv_b64)
    origin_node_id = f"stigmem://origin-{uuid.uuid4()}"
    origin_entity_uri = f"https://origin-{uuid.uuid4()}.example"
    origin_key_id = generate_key_id(origin_priv.public_key())

    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        conn.commit()
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=origin_node_id,
            entity_uri=origin_entity_uri,
            pub_b64=origin_pub,
            priv=origin_priv,
        )
        conn.commit()
    return (
        fed_node,
        sender_node_id,
        sender_entity_uri,
        sender_priv,
        sender_key_id,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    )


# ---------------------------------------------------------------------------
# (a) relay ON + relay_trusted + resolvable origin → APPLIED + columns persisted
# ---------------------------------------------------------------------------


def test_relay_on_trusted_resolvable_origin_applies_with_columns(relay_nodes: Any) -> None:
    """(a) A relayed revocation from a relay_trusted sender whose ORIGIN resolves (bound peer)
    with valid origin + issuer sigs is APPLIED; origin columns + received_from persist."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    # Same-issuer binding: the tombstone is issued by the same authority (origin) that revokes it.
    _insert_tombstone(
        fed_node.db_path,
        tombstone_id=tomb_id,
        entity_uri="user:relay-rev",
        signed_by=origin_entity_uri,
    )
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_tenants=["default", "acme"]
    )
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="ra")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "ra"
    row = _revocation_row(rec.id)
    assert row is not None
    assert row["received_from"] == sender_node_id
    assert row["origin_node_id"] == origin_node_id
    assert row["origin_entity_uri"] == origin_entity_uri
    assert row["origin_tenant"] == _TENANT
    assert json.loads(row["origin_allowed_tenants"]) == ["acme", "default"]
    assert row["origin_sig"] == entry["origin_sig"]


# ---------------------------------------------------------------------------
# (b) relay ON + sender NOT relay_trusted → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_on_untrusted_sender_skips(relay_nodes: Any) -> None:
    """(b) A relayed revocation from a sender that is NOT relay_trusted is SKIPPED, fail-closed."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-untrust")
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="rb")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=0), _FakeClient(page), None
        )
    )
    assert new_cursor == "rb"
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (c) relay OFF → relayed revocation SKIPPED
# ---------------------------------------------------------------------------


def test_relay_off_relayed_revocation_skipped(relay_nodes: Any) -> None:
    """(c) With relay OFF, a relayed revocation is SKIPPED (unchanged Rev-2)."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(False)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-off")
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="rc")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "rc"
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (d) origin UNREACHABLE + UNPINNED → resolve fails → SKIPPED (fail-closed)
# ---------------------------------------------------------------------------


def test_relay_unreachable_unpinned_origin_skips(relay_nodes: Any, monkeypatch: Any) -> None:
    """(d) A relayed revocation whose ORIGIN is unreachable, not a bound peer, and unpinned
    cannot be resolved → SKIPPED fail-closed (origin_unresolvable)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        _origin_node_id,
        _origin_entity_uri,
        _origin_priv,
        _origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    unknown_priv = Ed25519PrivateKey.generate()
    unknown_node = f"stigmem://unknown-{uuid.uuid4()}"
    unknown_uri = "https://unknown-origin.example"
    unknown_key_id = generate_key_id(unknown_priv.public_key())

    def _get(*_a: Any, **_k: Any) -> Any:
        import httpx as _httpx  # noqa: PLC0415

        return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _get)
    monkeypatch.setattr(oi, "assert_safe_url", lambda *a, **k: None)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-unreach")
    rec = _issuer_signed_revocation(
        unknown_priv, tombstone_id=tomb_id, signed_by=unknown_uri, key_id=unknown_key_id
    )
    origin = _build_origin(node_id=unknown_node, entity_uri=unknown_uri)
    entry = _build_v2_revocation_entry(unknown_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="rd")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "rd"
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (e) invalid ORIGIN sig → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_invalid_origin_sig_skips(relay_nodes: Any) -> None:
    """(e) A relayed revocation whose ORIGIN signature does not verify is SKIPPED."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-badorig")
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(
        origin_priv, revocation=rec, origin=origin, origin_sig="not-a-valid-sig"
    )
    page = _v2_page([entry], cursor="re")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (f) invalid ISSUER-signer sig → SKIPPED (both sigs required)
# ---------------------------------------------------------------------------


def test_relay_invalid_issuer_sig_skips(relay_nodes: Any) -> None:
    """(f) A relayed revocation with a valid ORIGIN sig but INVALID issuer-signer sig is
    SKIPPED — a relayed revocation must ALSO be a real tombstone reversal."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-badiss")
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    # Corrupt the issuer signature; the ORIGIN sig binds id/tombstone_id (unchanged) so it
    # stays valid.
    rec = rec.model_copy(update={"signature": "AAAA" + rec.signature[4:]})
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="rf")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (g) anti-relaunder: relay MUTATED tombstone_id → origin-sig check fails → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_mutated_tombstone_id_fails_origin_sig_skips(relay_nodes: Any) -> None:
    """(g) ANTI-RELAUNDER: a relay that RETARGETED the wire ``tombstone_id`` past the one the
    origin signed invalidates the origin signature (tombstone_id is bound in the tuple) →
    SKIPPED. The origin only ever signed for the ORIGINAL tombstone; the wire carries another."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    wire_tomb_id = f"tomb_{uuid.uuid4()}"  # the tombstone the wire row claims to reverse
    signed_tomb_id = f"tomb_{uuid.uuid4()}"  # the tombstone the origin actually signed for
    _insert_tombstone(
        fed_node.db_path, tombstone_id=wire_tomb_id, entity_uri="user:relay-rev-launder"
    )
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=wire_tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    # Sign the origin attestation over a DIFFERENT tombstone_id than the wire carries.
    entry = _build_v2_revocation_entry(
        origin_priv, revocation=rec, origin=origin, sign_tombstone_id=signed_tomb_id
    )
    page = _v2_page([entry], cursor="rg")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (i) direct revocation (origin == sender) still applied (Rev-2 unchanged)
# ---------------------------------------------------------------------------


def test_direct_revocation_still_applied_unchanged(relay_nodes: Any) -> None:
    """(i) A DIRECT revocation (origin.node_id == sender) is still applied via the unchanged
    Rev-2 path; origin columns + received_from stay NULL (self/direct)."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        sender_entity_uri,
        sender_priv,
        sender_key_id,
        _origin_node_id,
        _origin_entity_uri,
        _origin_priv,
        _origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)  # relay ON must not change the direct path

    tomb_id = f"tomb_{uuid.uuid4()}"
    # Same-issuer binding: tombstone issued by the same authority (sender) that revokes it.
    _insert_tombstone(
        fed_node.db_path,
        tombstone_id=tomb_id,
        entity_uri="user:relay-rev-direct",
        signed_by=sender_entity_uri,
    )
    rec = _issuer_signed_revocation(
        sender_priv, tombstone_id=tomb_id, signed_by=sender_entity_uri, key_id=sender_key_id
    )
    origin = _build_origin(node_id=sender_node_id, entity_uri=sender_entity_uri)
    entry = _build_v2_revocation_entry(sender_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="ri")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=0), _FakeClient(page), None
        )
    )
    assert new_cursor == "ri"
    row = _revocation_row(rec.id)
    assert row is not None
    assert row["received_from"] is None
    assert row["origin_node_id"] is None
    assert row["origin_sig"] is None


# ---------------------------------------------------------------------------
# (i-bonus) relayed revocation whose origin tenant fails the default-deny gate → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_tenant_policy_default_deny_skips(relay_nodes: Any) -> None:
    """A relayed revocation whose wire ``origin.tenant`` has no peer_tenant_map entry (and is
    not the single-tenant 'default' fallback) is DENIED by ``resolve_origin_tenant_for_peer``
    (default-deny) → SKIPPED, even with both signatures valid + origin resolvable."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        _sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    tomb_id = f"tomb_{uuid.uuid4()}"
    _insert_tombstone(fed_node.db_path, tombstone_id=tomb_id, entity_uri="user:relay-rev-tenant")
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    # origin.tenant = 'acme' — no peer_tenant_map entry → default-deny.
    origin = _build_origin(
        node_id=origin_node_id,
        entity_uri=origin_entity_uri,
        tenant="acme",
        allowed_tenants=["acme"],
    )
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="rm")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _revocation_row(rec.id) is None


# ===========================================================================
# (h) PUSH route parity — v2 relayed revocation through the shared chain
# ===========================================================================

_TOMBSTONE_PLUGIN_SRC = Path(__file__).resolve().parents[3] / "experimental" / "tombstones" / "src"
_TOMBSTONE_ENV = {
    "STIGMEM_TOMBSTONES_ENABLED": "true",
    "STIGMEM_TOMBSTONES_ALLOW_ADMIN_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_FEDERATION_ROUTES": "true",
    "STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER": "true",
}


def _tombstone_plugin_manifest() -> Any:
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    plugin = __import__("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


@contextmanager
def _tombstone_plugin_app(app: Any) -> Generator[None, None, None]:
    original_env = {name: os.environ.get(name) for name in _TOMBSTONE_ENV}
    try:
        for name, value in _TOMBSTONE_ENV.items():
            os.environ[name] = value
        manifest = _tombstone_plugin_manifest()
        discovered = DiscoveredPlugin(
            manifest=manifest,
            entry_point_name="tombstones",
            entry_point_value="stigmem_plugin_tombstones:plugin_manifest",
            distribution=manifest.name,
        )
        _include_plugin_routers(app, (discovered,))
        with stigmem_plugins([manifest]):
            yield
    finally:
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _make_peer_token(priv_b64: str, iss: str, sub: str) -> str:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    now_ms = int(time.time() * 1000)
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now_ms,
        "exp": now_ms + 3_600_000,
        "nonce": str(uuid.uuid4()),
        "scopes": ["public", "*"],
    }
    return pyjwt.encode(payload, privkey, algorithm="EdDSA")


class _PushNode:
    def __init__(
        self,
        client: TestClient,
        *,
        our_node_id: str,
        sender_node_id: str,
        sender_entity_uri: str,
        sender_priv: Ed25519PrivateKey,
        sender_priv_b64: str,
        sender_key_id: str,
        origin_node_id: str,
        origin_entity_uri: str,
        origin_priv: Ed25519PrivateKey,
        origin_key_id: str,
    ) -> None:
        self.client = client
        self.our_node_id = our_node_id
        self.sender_node_id = sender_node_id
        self.sender_entity_uri = sender_entity_uri
        self.sender_priv = sender_priv
        self.sender_priv_b64 = sender_priv_b64
        self.sender_key_id = sender_key_id
        self.origin_node_id = origin_node_id
        self.origin_entity_uri = origin_entity_uri
        self.origin_priv = origin_priv
        self.origin_key_id = origin_key_id

    def sender_token(self) -> str:
        return _make_peer_token(self.sender_priv_b64, self.sender_node_id, sub=self.our_node_id)

    def post(self, payload: dict[str, Any]) -> Any:
        return self.client.post(
            "/v1/federation/tombstones/ingest",
            json=payload,
            headers={"Authorization": f"Bearer {self.sender_token()}"},
        )


def _set_relay_trusted(db_file: str, node_id: str, value: int) -> None:
    conn = sqlite3.connect(db_file)
    try:
        conn.execute("UPDATE peers SET relay_trusted = ? WHERE node_id = ?", (value, node_id))
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def push_node(tmp_path: Any) -> Generator[_PushNode, None, None]:
    """Tombstone-plugin app with a relay_trusted SENDER peer + separate ORIGIN bound-peer.

    Mirrors the W6.8 ``push_node`` fixture for the revocation push surface.
    """
    db_file = str(tmp_path) + "/push_rev_test.db"
    db_mod.apply_migrations(db_path=db_file)

    node_pub, node_priv_b64 = generate_ed25519_b64()

    sender_pub, sender_priv_b64 = generate_ed25519_b64()
    sender_priv = _priv_from_b64(sender_priv_b64)
    sender_node_id = f"stigmem://sender-{uuid.uuid4()}"
    sender_entity_uri = f"https://sender-{uuid.uuid4()}.example"
    sender_key_id = generate_key_id(sender_priv.public_key())

    origin_pub, origin_priv_b64 = generate_ed25519_b64()
    origin_priv = _priv_from_b64(origin_priv_b64)
    origin_node_id = f"stigmem://origin-{uuid.uuid4()}"
    origin_entity_uri = f"https://origin-{uuid.uuid4()}.example"
    origin_key_id = generate_key_id(origin_priv.public_key())

    original = settings_module.settings
    ts = settings_module.Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://pushnode",
        trust_mode="relaxed",
        node_private_key=node_priv_b64,
    )
    settings_module.settings = ts
    auth_mod.settings = ts
    db_mod.settings = ts
    fed_mod.settings = ts
    tomb_routes_mod.settings = ts
    tombstones_mod.invalidate_tombstone_cache()

    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=sender_node_id,
            entity_uri=sender_entity_uri,
            pub_b64=sender_pub,
            priv=sender_priv,
        )
        conn.commit()
    with _db_ctx() as conn:
        make_bound_peer(
            conn,
            node_id=origin_node_id,
            entity_uri=origin_entity_uri,
            pub_b64=origin_pub,
            priv=origin_priv,
        )
        conn.commit()

    our_node_id = db_mod.get_or_create_node_id(db_path=db_file)

    app = create_app()
    with _tombstone_plugin_app(app):
        client = TestClient(app, raise_server_exceptions=True)
        client.__enter__()
        yield _PushNode(
            client,
            our_node_id=our_node_id,
            sender_node_id=sender_node_id,
            sender_entity_uri=sender_entity_uri,
            sender_priv=sender_priv,
            sender_priv_b64=sender_priv_b64,
            sender_key_id=sender_key_id,
            origin_node_id=origin_node_id,
            origin_entity_uri=origin_entity_uri,
            origin_priv=origin_priv,
            origin_key_id=origin_key_id,
        )
        client.__exit__(None, None, None)

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original
    fed_mod.settings = original
    tomb_routes_mod.settings = original
    tombstones_mod.invalidate_tombstone_cache()


def _push_insert_tombstone(entity_uri: str, signed_by: str = "stigmem://local/issuer") -> str:
    tomb_id = f"tomb_{uuid.uuid4()}"
    with _db_ctx() as conn:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tomb_id,
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
    return tomb_id


def test_push_v2_relayed_revocation_trusted_applied(push_node: _PushNode) -> None:
    """(h) PUSH: a v2 relayed revocation from a relay_trusted sender + resolvable origin is
    applied; origin columns + received_from persisted."""
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    # Same-issuer binding: tombstone issued by the same authority (origin) that revokes it.
    tomb_id = _push_insert_tombstone("user:push-rev-relay", push_node.origin_entity_uri)
    rec = _issuer_signed_revocation(
        push_node.origin_priv,
        tombstone_id=tomb_id,
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _build_origin(
        node_id=push_node.origin_node_id, entity_uri=push_node.origin_entity_uri
    )
    entry = _build_v2_revocation_entry(push_node.origin_priv, revocation=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 200, resp.text
    row = _revocation_row(rec.id)
    assert row is not None
    assert row["received_from"] == push_node.sender_node_id
    assert row["origin_node_id"] == push_node.origin_node_id
    assert row["origin_sig"] == entry["origin_sig"]


def test_push_v2_relayed_revocation_untrusted_rejected(push_node: _PushNode) -> None:
    """(h) PUSH: a v2 relayed revocation from a NOT-relay_trusted sender → 403, not applied."""
    _set_relay_enabled(True)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 0)

    tomb_id = _push_insert_tombstone("user:push-rev-untrust")
    rec = _issuer_signed_revocation(
        push_node.origin_priv,
        tombstone_id=tomb_id,
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _build_origin(
        node_id=push_node.origin_node_id, entity_uri=push_node.origin_entity_uri
    )
    entry = _build_v2_revocation_entry(push_node.origin_priv, revocation=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 403, resp.text
    assert "relay_sender_not_trusted" in resp.json()["detail"]
    assert _revocation_row(rec.id) is None


def test_push_v2_relayed_revocation_relay_off_rejected(push_node: _PushNode) -> None:
    """(h) PUSH: a v2 relayed revocation with relay OFF → 403 (origin_not_sender), not applied."""
    _set_relay_enabled(False)
    _set_relay_trusted(settings_module.settings.db_path, push_node.sender_node_id, 1)

    tomb_id = _push_insert_tombstone("user:push-rev-off")
    rec = _issuer_signed_revocation(
        push_node.origin_priv,
        tombstone_id=tomb_id,
        signed_by=push_node.origin_entity_uri,
        key_id=push_node.origin_key_id,
    )
    origin = _build_origin(
        node_id=push_node.origin_node_id, entity_uri=push_node.origin_entity_uri
    )
    entry = _build_v2_revocation_entry(push_node.origin_priv, revocation=rec, origin=origin)

    resp = push_node.post(entry)
    assert resp.status_code == 403, resp.text
    assert "origin_not_sender" in resp.json()["detail"]
    assert _revocation_row(rec.id) is None


def test_push_bare_revocation_accepted_as_direct(push_node: _PushNode) -> None:
    """(h) PUSH back-compat: a bare (pre-v2) revocation POST is accepted as a DIRECT,
    issuer-verified revocation (received_from NULL)."""
    _set_relay_enabled(True)

    # Same-issuer binding: tombstone issued by the same authority (sender) that revokes it.
    tomb_id = _push_insert_tombstone("user:push-rev-bare", push_node.sender_entity_uri)
    rec = _issuer_signed_revocation(
        push_node.sender_priv,
        tombstone_id=tomb_id,
        signed_by=push_node.sender_entity_uri,
        key_id=push_node.sender_key_id,
    )

    resp = push_node.post(rec.model_dump())
    assert resp.status_code == 200, resp.text
    row = _revocation_row(rec.id)
    assert row is not None
    assert row["received_from"] is None
    assert row["origin_node_id"] is None


# ===========================================================================
# PROOF (j–l): A→B→C multi-node revocation relay
# ===========================================================================


class _Node:
    """A federation identity used as origin A or relay-sender B / downstream C in the proof."""

    def __init__(self, label: str) -> None:
        self.pub_b64, self.priv_b64 = generate_ed25519_b64()
        self.priv = _priv_from_b64(self.priv_b64)
        self.node_id = f"stigmem://{label}-{uuid.uuid4()}"
        self.entity_uri = f"https://{label}-{uuid.uuid4()}.example"
        self.key_id = generate_key_id(self.priv.public_key())

    def manifest(self) -> OrgManifest:
        m = OrgManifest(
            entity_uri=self.entity_uri,
            key_id=self.key_id,
            public_key=self.pub_b64,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-12-01T00:00:00Z",
            entities=[self.entity_uri, self.node_id],
        )
        sign_manifest(m, self.priv)
        return m


def _origin_block(node: _Node) -> dict[str, Any]:
    return {
        "tenant": _TENANT,
        "node_id": node.node_id,
        "allowed_scopes": [],
        "allowed_tenants": [_TENANT],
        "entity_uri": node.entity_uri,
    }


def _proof_origin_sig(
    origin_node: _Node, rec: TombstoneRevocationRecord, origin: dict[str, Any], *,
    sign_tombstone_id: str | None = None
) -> str:
    return sign_revocation_origin(
        origin_node.priv,
        revocation_id=rec.id,
        tombstone_id=sign_tombstone_id if sign_tombstone_id is not None else rec.tombstone_id,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
    )


def _seed_suppressed_tombstone_on_b(
    db_path: str,
    *,
    tombstone_id: str,
    entity_uri: str,
    signed_by: str = "stigmem://a/issuer",
) -> None:
    """Insert the SUPPRESSING tombstone (the one C also holds and will reinstate).

    ``signed_by`` is A's issuer authority — same-issuer binding requires A's revocation to be
    signed by this for the reinstatement to apply at C."""
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
    tombstones_mod.invalidate_tombstone_cache()


def _seed_relayed_revocation_on_b(
    db_path: str,
    *,
    rec: TombstoneRevocationRecord,
    origin: dict[str, Any],
    origin_sig: str,
    received_from: str,
) -> None:
    """Insert A's revocation into B's DB with A's verbatim origin block + received_from=A,
    exactly as B would have stored it after a direct pull from A (Rev-2/Rev-3 direct path)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at,
                received_from, origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec.id,
                rec.tombstone_id,
                rec.reason,
                rec.signed_by,
                rec.key_id,
                rec.signature,
                rec.created_at,
                received_from,
                origin["node_id"],
                origin["tenant"],
                origin["entity_uri"],
                json.dumps(sorted(origin["allowed_scopes"])),
                json.dumps(sorted(origin["allowed_tenants"])),
                origin_sig,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _register_relay_peer_on_b(db_path: str, peer_node_id: str, peer_pub_b64: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, declaration_sig, signed_at, pull_tenant, allowed_tenants)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                peer_node_id,
                "http://node-c",
                peer_pub_b64,
                json.dumps(["public", "*"]),
                "active",
                "test_dummy_sig",
                "2026-05-02T00:00:00Z",
                _TENANT,
                json.dumps([_TENANT]),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _delete_revocation(db_path: str, rev_id: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM tombstone_revocations WHERE id = ?", (rev_id,))
        conn.commit()
    finally:
        conn.close()
    tombstones_mod.invalidate_tombstone_cache()


class _CapturedResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _BGetClient:
    """Replays B's REAL GET wire body to C's pull client (mirrors W6.9)."""

    def __init__(self, captured_body: dict[str, Any]) -> None:
        self._body = captured_body

    async def get(self, url: str, *, params: dict[str, Any] | None = None,
                  headers: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        return _CapturedResponse(self._body)


def _c_relay_peer_dict(b_node_id: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": b_node_id,
        "node_url": "http://relay-b",
        "allowed_scopes": json.dumps(["public", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": 1,
    }


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    """trust_mode=off so a peer-JWT Bearer token passes B's poll auth."""
    fed_module = sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_module.settings, "trust_mode", "off", raising=False)


def _no_fetch(monkeypatch: Any) -> None:
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    def _get(*_a: Any, **_k: Any) -> Any:
        import httpx as _httpx  # noqa: PLC0415

        return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _get)
    monkeypatch.setattr(oi, "assert_safe_url", lambda *a, **k: None)


def _fetch_serves_a(monkeypatch: Any, a: _Node) -> None:
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    a_manifest = manifest_to_dict(a.manifest())

    def _get(url: Any, *_a: Any, **_k: Any) -> Any:
        import httpx as _httpx  # noqa: PLC0415

        if str(url).endswith("/.well-known/stigmem-manifest.json"):
            return _httpx.Response(200, json=a_manifest)
        return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _get)
    monkeypatch.setattr(oi, "assert_safe_url", lambda *a, **k: None)


def _bearer(fed_node: Any, c: _Node) -> str:
    from conftest import make_peer_token  # noqa: PLC0415

    return "Bearer " + make_peer_token(
        c.priv_b64, c.node_id, fed_node.node_id, ["public", "*"]
    )


def _run_bc_relay(
    fed_node: Any, a: _Node, c: _Node, rec: TombstoneRevocationRecord,
    origin: dict[str, Any], origin_sig: str, *, entity_x: str
) -> str | None:
    """Drive the B→C revocation relay hop. ``fed_node`` is the RELAY B; ``c`` the downstream.

    Seeds the suppressing tombstone + A's relayed revocation on B, registers C as a relay peer,
    captures B's REAL GET wire body (W6.6 egress gate runs), clears B's seed revocation, then
    drives C's REAL ``pull_tombstones_from_peer_once``. The surviving revocation row (if any) is
    the one C's OWN secure relay-ingest chain wrote (origin A, received_from B)."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    # Same-issuer binding: A's suppressing tombstone is issued by A (a.entity_uri), the same
    # authority that signs the relayed revocation — so the reinstatement applies at C.
    _seed_suppressed_tombstone_on_b(
        fed_node.db_path,
        tombstone_id=rec.tombstone_id,
        entity_uri=entity_x,
        signed_by=a.entity_uri,
    )
    _seed_relayed_revocation_on_b(
        fed_node.db_path, rec=rec, origin=origin, origin_sig=origin_sig, received_from=a.node_id
    )
    _register_relay_peer_on_b(fed_node.db_path, c.node_id, c.pub_b64)
    c_auth = _bearer(fed_node, c)
    b_resp = fed_node.client.get(
        "/v1/federation/tombstones",
        params={"limit": 200},
        headers={"Authorization": c_auth},
    )
    assert b_resp.status_code == 200, b_resp.text
    b_body = b_resp.json()
    _delete_revocation(fed_node.db_path, rec.id)
    return asyncio.run(
        pull_tombstones_from_peer_once(
            _c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None
        )
    )


def _is_suppressed(entity_uri: str) -> bool:
    """True iff an active, un-revoked tombstone for *entity_uri* exists (the suppression signal)."""
    with _db_ctx() as conn:
        rows = conn.execute(
            """SELECT 1 FROM tombstones t
               WHERE t.entity_uri = ? AND NOT EXISTS (
                   SELECT 1 FROM tombstone_revocations r WHERE r.tombstone_id = t.id
               )""",
            (entity_uri,),
        ).fetchall()
    return len(rows) > 0


@pytest.fixture()
def relay_topology(fed_node: Any, _trust_off: None) -> tuple[Any, _Node, _Node]:
    """origin A + downstream C identities; store A's issuer manifest at C (B = fed_node)."""
    a = _Node("origin-a")
    c = _Node("downstream-c")
    store_peer_manifest(a.entity_uri, a.manifest(), None, trust_mode="relaxed")
    return fed_node, a, c


# ---------------------------------------------------------------------------
# (j) HAPPY PATH — A→B→C: A reachable, C verifies A's key + issuer sig → REINSTATED.
# ---------------------------------------------------------------------------


def test_j_proof_relayed_revocation_reinstates_at_c(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(j) A revokes a tombstone (issuer-signs + origin-signs); B relays; C verifies against
    A's FETCHED key + A's issuer sig → applies; the tombstone is REINSTATED at C. The capstone:
    origin_node_id == A, received_from == B (A's attestation survived the relay; B did not
    re-sign)."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:rev4-alice"
    tomb_id = f"tomb_{uuid.uuid4()}"
    rec = _issuer_signed_revocation(
        a.priv, tombstone_id=tomb_id, signed_by=a.entity_uri, key_id=a.key_id
    )
    origin = _origin_block(a)
    osig = _proof_origin_sig(a, rec, origin)

    # Before relay: the tombstone suppresses entity_x at C (seeded by _run_bc_relay).
    new_cursor = _run_bc_relay(fed_node, a, c, rec, origin, osig, entity_x=entity_x)
    assert new_cursor is not None

    row = _revocation_row(rec.id)
    assert row is not None, "C did not apply the relayed revocation"
    assert row["origin_node_id"] == a.node_id
    assert row["origin_entity_uri"] == a.entity_uri
    assert row["received_from"] == fed_node.node_id
    assert row["origin_sig"] == osig
    # REINSTATED: the suppressing tombstone is now revoked at C → no longer suppressed.
    assert _is_suppressed(entity_x) is False


# ---------------------------------------------------------------------------
# (k) RELAY-OFF CONTAINMENT — C drops B's relayed revocation; suppression persists.
# ---------------------------------------------------------------------------


def test_k_relay_off_containment_revocation_dropped(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(k) Same topology, ``federation_relay_enabled=False`` at C → C DROPS B's relayed
    revocation (origin_not_sender) even though A is reachable + B is relay_trusted. The
    tombstone STAYS suppressed at C."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(False)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:rev4-carol"
    tomb_id = f"tomb_{uuid.uuid4()}"
    rec = _issuer_signed_revocation(
        a.priv, tombstone_id=tomb_id, signed_by=a.entity_uri, key_id=a.key_id
    )
    origin = _origin_block(a)
    osig = _proof_origin_sig(a, rec, origin)

    _run_bc_relay(fed_node, a, c, rec, origin, osig, entity_x=entity_x)
    assert _revocation_row(rec.id) is None, "relay OFF must not apply a relayed revocation at C"
    # Containment: the suppression survives — the tombstone is still active at C.
    assert _is_suppressed(entity_x) is True


# ---------------------------------------------------------------------------
# (l) UNANCHORED FAIL-CLOSED — no pin + A unreachable → C does not apply.
# ---------------------------------------------------------------------------


def test_l_unanchored_unreachable_origin_fails_closed(
    fed_node: Any, _trust_off: None, monkeypatch: Any
) -> None:
    """(l) C has NO pin for A, A is UNREACHABLE, B is relay_trusted → C's relay key resolver
    raises → C does NOT apply the revocation. Proves a relay cannot REINSTATE an entity at C by
    inventing an unknown, unreachable origin (no reinstatement-by-unknown-origin)."""
    a = _Node("origin-a")
    c = _Node("downstream-c")
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)  # A unreachable, NO pin, NO stored binding for A.

    entity_x = "user:rev4-dave"
    tomb_id = f"tomb_{uuid.uuid4()}"
    rec = _issuer_signed_revocation(
        a.priv, tombstone_id=tomb_id, signed_by=a.entity_uri, key_id=a.key_id
    )
    origin = _origin_block(a)
    osig = _proof_origin_sig(a, rec, origin)

    _run_bc_relay(fed_node, a, c, rec, origin, osig, entity_x=entity_x)
    assert _revocation_row(rec.id) is None, (
        "unanchored + unreachable origin must fail closed — no reinstatement at C"
    )
    assert _is_suppressed(entity_x) is True


def test_l_pin_path_unreachable_origin_applies(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(l-bonus) A UNREACHABLE but C holds an OPERATOR PIN for A's (entity_uri, node_id,
    key_fingerprint) → C accepts A's key via the pin and applies. Proves offline relay trust
    through the human anchor (mirrors W6.9 (b))."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)
    with _db_ctx() as conn:
        put_origin_pin(
            conn,
            entity_uri=a.entity_uri,
            node_id=a.node_id,
            key_fingerprint=fingerprint_from_pubkey(a.pub_b64),
            pinned_by="operator:test",
        )
        conn.commit()

    entity_x = "user:rev4-bob"
    tomb_id = f"tomb_{uuid.uuid4()}"
    rec = _issuer_signed_revocation(
        a.priv, tombstone_id=tomb_id, signed_by=a.entity_uri, key_id=a.key_id
    )
    origin = _origin_block(a)
    osig = _proof_origin_sig(a, rec, origin)

    _run_bc_relay(fed_node, a, c, rec, origin, osig, entity_x=entity_x)
    row = _revocation_row(rec.id)
    assert row is not None, "C did not apply the pinned-unreachable relayed revocation"
    assert row["origin_node_id"] == a.node_id
    assert row["received_from"] == fed_node.node_id
    assert _is_suppressed(entity_x) is False
