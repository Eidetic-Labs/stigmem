"""Phase 2c W6.7 — secure RELAYED tombstone ingest (origin.node_id != sender).

W6.5 cut the tombstone wire to v2 and handles DIRECT tombstones (origin == sender),
SKIPPING relayed ones. This task enables relayed tombstones through the secure trust
resolver, mirroring the FACT relay ingest (W3.2 + W4.2):

  relay OFF → relayed tombstone SKIPPED (unchanged W6.5)
  relay ON + sender NOT relay_trusted → SKIPPED (relay_sender_not_trusted), fail-closed
  relay ON + relay_trusted + origin != sender →
    resolve_origin_key_for_relay (pin/stored/fetch/fail-closed)
    → verify tombstone ORIGIN signature
    → verify ISSUER-signer signature (both required)
    → scope ∈ origin.allowed_scopes (ingest scope gate)
    → resolve_origin_tenant_for_peer (default-deny)
    → apply_inbound_tombstone(... origin cols + received_from)

Tests:
  (a) relay ON + relay_trusted sender + origin resolvable (bound peer) → APPLIED;
      origin columns + received_from persisted (row asserted).
  (b) relay ON + sender NOT relay_trusted → SKIPPED (relay_sender_not_trusted).
  (c) relay OFF → relayed tombstone SKIPPED (unchanged).
  (d) relayed tombstone, origin UNREACHABLE + UNPINNED → resolve fails → SKIPPED.
  (e) relayed tombstone whose ORIGIN sig is invalid → SKIPPED.
  (f) relayed tombstone whose ISSUER-signer sig is invalid → SKIPPED (both required).
  (g) relayed tombstone whose scope ∉ origin_allowed_scopes → SKIPPED.
  (h) anti-relaunder: a relay that MUTATED scope (widened) → origin-sig check fails → SKIPPED.
  (i) direct tombstone (origin == sender) still applied (W6.5 path unchanged).
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
from stigmem_node.federation.origin_signature import sign_tombstone_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.lifecycle.tombstone_signing import _signing_body
from stigmem_node.models.tombstones import TombstoneRecord

from .helpers import generate_ed25519_b64, make_bound_peer

_TENANT = "default"


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


def _tombstone_row(entity_uri: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstones WHERE entity_uri = ?", (entity_uri,)
        ).fetchone()
    return dict(row) if row is not None else None


def _issuer_signed_tombstone(
    issuer_priv: Ed25519PrivateKey,
    *,
    entity_uri: str,
    scope: str = "*",
    signed_by: str,
    key_id: str,
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
    sign_scope: str | None = None,
    origin_manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a v2 tombstone wire entry signed by the ORIGIN key.

    ``sign_scope`` lets a test sign over a DIFFERENT scope than the tombstone carries
    (anti-relaunder: a relay that widened the on-wire scope past the signed one).
    """
    if origin_sig is None:
        origin_sig = sign_tombstone_origin(
            origin_priv,
            tombstone_id=tombstone.id,
            entity_uri=tombstone.entity_uri,
            scope=sign_scope if sign_scope is not None else tombstone.scope,
            origin_node_id=origin["node_id"],
            origin_tenant=origin["tenant"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_entity_uri=origin["entity_uri"],
        )
    entry: dict[str, Any] = {
        "tombstone": tombstone.model_dump(),
        "origin": origin,
        "origin_sig": origin_sig,
    }
    if origin_manifest is not None:
        entry["origin_manifest"] = origin_manifest
    return entry


def _v2_page(entries: list[dict[str, Any]], cursor: str | None = None) -> dict[str, Any]:
    return {"v": 2, "tombstones": entries, "revocations": [], "cursor": cursor}


# param named relay_ok (not relay_trusted) to avoid a CodeQL clear-text-logging
# name-heuristic FP; dict key stays "relay_trusted" (production wire/DB contract).
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
    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    _settings_mod.settings.federation_relay_enabled = value


@pytest.fixture()
def relay_nodes(
    fed_node: Any,
) -> tuple[Any, str, str, Ed25519PrivateKey, str, str, str, Ed25519PrivateKey, str]:
    """fed_node + a relay SENDER peer + a separate ORIGIN bound-peer (origin != sender).

    Both are entity_uri-bound peers with stored self-verifying manifests, so the SENDER's
    key resolves (it relays) and the ORIGIN resolves via the relay resolver's peer path
    (resolve_origin_key tier) + its issuer-signer manifest is stored.

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
    """(a) A relayed tombstone from a relay_trusted sender whose ORIGIN resolves (bound peer)
    with valid origin + issuer sigs is APPLIED; origin columns + received_from persist."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    (
        fed_node,
        sender_node_id,
        _sender_uri,
        sender_priv,
        _sender_kid,
        origin_node_id,
        origin_entity_uri,
        origin_priv,
        origin_key_id,
    ) = relay_nodes
    _set_relay_enabled(True)

    # The ISSUER is the ORIGIN node (signed_by == origin_entity_uri, manifest stored).
    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-bob",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id,
        entity_uri=origin_entity_uri,
        allowed_scopes=["public", "team"],
    )
    entry = _build_v2_tombstone_entry(origin_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="ca")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "ca"
    row = _tombstone_row("user:relay-bob")
    assert row is not None
    # Origin provenance columns + received_from persisted so THIS node can re-relay it.
    assert row["received_from"] == sender_node_id
    assert row["origin_node_id"] == origin_node_id
    assert row["origin_entity_uri"] == origin_entity_uri
    assert row["origin_tenant"] == _TENANT
    assert json.loads(row["origin_allowed_scopes"]) == ["public", "team"]
    assert json.loads(row["origin_allowed_tenants"]) == [_TENANT]
    assert row["origin_sig"] == entry["origin_sig"]


# ---------------------------------------------------------------------------
# (b) relay ON + sender NOT relay_trusted → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_on_untrusted_sender_skips(relay_nodes: Any) -> None:
    """(b) A relayed tombstone from a sender that is NOT relay_trusted is SKIPPED
    (relay_sender_not_trusted), fail-closed — never applied."""
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

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-untrusted",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["public"]
    )
    entry = _build_v2_tombstone_entry(origin_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="cb")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=0), _FakeClient(page), None
        )
    )
    assert new_cursor == "cb"  # page consumed, entry skipped
    assert _tombstone_row("user:relay-untrusted") is None


# ---------------------------------------------------------------------------
# (c) relay OFF → relayed tombstone SKIPPED (unchanged W6.5)
# ---------------------------------------------------------------------------


def test_relay_off_relayed_tombstone_skipped(relay_nodes: Any) -> None:
    """(c) With relay OFF, a relayed tombstone is SKIPPED (unchanged W6.5) even from an
    otherwise-trusted sender with a resolvable origin."""
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

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-off",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["public"]
    )
    entry = _build_v2_tombstone_entry(origin_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="cc")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "cc"
    assert _tombstone_row("user:relay-off") is None


# ---------------------------------------------------------------------------
# (d) origin UNREACHABLE + UNPINNED → resolve fails → SKIPPED (fail-closed)
# ---------------------------------------------------------------------------


def test_relay_unreachable_unpinned_origin_skips(relay_nodes: Any, monkeypatch: Any) -> None:
    """(d) A relayed tombstone whose ORIGIN is unreachable, not a bound peer, and unpinned
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

    # A wholly-unknown origin (not a bound peer, unreachable, unpinned).
    unknown_priv = Ed25519PrivateKey.generate()
    unknown_node = f"stigmem://unknown-{uuid.uuid4()}"
    unknown_uri = "https://unknown-origin.example"
    unknown_key_id = generate_key_id(unknown_priv.public_key())

    class _NoFetch:
        def __call__(self, *_a: Any, **_k: Any) -> Any:
            import httpx as _httpx  # noqa: PLC0415

            return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _NoFetch())
    monkeypatch.setattr(oi, "assert_safe_url", lambda *a, **k: None)

    rec = _issuer_signed_tombstone(
        unknown_priv,
        entity_uri="user:relay-unreachable",
        scope="public",
        signed_by=unknown_uri,
        key_id=unknown_key_id,
    )
    origin = _build_origin(
        node_id=unknown_node, entity_uri=unknown_uri, allowed_scopes=["public"]
    )
    entry = _build_v2_tombstone_entry(unknown_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="cd")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert new_cursor == "cd"
    assert _tombstone_row("user:relay-unreachable") is None


# ---------------------------------------------------------------------------
# (e) invalid ORIGIN sig → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_invalid_origin_sig_skips(relay_nodes: Any) -> None:
    """(e) A relayed tombstone whose ORIGIN signature does not verify is SKIPPED."""
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

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-badorigin",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["public"]
    )
    # Garbage origin_sig (issuer sig stays valid).
    entry = _build_v2_tombstone_entry(
        origin_priv, tombstone=rec, origin=origin, origin_sig="not-a-valid-sig"
    )
    page = _v2_page([entry], cursor="ce")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _tombstone_row("user:relay-badorigin") is None


# ---------------------------------------------------------------------------
# (f) invalid ISSUER-signer sig → SKIPPED (both sigs required)
# ---------------------------------------------------------------------------


def test_relay_invalid_issuer_sig_skips(relay_nodes: Any) -> None:
    """(f) A relayed tombstone with a valid ORIGIN sig but an INVALID issuer-signer sig is
    SKIPPED — a relayed tombstone must ALSO be a real suppression order."""
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

    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-badissuer",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    # Corrupt the issuer signature; re-sign the ORIGIN sig over the corrupted record so the
    # origin sig itself stays valid (the tombstone id/entity_uri/scope are unchanged).
    rec = rec.model_copy(update={"signature": "AAAA" + rec.signature[4:]})
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["public"]
    )
    entry = _build_v2_tombstone_entry(origin_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="cf")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _tombstone_row("user:relay-badissuer") is None


# ---------------------------------------------------------------------------
# (g) scope ∉ origin_allowed_scopes → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_scope_not_in_origin_grant_skips(relay_nodes: Any) -> None:
    """(g) A relayed tombstone whose scope is NOT inside origin.allowed_scopes is SKIPPED —
    a relay can't widen the scope a tombstone travels under (ingest scope gate)."""
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

    # tombstone scope 'public' but the origin only granted 'team'.
    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-scopegate",
        scope="public",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["team"]
    )
    entry = _build_v2_tombstone_entry(origin_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="cg")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _tombstone_row("user:relay-scopegate") is None


# ---------------------------------------------------------------------------
# (h) anti-relaunder: relay MUTATED scope (widened) → origin-sig check fails → SKIPPED
# ---------------------------------------------------------------------------


def test_relay_mutated_scope_fails_origin_sig_skips(relay_nodes: Any) -> None:
    """(h) ANTI-RELAUNDER: a relay that widened the on-wire tombstone scope ('team' → '*')
    past the SIGNED scope invalidates the origin signature (scope is bound in the tuple) →
    SKIPPED. The origin only ever signed scope='team'; the wire carries scope='*'."""
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

    # The wire tombstone claims scope='*' but the origin signed over scope='team' AND
    # allowed_scopes includes '*' (so the scope-gate alone would not catch it — only the
    # origin-sig binding does).
    rec = _issuer_signed_tombstone(
        origin_priv,
        entity_uri="user:relay-relaunder",
        scope="*",
        signed_by=origin_entity_uri,
        key_id=origin_key_id,
    )
    origin = _build_origin(
        node_id=origin_node_id, entity_uri=origin_entity_uri, allowed_scopes=["team", "*"]
    )
    # Sign the origin attestation over the NARROW scope the origin actually authorized.
    entry = _build_v2_tombstone_entry(
        origin_priv, tombstone=rec, origin=origin, sign_scope="team"
    )
    page = _v2_page([entry], cursor="ch")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    assert _tombstone_row("user:relay-relaunder") is None


# ---------------------------------------------------------------------------
# (i) direct tombstone (origin == sender) still applied (W6.5 path unchanged)
# ---------------------------------------------------------------------------


def test_direct_tombstone_still_applied_unchanged(relay_nodes: Any) -> None:
    """(i) A DIRECT tombstone (origin.node_id == sender) is still applied via the unchanged
    W6.5 path; origin columns stay NULL (self/direct), received_from NULL."""
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

    rec = _issuer_signed_tombstone(
        sender_priv,
        entity_uri="user:relay-direct",
        scope="public",
        signed_by=sender_entity_uri,
        key_id=sender_key_id,
    )
    origin = _build_origin(
        node_id=sender_node_id, entity_uri=sender_entity_uri, allowed_scopes=["public"]
    )
    entry = _build_v2_tombstone_entry(sender_priv, tombstone=rec, origin=origin)
    page = _v2_page([entry], cursor="ci")

    new_cursor = asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=0), _FakeClient(page), None
        )
    )
    assert new_cursor == "ci"
    row = _tombstone_row("user:relay-direct")
    assert row is not None
    # Direct/self path leaves the origin columns + received_from NULL (unchanged W6.5).
    assert row["received_from"] is None
    assert row["origin_node_id"] is None
    assert row["origin_sig"] is None
