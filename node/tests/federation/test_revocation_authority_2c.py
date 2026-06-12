"""Phase 2c — same-issuer binding for tombstone revocations (RTBF integrity).

A revocation REINSTATES (un-suppresses) a tombstoned entity. Before this fix the
revocation verify chain checked the revocation's OWN signatures but NOTHING tied the
revoking authority to the authority that issued the ORIGINAL tombstone. So any
``relay_trusted`` peer — OR any authenticated push peer via the BARE (non-enveloped)
revocation path — could mint a revocation referencing ANOTHER org's ``tombstone_id`` and
un-suppress content that org ordered forgotten (censorship-integrity violation; the
irreversible-harm direction).

FOUNDER DECISION (locked): **same-issuer binding.** A federated/relayed revocation is
applied ONLY if its signer (``revocation.signed_by``) matches the original tombstone's
issuer (``tombstone.signed_by``). Only the org that suppressed can un-suppress. Reject
``revocation_authority_mismatch`` otherwise; gate the bare-revocation push path the same way.

Two enforcement points (single security invariant):
  1. INGEST chokepoint: ``apply_inbound_revocation`` rejects a revocation whose
     ``signed_by`` != the held tombstone's ``signed_by`` (pull → skip + audit, push → 403).
  2. RECALL-time suppression-lift: a stored revocation only cancels a tombstone whose
     ``signed_by`` matches — so an unknown-tombstone revocation is inert until a SAME-ISSUER
     tombstone exists, and a forged cross-issuer revocation can NEVER lift a suppression
     (retroactively covers already-stored revocations + the unknown-then-arrives case).

Tests:
  (a) relayed CROSS-issuer revocation rejected → tombstone STAYS suppressed.
  (b) relayed SAME-issuer revocation applied → entity reinstated.
  (c) bare push CROSS-issuer rejected → not applied.
  (d) bare push SAME-issuer applied → back-compat preserved.
  (e) unknown-tombstone forged revocation is INERT: a B-signed revocation for an unheld
      tombstone_id; later A issues that tombstone → entity is SUPPRESSED (forged revocation
      does NOT lift A's suppression). [recall-query approach]
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from typing import Any

from stigmem_node.db import db as _db_ctx
from stigmem_node.lifecycle import tombstones as tombstones_mod

# ``relay_nodes`` / ``push_node`` fixtures are provided by tests/federation/conftest.py.
from .test_revocation_relay_2c import (
    _TENANT,
    _build_origin,
    _build_v2_revocation_entry,
    _FakeClient,
    _issuer_signed_revocation,
    _peer_dict,
    _PushNode,
    _revocation_row,
    _set_relay_enabled,
    _v2_page,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _insert_tombstone_signed_by(
    db_path: str, *, tombstone_id: str, entity_uri: str, signed_by: str
) -> None:
    """Insert a suppressing tombstone with an explicit ``signed_by`` issuer."""
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


def _is_suppressed(entity_uri: str) -> bool:
    """True iff *entity_uri* is suppressed at recall time (active, un-revoked tombstone)."""
    tombstones_mod.invalidate_tombstone_cache()
    return tombstones_mod.is_tombstoned(entity_uri, "*")


def _push_insert_tombstone_signed_by(entity_uri: str, signed_by: str) -> str:
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
    tombstones_mod.invalidate_tombstone_cache()
    return tomb_id


def _enable_recall_filter(monkeypatch: Any) -> None:
    """Force the recall-time tombstone filter ON so is_tombstoned reflects DB state."""
    import stigmem_node.lifecycle.tombstone_gate as gate

    monkeypatch.setattr(gate, "tombstone_filter_enabled", lambda: True)


# ---------------------------------------------------------------------------
# (a) relayed CROSS-issuer revocation rejected → tombstone STAYS suppressed
# ---------------------------------------------------------------------------


def test_a_relayed_cross_issuer_revocation_rejected(relay_nodes: Any, monkeypatch: Any) -> None:
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
    _enable_recall_filter(monkeypatch)

    entity_x = "user:cross-issuer-a"
    tomb_id = f"tomb_{uuid.uuid4()}"
    # Tombstone issued by org A (a DIFFERENT issuer than the relayed revocation's signer B).
    _insert_tombstone_signed_by(
        fed_node.db_path,
        tombstone_id=tomb_id,
        entity_uri=entity_x,
        signed_by="stigmem://org-a/issuer",
    )
    assert _is_suppressed(entity_x) is True

    # Org B (the relayed origin) signs a revocation for A's tombstone.
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="auth-a")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    # Rejected: no revocation row written.
    assert _revocation_row(rec.id) is None
    # Suppression intact: A's tombstone still suppresses entity_x.
    assert _is_suppressed(entity_x) is True


# ---------------------------------------------------------------------------
# (b) relayed SAME-issuer revocation applied → entity reinstated
# ---------------------------------------------------------------------------


def test_b_relayed_same_issuer_revocation_applied(relay_nodes: Any, monkeypatch: Any) -> None:
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
    _enable_recall_filter(monkeypatch)

    entity_x = "user:same-issuer-b"
    tomb_id = f"tomb_{uuid.uuid4()}"
    # Tombstone issued by org A == the revoking origin's signer (origin_entity_uri).
    _insert_tombstone_signed_by(
        fed_node.db_path, tombstone_id=tomb_id, entity_uri=entity_x, signed_by=origin_entity_uri
    )
    assert _is_suppressed(entity_x) is True

    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="auth-b")

    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )
    # Applied: revocation row written + entity reinstated.
    assert _revocation_row(rec.id) is not None
    assert _is_suppressed(entity_x) is False


# ---------------------------------------------------------------------------
# (c) bare push CROSS-issuer rejected → not applied
# ---------------------------------------------------------------------------


def test_c_bare_push_cross_issuer_rejected(push_node: _PushNode) -> None:
    _set_relay_enabled(True)

    entity_x = "user:bare-cross-c"
    # Tombstone issued by org A.
    tomb_id = _push_insert_tombstone_signed_by(entity_x, "stigmem://org-a/issuer")

    # Bare revocation signed by the SENDER (org B) — a different issuer than A.
    rec = _issuer_signed_revocation(
        push_node.sender_priv,
        tombstone_id=tomb_id,
        signed_by=push_node.sender_entity_uri,
        key_id=push_node.sender_key_id,
    )
    resp = push_node.post(rec.model_dump())
    assert resp.status_code == 403, resp.text
    assert "revocation_authority_mismatch" in resp.json()["detail"]
    assert _revocation_row(rec.id) is None


# ---------------------------------------------------------------------------
# (d) bare push SAME-issuer applied → back-compat preserved
# ---------------------------------------------------------------------------


def test_d_bare_push_same_issuer_applied(push_node: _PushNode) -> None:
    _set_relay_enabled(True)

    entity_x = "user:bare-same-d"
    # Tombstone issued by the SENDER's own entity (same issuer as the bare revocation).
    tomb_id = _push_insert_tombstone_signed_by(entity_x, push_node.sender_entity_uri)

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


# ---------------------------------------------------------------------------
# (e) unknown-tombstone forged revocation is INERT (recall-query approach)
# ---------------------------------------------------------------------------


def test_e_unknown_tombstone_forged_revocation_inert(
    relay_nodes: Any, monkeypatch: Any
) -> None:
    """A B-signed revocation for a tombstone_id NOT held; later A issues that tombstone.
    The forged B-revocation must NOT lift A's suppression — the entity stays SUPPRESSED."""
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
    _enable_recall_filter(monkeypatch)

    entity_x = "user:unknown-then-arrives-e"
    tomb_id = f"tomb_{uuid.uuid4()}"

    # 1) B signs a revocation for a tombstone_id NOT yet held locally. It stores (out-of-order
    #    arrival is allowed) but must be inert because no SAME-issuer tombstone exists.
    rec = _issuer_signed_revocation(
        origin_priv, tombstone_id=tomb_id, signed_by=origin_entity_uri, key_id=origin_key_id
    )
    origin = _build_origin(node_id=origin_node_id, entity_uri=origin_entity_uri)
    entry = _build_v2_revocation_entry(origin_priv, revocation=rec, origin=origin)
    page = _v2_page([entry], cursor="auth-e")
    asyncio.run(
        pull_tombstones_from_peer_once(
            _peer_dict(sender_node_id, relay_ok=1), _FakeClient(page), None
        )
    )

    # 2) Later, org A issues the tombstone with that id (A != B).
    _insert_tombstone_signed_by(
        fed_node.db_path,
        tombstone_id=tomb_id,
        entity_uri=entity_x,
        signed_by="stigmem://org-a/issuer",
    )

    # 3) The forged B-revocation does NOT lift A's suppression.
    assert _is_suppressed(entity_x) is True
