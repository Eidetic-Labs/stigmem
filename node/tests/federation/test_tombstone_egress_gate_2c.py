"""Phase 2c W6.6 — SQL egress gate for RELAYED tombstones (scope/tenant grant).

Mirrors the FACT egress gate (W2.3, ``test_relay_2c.py``) on the tombstone path. The
tombstone poll GET re-federates a RELAYED tombstone (``received_from IS NOT NULL``) ONLY
when, with relay ON, the origin's signed grant permits it for THIS peer:
  * the tombstone's ``scope`` is a member of its stored ``origin_allowed_scopes`` JSON, AND
  * ``origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅``.
With relay OFF, ONLY self-originated (``received_from IS NULL``) tombstones egress — Phase-1
identical. The gate lives ENTIRELY in SQL (``list_federatable_tombstones``) so ``LIMIT``
applies post-filter (no Python post-filtering → no short pages / skipped cursor).

Tests:
  (a) relay OFF → only ``received_from IS NULL`` tombstones returned (a relayed row withheld).
  (b) relay ON → a relayed tombstone whose scope ∈ origin_allowed_scopes AND
      origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅ IS returned.
  (c) relay ON → a relayed tombstone whose scope ∉ origin_allowed_scopes is WITHHELD.
  (d) relay ON → a relayed tombstone whose origin_allowed_tenants excludes the peer is WITHHELD.
  (e) self-originated tombstones always egress regardless of the relay flag.
  (f) the limit/cursor still works with the relay filter IN SQL (mix pass/withheld spanning
      pages at a small limit → no short non-final page, exactly the eligible rows returned).
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

import pytest
from conftest import FedNode, make_peer_token

from .helpers import generate_ed25519_b64

_TENANT = "default"
_ORIGIN_NODE_ID = "stigmem:node:tomb-upstream-origin"
_ORIGIN_TENANT = "acme"
_ORIGIN_ENTITY_URI = "https://tomb-upstream-origin.example"


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    """Set trust_mode=off so a peer-JWT Bearer token passes the poll auth (mirrors the
    existing W6.5 tombstone poll tests)."""
    import sys as _sys

    fed_mod = _sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_mod.settings, "trust_mode", "off", raising=False)


def _set_relay_enabled(value: bool) -> None:
    """Toggle federation_relay_enabled on the live (test-patched) settings object.

    The poll route reads the flag via ``_public_module().settings`` — the same Settings
    instance the fed_node fixture patched across federation modules — so mutating that
    instance is sufficient and is restored by the fixture teardown.
    """
    import stigmem_node.settings as _settings_mod

    _settings_mod.settings.federation_relay_enabled = value


def _insert_self_tombstone(db_path: str, *, entity_uri: str, scope: str, created_at: str) -> str:
    """Insert a SELF-originated tombstone (received_from IS NULL)."""
    tomb_id = f"tomb_{uuid.uuid4()}"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tomb_id,
                entity_uri,
                scope,
                None,
                "stigmem://local/issuer",
                "key-1",
                "issuer-sig",
                created_at,
                0,
                _TENANT,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return tomb_id


def _insert_relayed_tombstone(
    db_path: str,
    *,
    entity_uri: str,
    scope: str,
    created_at: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
) -> str:
    """Insert an INBOUND (relayed) tombstone row (received_from IS NOT NULL) + stored
    origin block. origin_allowed_* are stored with the canonical ``json.dumps(sorted([...]))``
    encoding (the same encoding ingest uses). A stored origin_sig + origin_entity_uri are set
    so the W6.5 emit path forwards rather than skipping it."""
    tomb_id = f"tomb_{uuid.uuid4()}"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id, received_from,
                origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                tomb_id,
                entity_uri,
                scope,
                None,
                _ORIGIN_ENTITY_URI,
                "key-1",
                "issuer-sig",
                created_at,
                0,
                _TENANT,
                "stigmem:node:tomb-direct-peer",  # received_from -> relayed
                _ORIGIN_NODE_ID,
                _ORIGIN_TENANT,
                _ORIGIN_ENTITY_URI,
                json.dumps(sorted(origin_allowed_scopes)),
                json.dumps(sorted(origin_allowed_tenants)),
                f"STORED-ORIGIN-SIG-{tomb_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return tomb_id


def _insert_relayed_revocation(
    db_path: str,
    *,
    tombstone_id: str,
    created_at: str,
    origin_allowed_tenants: list[str],
) -> str:
    """Insert an INBOUND (relayed) revocation row (received_from IS NOT NULL) + stored origin
    block. The gate on revocations is TENANT-ONLY (no scope), so only origin_allowed_tenants is
    controlled here. A stored origin_sig + origin_entity_uri are set so the Rev-2 emit path
    forwards rather than skipping it. The referenced tombstone is also created (the poll route
    surfaces the revocation independently of tombstone presence, but we keep it consistent)."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, key_id, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                tombstone_id,
                f"user:rev-target-{tombstone_id}",
                "public",
                None,
                "stigmem://local/issuer",
                "key-1",
                "issuer-sig",
                created_at,
                0,
                _TENANT,
            ),
        )
        rev_id = f"tombrevoke_{uuid.uuid4()}"
        conn.execute(
            """INSERT INTO tombstone_revocations
               (id, tombstone_id, reason, signed_by, key_id, signature, created_at,
                received_from, origin_node_id, origin_tenant, origin_entity_uri,
                origin_allowed_scopes, origin_allowed_tenants, origin_sig)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rev_id,
                tombstone_id,
                "relayed-revocation",
                _ORIGIN_ENTITY_URI,
                "key-1",
                "issuer-sig",
                created_at,
                "stigmem:node:tomb-direct-peer",  # received_from -> relayed
                _ORIGIN_NODE_ID,
                _ORIGIN_TENANT,
                _ORIGIN_ENTITY_URI,
                None,
                json.dumps(sorted(origin_allowed_tenants)),
                f"STORED-ORIGIN-SIG-{rev_id}",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return rev_id


def _register_pull_peer(
    fed_node: FedNode,
    *,
    allowed_scopes: list[str],
    allowed_tenants: list[str],
    pull_tenant: str = _TENANT,
) -> tuple[str, str]:
    """Register an active peer with explicit allowed_scopes/allowed_tenants. Returns
    (node_id, priv_b64) for minting a pull token."""
    pub_b64, priv_b64 = generate_ed25519_b64()
    node_id = f"stigmem://tomb-pull-{uuid.uuid4()}"
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
                "http://tomb-pull",
                pub_b64,
                json.dumps(allowed_scopes),
                "active",
                "test_dummy_sig",
                "2026-05-02T00:00:00Z",
                pull_tenant,
                json.dumps(allowed_tenants),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return node_id, priv_b64


def _poll_entity_uris(
    fed_node: FedNode, node_id: str, priv: str, **q: Any
) -> set[str]:
    """Hit the tombstone poll endpoint; return the set of returned tombstone entity_uris."""
    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    url = "/v1/federation/tombstones" + (f"?{qs}" if qs else "")
    r = fed_node.client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return {e["tombstone"]["entity_uri"] for e in r.json()["tombstones"]}


def _poll_revocation_ids(fed_node: FedNode, node_id: str, priv: str, **q: Any) -> set[str]:
    """Hit the tombstone poll endpoint; return the set of returned revocation ids."""
    token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    url = "/v1/federation/tombstones" + (f"?{qs}" if qs else "")
    r = fed_node.client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return {e["revocation"]["id"] for e in r.json()["revocations"]}


# ---------------------------------------------------------------------------
# (a) relay OFF — only self-originated egress; a relayed row is withheld.
# ---------------------------------------------------------------------------


def test_relay_off_withholds_relayed_tombstone(fed_node: FedNode, _trust_off: None) -> None:
    """(a) relay OFF — only received_from IS NULL tombstones returned (Phase-1 identical)."""
    _set_relay_enabled(False)
    self_e = "user:self-a"
    _insert_self_tombstone(
        fed_node.db_path, entity_uri=self_e, scope="public", created_at="2026-06-10T00:00:01Z"
    )
    relayed_e = "user:relayed-a"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:02Z",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    uris = _poll_entity_uris(fed_node, node_id, priv)
    assert self_e in uris
    assert relayed_e not in uris


# ---------------------------------------------------------------------------
# (b) relay ON — relayed tombstone within origin grant IS returned.
# ---------------------------------------------------------------------------


def test_relay_on_egresses_relayed_within_origin_grant(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(b) relay ON — scope ∈ origin_allowed_scopes AND tenants overlap → returned."""
    _set_relay_enabled(True)
    relayed_e = "user:relayed-b"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["public", "team"],
        origin_allowed_tenants=["acme", "default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert relayed_e in _poll_entity_uris(fed_node, node_id, priv)


# ---------------------------------------------------------------------------
# (c) relay ON — scope outside origin grant → withheld.
# ---------------------------------------------------------------------------


def test_relay_on_withholds_scope_outside_origin_grant(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(c) relay ON — scope ∉ origin_allowed_scopes → withheld."""
    _set_relay_enabled(True)
    relayed_e = "user:relayed-c"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["team"],  # 'public' NOT granted by origin
        origin_allowed_tenants=["default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert relayed_e not in _poll_entity_uris(fed_node, node_id, priv)


# ---------------------------------------------------------------------------
# (d) relay ON — tenant outside origin grant → withheld.
# ---------------------------------------------------------------------------


def test_relay_on_withholds_tenant_outside_origin_grant(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(d) relay ON — origin_allowed_tenants ∩ peer.allowed_tenants = ∅ → withheld."""
    _set_relay_enabled(True)
    relayed_e = "user:relayed-d"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],  # peer.allowed_tenants is ["default"] → no overlap
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert relayed_e not in _poll_entity_uris(fed_node, node_id, priv)


# ---------------------------------------------------------------------------
# (e) self-originated tombstones always egress regardless of the relay flag.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relay_on", [False, True])
def test_self_originated_always_egresses(
    fed_node: FedNode, _trust_off: None, relay_on: bool
) -> None:
    """(e) a self-originated (received_from IS NULL) tombstone egresses with relay both off
    and on (the relay branch never perturbs the self-only path)."""
    _set_relay_enabled(relay_on)
    self_e = f"user:self-e-{relay_on}"
    _insert_self_tombstone(
        fed_node.db_path, entity_uri=self_e, scope="public", created_at="2026-06-10T00:00:01Z"
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert self_e in _poll_entity_uris(fed_node, node_id, priv)


# ---------------------------------------------------------------------------
# (f) limit/cursor works with the relay filter IN SQL (no short non-final page).
# ---------------------------------------------------------------------------


def test_relay_on_pagination_filters_in_sql_not_python(
    fed_node: FedNode, _trust_off: None
) -> None:
    """(f) relay ON, a mix of pass/withheld relayed tombstones spanning >1 page at a small
    limit: every non-final page is FULL (no short page from post-filtering), the cursor
    advances past withheld rows, and exactly the eligible tombstones come back. Proves the
    gate is IN SQL (LIMIT applies post-filter)."""
    _set_relay_enabled(True)

    # 12 relayed tombstones: even-indexed PASS (origin grants public+default), odd-indexed
    # FAIL (origin tenant excludes the peer's tenant). created_at strictly increasing for a
    # stable cursor order; interleaved so a Python post-filter would produce short pages.
    expected_pass: set[str] = set()
    for i in range(12):
        passes = i % 2 == 0
        entity = f"user:page-{i}"
        _insert_relayed_tombstone(
            fed_node.db_path,
            entity_uri=entity,
            scope="public",
            created_at=f"2026-06-10T00:00:{i:02d}Z",
            origin_allowed_scopes=["public"],
            origin_allowed_tenants=(["default"] if passes else ["acme"]),
        )
        if passes:
            expected_pass.add(entity)

    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )

    collected: set[str] = set()
    cursor: str | None = None
    limit = 3
    for _ in range(20):  # generous page cap; loop breaks on has_more=False
        token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
        qs = f"limit={limit}" + (f"&since={cursor}" if cursor else "")
        r = fed_node.client.get(
            f"/v1/federation/tombstones?{qs}", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        page_uris = [e["tombstone"]["entity_uri"] for e in body["tombstones"]]
        collected.update(page_uris)
        if body["has_more"]:
            assert len(page_uris) == limit, (
                "non-final page is short → filtering leaked to Python"
            )
        cursor = body["cursor"]
        if not body["has_more"]:
            break

    assert collected == expected_pass
    # 6 eligible tombstones at limit 3 ⇒ no eligible row lost, no ineligible row slipped in.
    assert len(collected) == 6


# ---------------------------------------------------------------------------
# LIKE-metacharacter egress hardening: the tenant-overlap LIKE must be EXACT on
# BOTH the tombstone and the revocation egress gate. peer.allowed_tenants is
# operator-set free text (migration 041, no enum), so a wildcard-bearing tenant
# name (``_`` single-char / ``%`` any-run) must NOT false-match a DIFFERENT origin
# tenant. ``a_me`` must not match origin grant ``["acme"]``.
# ---------------------------------------------------------------------------


def test_tombstone_relay_tenant_underscore_does_not_wildcard_match(
    fed_node: FedNode, _trust_off: None
) -> None:
    """A peer whose allowed_tenants is ``["a_me"]`` (``_`` = LIKE single-char wildcard) must
    NOT receive a relayed tombstone whose origin_allowed_tenants is ``["acme"]`` — the ``_``
    must be escaped so it matches only a literal underscore, not the ``c`` in ``acme``."""
    _set_relay_enabled(True)
    relayed_e = "user:tomb-underscore"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"]
    )
    assert relayed_e not in _poll_entity_uris(fed_node, node_id, priv)


def test_tombstone_relay_tenant_percent_does_not_wildcard_match(
    fed_node: FedNode, _trust_off: None
) -> None:
    """A peer whose allowed_tenants is ``["a%"]`` (``%`` = LIKE any-run wildcard) must NOT
    receive a relayed tombstone whose origin_allowed_tenants is ``["acme"]``."""
    _set_relay_enabled(True)
    relayed_e = "user:tomb-percent"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a%"]
    )
    assert relayed_e not in _poll_entity_uris(fed_node, node_id, priv)


def test_tombstone_relay_tenant_exact_metachar_still_egresses(
    fed_node: FedNode, _trust_off: None
) -> None:
    """Positive control: an exact literal ``a_me`` tenant on both sides still egresses —
    escaping the wildcard must not break a legitimate metacharacter-bearing tenant match."""
    _set_relay_enabled(True)
    relayed_e = "user:tomb-exact-metachar"
    _insert_relayed_tombstone(
        fed_node.db_path,
        entity_uri=relayed_e,
        scope="public",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["a_me"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"]
    )
    assert relayed_e in _poll_entity_uris(fed_node, node_id, priv)


def test_revocation_relay_tenant_underscore_does_not_wildcard_match(
    fed_node: FedNode, _trust_off: None
) -> None:
    """A peer whose allowed_tenants is ``["a_me"]`` must NOT receive a relayed revocation whose
    origin_allowed_tenants is ``["acme"]`` — the revocation egress gate (tenant-only) must
    escape the ``_`` so it does not wildcard-match a different origin tenant."""
    _set_relay_enabled(True)
    rev_id = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id=f"tomb_{uuid.uuid4()}",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_tenants=["acme"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"]
    )
    assert rev_id not in _poll_revocation_ids(fed_node, node_id, priv)


def test_revocation_relay_tenant_percent_does_not_wildcard_match(
    fed_node: FedNode, _trust_off: None
) -> None:
    """A peer whose allowed_tenants is ``["a%"]`` must NOT receive a relayed revocation whose
    origin_allowed_tenants is ``["acme"]``."""
    _set_relay_enabled(True)
    rev_id = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id=f"tomb_{uuid.uuid4()}",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_tenants=["acme"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a%"]
    )
    assert rev_id not in _poll_revocation_ids(fed_node, node_id, priv)


def test_revocation_relay_tenant_exact_metachar_still_egresses(
    fed_node: FedNode, _trust_off: None
) -> None:
    """Positive control: an exact literal ``a_me`` tenant on both sides still egresses a
    relayed revocation."""
    _set_relay_enabled(True)
    rev_id = _insert_relayed_revocation(
        fed_node.db_path,
        tombstone_id=f"tomb_{uuid.uuid4()}",
        created_at="2026-06-10T00:00:01Z",
        origin_allowed_tenants=["a_me"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"]
    )
    assert rev_id in _poll_revocation_ids(fed_node, node_id, priv)
