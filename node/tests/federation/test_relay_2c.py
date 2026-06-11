"""Phase 2c relay — W2/W3 relay tests accumulate here.

W2.1: dormant foundation — relay enablement flag + peers.relay_trusted column
(both default off; no runtime behaviour change until W2.2+).

W2.2: at egress emit, distinguish self-originated (sign a FRESH origin block with
this node's identity — unchanged 2b behaviour) from relayed facts (received_from
not NULL — forward the STORED origin block + STORED origin_sig verbatim, no re-sign).
"""

import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.db import db
from stigmem_node.federation.origin_signature import sign_origin
from stigmem_node.models.facts import FactRecord, FactValue
from stigmem_node.settings import Settings

# ---------------------------------------------------------------------------
# W2.1 — settings flag
# ---------------------------------------------------------------------------


def test_federation_relay_enabled_defaults_false() -> None:
    """Settings().federation_relay_enabled must default to False (relay is OFF)."""
    assert Settings().federation_relay_enabled is False


# ---------------------------------------------------------------------------
# W2.1 — migration 045: peers.relay_trusted column
# ---------------------------------------------------------------------------


def test_peers_has_relay_trusted_column(client) -> None:  # type: ignore[no-untyped-def]
    """Migration 045 adds relay_trusted to peers; PRAGMA table_info confirms it."""
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    assert "relay_trusted" in cols


def test_relay_trusted_defaults_to_zero(client) -> None:  # type: ignore[no-untyped-def]
    """A peer inserted without relay_trusted reads 0 (default off)."""
    with db() as conn:
        conn.execute(
            "INSERT INTO peers "
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, "
            "declaration_sig, signed_at) "
            "VALUES ('rt1', 'stigmem:node:rt1', 'http://x', 'PUB', '[]', 'active', "
            "'SIG', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT relay_trusted FROM peers WHERE id='rt1'"
        ).fetchone()
    assert row["relay_trusted"] == 0


# ---------------------------------------------------------------------------
# W2.2 — emit branch: self-originated (fresh sign) vs relayed (forward verbatim)
# ---------------------------------------------------------------------------

# This node's identity at emit time (the relay node). Distinct from the ORIGIN.
_OWN_NODE_ID = "stigmem:node:relay-self"
_PULL_TENANT = "default"

# The ORIGIN node (the upstream that first asserted the relayed fact).
_ORIGIN_NODE_ID = "stigmem:node:upstream-origin"
_ORIGIN_TENANT = "acme"


def _self_record() -> FactRecord:
    """A locally-originated, replication-eligible record (received_from is None)."""
    return FactRecord(
        id="11111111-1111-1111-1111-111111111111",
        entity="self:entity",
        relation="self:value",
        value=FactValue(type="string", v="local"),
        source="agent:test",
        timestamp="2026-06-10T00:00:00Z",
        hlc="1.000",
        received_from=None,
        confidence=1.0,
        scope="public",
        cid="bafyselfcid",
        origin_allowed_scopes=None,
    )


def _relayed_record() -> FactRecord:
    """A record received FROM a peer (received_from not None) — relay forwards it."""
    return FactRecord(
        id="22222222-2222-2222-2222-222222222222",
        entity="relayed:entity",
        relation="relayed:value",
        value=FactValue(type="string", v="from-upstream"),
        source=_ORIGIN_NODE_ID,
        timestamp="2026-06-10T00:00:00Z",
        hlc="2.000",
        received_from="stigmem:node:direct-peer",
        confidence=1.0,
        scope="public",
        cid="bafyrelayedcid",
        origin_node_id=_ORIGIN_NODE_ID,
        origin_allowed_scopes=["public"],
    )


def _stored_origin_row(
    record: FactRecord,
    *,
    origin_sig: str | None,
    origin_tenant: str | None = _ORIGIN_TENANT,
    origin_node_id: str | None = _ORIGIN_NODE_ID,
    origin_allowed_scopes: list[str] | None = None,
    origin_allowed_tenants: list[str] | None = None,
) -> dict[str, Any]:
    """A DB-row stand-in carrying the stored origin_* columns FactRecord omits."""
    return {
        "id": record.id,
        "origin_tenant": origin_tenant,
        "origin_node_id": origin_node_id,
        "origin_allowed_scopes": (
            json.dumps(origin_allowed_scopes) if origin_allowed_scopes is not None else None
        ),
        "origin_allowed_tenants": (
            json.dumps(origin_allowed_tenants) if origin_allowed_tenants is not None else None
        ),
        "origin_sig": origin_sig,
    }


def test_self_originated_emit_signs_fresh_with_own_identity() -> None:
    """Self-originated fact: emit a fresh OriginBlock for THIS node + a fresh sig."""
    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _self_record()
    row = _stored_origin_row(record, origin_sig=None, origin_node_id=None, origin_tenant=None)

    result = build_origin_entry(
        record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
    )
    assert result is not None
    origin, sig = result
    assert origin.node_id == _OWN_NODE_ID  # this node, not an upstream
    assert origin.tenant == _PULL_TENANT
    assert origin.allowed_tenants == [_PULL_TENANT]
    # the sig is freshly computed over THIS node's origin block
    assert record.cid is not None
    expected = sign_origin(
        priv,
        fact_id=record.id,
        cid=record.cid,
        origin=origin.model_dump(),
        valid_until=record.valid_until,
    )
    assert sig == expected


def test_relayed_emit_forwards_stored_origin_block_verbatim() -> None:
    """Relayed fact: emit the STORED origin block + STORED origin_sig, no re-sign."""
    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _relayed_record()
    stored_sig = "STORED-ORIGIN-SIGNATURE-FROM-UPSTREAM"
    row = _stored_origin_row(
        record,
        origin_sig=stored_sig,
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
    )

    result = build_origin_entry(
        record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
    )
    assert result is not None
    origin, sig = result
    # origin attribution is the UPSTREAM origin, NOT this relay node
    assert origin.node_id == _ORIGIN_NODE_ID
    assert origin.node_id != _OWN_NODE_ID
    assert origin.tenant == _ORIGIN_TENANT
    assert origin.allowed_scopes == ["public"]
    assert origin.allowed_tenants == ["acme"]
    # the stored sig is forwarded verbatim (NOT re-signed by this node)
    assert sig == stored_sig
    assert record.cid is not None
    fresh = sign_origin(
        priv,
        fact_id=record.id,
        cid=record.cid,
        origin=origin.model_dump(),
        valid_until=record.valid_until,
    )
    assert sig != fresh  # proves it was not re-signed locally


def test_relayed_emit_without_stored_sig_is_skipped(caplog) -> None:  # type: ignore[no-untyped-def]
    """A relayed fact missing its stored origin_sig is SKIPPED (None) + warned."""
    import logging  # noqa: PLC0415

    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _relayed_record()
    row = _stored_origin_row(record, origin_sig=None, origin_allowed_scopes=["public"])

    with caplog.at_level(logging.WARNING):
        result = build_origin_entry(
            record, row, own_node_id=_OWN_NODE_ID, pull_tenant=_PULL_TENANT, priv=priv
        )
    assert result is None
    assert any(record.id in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# W2.3 — SQL egress RE-FEDERATES relayed facts ONLY within origin propagation
# limits, and ONLY when ``federation_relay_enabled`` is ON.
#
# These are end-to-end pull-endpoint tests: an INBOUND (received_from not NULL)
# fact is inserted directly into the DB with controlled origin_allowed_scopes /
# origin_allowed_tenants / scope / re_federation_blocked, a peer is registered
# with specific allowed_scopes / allowed_tenants, and the pull endpoint is hit.
# The assertions are over WHICH fact ids come back in the v2 envelope.
# ---------------------------------------------------------------------------

import uuid  # noqa: E402

from conftest import FedNode, make_peer_token  # noqa: E402

from stigmem_node.db import db as _db_ctx  # noqa: E402

from .helpers import generate_ed25519_b64  # noqa: E402


def _set_relay_enabled(value: bool) -> None:
    """Toggle federation_relay_enabled on the live (test-patched) settings object.

    The pull route reads the flag via ``_public_module().settings`` — the same
    Settings instance the fed_node fixture patched across federation modules — so
    mutating that instance is sufficient and is restored by the fixture teardown.
    """
    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    _settings_mod.settings.federation_relay_enabled = value


def _insert_inbound_fact(
    db_path: str,
    *,
    entity: str,
    scope: str,
    hlc: str,
    origin_allowed_scopes: list[str],
    origin_allowed_tenants: list[str],
    re_federation_blocked: int = 0,
    tenant_id: str = "default",
) -> str:
    """Insert an INBOUND (relayed) fact row directly + return its id.

    ``received_from`` is non-NULL (this is a relayed fact, not self-originated).
    origin_allowed_scopes / origin_allowed_tenants are stored with the SAME
    canonical encoding ingest uses: ``json.dumps(sorted([...]))``. A stored
    origin_sig is set so the W2.2 emit path forwards it rather than skipping.
    """
    import sqlite3  # noqa: PLC0415

    fact_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                confidence, scope, hlc, tenant_id, received_from,
                origin_node_id, origin_allowed_scopes, re_federation_blocked,
                origin_tenant, origin_allowed_tenants, origin_sig, cid)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                entity,
                "relayed:value",
                "string",
                "from-upstream",
                _ORIGIN_NODE_ID,
                "2026-06-10T00:00:00Z",
                1.0,
                scope,
                hlc,
                tenant_id,
                "stigmem:node:direct-peer",  # received_from -> relayed
                _ORIGIN_NODE_ID,
                json.dumps(sorted(origin_allowed_scopes)),
                re_federation_blocked,
                _ORIGIN_TENANT,
                json.dumps(sorted(origin_allowed_tenants)),
                f"STORED-SIG-{fact_id}",
                f"bafycid{fact_id[:8]}",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return fact_id


def _register_pull_peer(
    fed_node: FedNode,
    *,
    allowed_scopes: list[str],
    allowed_tenants: list[str],
    pull_tenant: str = "default",
) -> tuple[str, str]:
    """Register an active peer with explicit allowed_scopes/allowed_tenants/pull_tenant.

    Returns (node_id, priv_b64) for minting a pull token.
    """
    import sqlite3  # noqa: PLC0415

    pub_b64, priv_b64 = generate_ed25519_b64()
    node_id = f"stigmem://relay-pull-{uuid.uuid4()}"
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
                "http://relay-pull",
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


def _pull_ids(fed_node: FedNode, node_id: str, priv: str, scopes: list[str], **q: Any) -> set[str]:
    """Hit the pull endpoint and return the set of returned fact ids."""
    token = make_peer_token(priv, node_id, fed_node.node_id, scopes)
    qs = "&".join(f"{k}={v}" for k, v in q.items())
    url = "/v1/federation/facts" + (f"?{qs}" if qs else "")
    r = fed_node.client.get(url, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return {e["fact"]["id"] for e in r.json()["facts"]}


def test_relay_on_egresses_relayed_fact_within_origin_limits(fed_node: FedNode) -> None:
    """W2.3 (a): relay ON — a relayed fact egresses iff its scope is in
    origin_allowed_scopes ∩ peer.allowed_scopes AND
    origin_allowed_tenants ∩ peer.allowed_tenants is non-empty."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:in-limits",
        scope="public",
        hlc="100.000",
        origin_allowed_scopes=["public", "team"],
        origin_allowed_tenants=["acme", "default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert fid in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_blocks_relayed_fact_scope_outside_origin_grant(fed_node: FedNode) -> None:
    """W2.3 (a, negative): a relayed fact whose scope is NOT in
    origin_allowed_scopes does NOT egress even when relay is ON."""
    _set_relay_enabled(True)
    # Origin only granted scope "team"; the peer is pulling scope "public".
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:scope-outside",
        scope="public",
        hlc="101.000",
        origin_allowed_scopes=["team"],  # 'public' NOT granted by origin
        origin_allowed_tenants=["default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_blocks_relayed_fact_tenant_outside_origin_grant(fed_node: FedNode) -> None:
    """W2.3 (b): a relayed fact whose origin_allowed_tenants excludes the peer's
    tenant set does NOT egress."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:tenant-outside",
        scope="public",
        hlc="102.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],  # peer.allowed_tenants is ["default"] → no overlap
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_never_egresses_re_federation_blocked(fed_node: FedNode) -> None:
    """W2.3 (c): a relayed fact with re_federation_blocked=1 never egresses,
    even when scope + tenant otherwise pass."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:blocked",
        scope="public",
        hlc="103.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["default"],
        re_federation_blocked=1,
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_off_never_egresses_inbound_facts(fed_node: FedNode) -> None:
    """W2.3 (d): with relay OFF (today's behaviour), NO inbound fact egresses —
    even one fully within origin propagation limits. Regression guard."""
    _set_relay_enabled(False)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:off",
        scope="public",
        hlc="104.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["default"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_pagination_filters_in_sql_not_python(fed_node: FedNode) -> None:
    """W2.3 (e): with relay ON and a mix of pass/fail relayed facts spanning more
    than one page at a small limit, the cursor advances correctly, every page is
    full (no short page from post-filtering), and exactly the eligible facts come
    back across all pages. Proves the gate is IN SQL (LIMIT applies post-filter)."""
    _set_relay_enabled(True)

    # 12 relayed facts: even-indexed PASS (origin grants public+default), odd-indexed
    # FAIL (origin tenant excludes the peer's tenant). Interleaved so a post-filter
    # would produce short pages. HLCs strictly increasing for stable cursor order.
    expected_pass: set[str] = set()
    for i in range(12):
        passes = i % 2 == 0
        fid = _insert_inbound_fact(
            fed_node.db_path,
            entity=f"relay:page-{i}",
            scope="public",
            hlc=f"2{i:03d}.000",
            origin_allowed_scopes=["public"],
            origin_allowed_tenants=(["default"] if passes else ["acme"]),
        )
        if passes:
            expected_pass.add(fid)

    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )

    # Page through with a small limit. Each page (except possibly the last) must be
    # FULL — a short non-final page would mean Python post-filtering shrank it.
    collected: set[str] = set()
    cursor: str | None = None
    limit = 3
    for _ in range(20):  # generous page cap; loop breaks on has_more=False
        token = make_peer_token(priv, node_id, fed_node.node_id, ["public"])
        qs = f"limit={limit}" + (f"&cursor={cursor}" if cursor else "")
        r = fed_node.client.get(
            f"/v1/federation/facts?{qs}", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        page_ids = [e["fact"]["id"] for e in body["facts"]]
        collected.update(page_ids)
        if body["has_more"]:
            assert len(page_ids) == limit, "non-final page is short → filtering leaked to Python"
        cursor = body["cursor"]
        if not body["has_more"]:
            break

    assert collected == expected_pass
    # 6 eligible facts at limit 3 ⇒ no eligible fact lost, no ineligible fact slipped in.
    assert len(collected) == 6


def test_relay_off_egress_query_byte_identical_clause(fed_node: FedNode) -> None:
    """W2.3 guardrail: relay OFF must keep the egress query byte-identical to today.
    A self-originated fact still egresses (the relay branch must not perturb the
    non-relay path)."""
    _set_relay_enabled(False)
    r = fed_node.client.post(
        "/v1/facts",
        json={
            "entity": f"self:relayoff:{uuid.uuid4()}",
            "relation": "test:value",
            "value": {"type": "string", "v": "local"},
            "source": "agent:test",
            "scope": "public",
        },
    )
    assert r.status_code == 201
    self_id = r.json()["id"]
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["default"]
    )
    assert self_id in _pull_ids(fed_node, node_id, priv, ["public"])
    # sanity: confirm the row is genuinely self-originated (received_from IS NULL)
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT received_from FROM facts WHERE id = ?", (self_id,)
        ).fetchone()
    assert row["received_from"] is None
