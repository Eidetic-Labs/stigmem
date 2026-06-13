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

import stigmem_node.settings as _smod
from stigmem_node.db import db
from stigmem_node.federation.origin_signature import sign_origin
from stigmem_node.models.facts import FactRecord, FactValue

# ---------------------------------------------------------------------------
# W2.1 — settings flag
# ---------------------------------------------------------------------------


def test_federation_relay_enabled_defaults_false() -> None:
    """Settings().federation_relay_enabled must default to False (relay is OFF)."""
    assert _smod.Settings().federation_relay_enabled is False


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
        row = conn.execute("SELECT relay_trusted FROM peers WHERE id='rt1'").fetchone()
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
_ORIGIN_ENTITY_URI = "https://upstream-origin.example"
_OWN_ENTITY_URI = "https://relay-self.example"


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
    origin_entity_uri: str | None = _ORIGIN_ENTITY_URI,
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
        "origin_entity_uri": origin_entity_uri,
    }


def test_self_originated_emit_signs_fresh_with_own_identity() -> None:
    """Self-originated fact: emit a fresh OriginBlock for THIS node + a fresh sig."""
    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _self_record()
    row = _stored_origin_row(record, origin_sig=None, origin_node_id=None, origin_tenant=None)

    result = build_origin_entry(
        record,
        row,
        own_node_id=_OWN_NODE_ID,
        own_entity_uri=_OWN_ENTITY_URI,
        pull_tenant=_PULL_TENANT,
        priv=priv,
    )
    assert result is not None
    origin, sig, origin_manifest = result
    assert origin_manifest is None  # self-originated facts carry no relay manifest
    assert origin.node_id == _OWN_NODE_ID  # this node, not an upstream
    assert origin.tenant == _PULL_TENANT
    assert origin.allowed_tenants == [_PULL_TENANT]
    assert origin.entity_uri == _OWN_ENTITY_URI  # W3.1: this node's own entity_uri
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
        record,
        row,
        own_node_id=_OWN_NODE_ID,
        own_entity_uri=_OWN_ENTITY_URI,
        pull_tenant=_PULL_TENANT,
        priv=priv,
    )
    assert result is not None
    origin, sig, _origin_manifest = result
    # origin attribution is the UPSTREAM origin, NOT this relay node
    assert origin.node_id == _ORIGIN_NODE_ID
    assert origin.node_id != _OWN_NODE_ID
    assert origin.tenant == _ORIGIN_TENANT
    assert origin.allowed_scopes == ["public"]
    assert origin.allowed_tenants == ["acme"]
    # W3.1: forwarded entity_uri is the STORED upstream entity_uri, NOT this relay's
    assert origin.entity_uri == _ORIGIN_ENTITY_URI
    assert origin.entity_uri != _OWN_ENTITY_URI
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
            record,
            row,
            own_node_id=_OWN_NODE_ID,
            own_entity_uri=_OWN_ENTITY_URI,
            pull_tenant=_PULL_TENANT,
            priv=priv,
        )
    assert result is None
    assert any(record.id in r.getMessage() for r in caplog.records)


def test_relayed_emit_without_stored_entity_uri_is_skipped(caplog) -> None:  # type: ignore[no-untyped-def]
    """W3.1: a relayed fact missing its stored origin_entity_uri (pre-v2.1 origin) is
    SKIPPED (None) + warned — it cannot produce a v2.1 origin block and is not relayable."""
    import logging  # noqa: PLC0415

    from stigmem_node.routes.federation.replication import build_origin_entry  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    record = _relayed_record()
    row = _stored_origin_row(
        record,
        origin_sig="STORED-SIG",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
        origin_entity_uri=None,  # pre-v2.1: no stored entity_uri
    )

    with caplog.at_level(logging.WARNING):
        result = build_origin_entry(
            record,
            row,
            own_node_id=_OWN_NODE_ID,
            own_entity_uri=_OWN_ENTITY_URI,
            pull_tenant=_PULL_TENANT,
            priv=priv,
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
    _smod.settings.federation_relay_enabled = value


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
                origin_tenant, origin_allowed_tenants, origin_sig, cid,
                origin_entity_uri)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                _ORIGIN_ENTITY_URI,  # W3.1: stored origin entity_uri (forwarded at relay)
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
        row = conn.execute("SELECT received_from FROM facts WHERE id = ?", (self_id,)).fetchone()
    assert row["received_from"] is None


# ---------------------------------------------------------------------------
# LIKE-metacharacter egress hardening: the tenant-overlap LIKE must be EXACT.
# peer.allowed_tenants is operator-set free text (migration 041, no enum), so a
# tenant name containing a SQL LIKE wildcard (``_`` single-char / ``%`` any-run)
# must NOT false-match a DIFFERENT origin tenant. ``a_me`` must not match origin
# grant ``["acme"]``; ``a%`` must not match anything but a literal ``a%``.
# ---------------------------------------------------------------------------


def test_relay_on_tenant_underscore_does_not_wildcard_match(fed_node: FedNode) -> None:
    """A peer whose allowed_tenants is ``["a_me"]`` (underscore = LIKE single-char wildcard)
    must NOT receive a relayed fact whose origin_allowed_tenants is ``["acme"]`` — the ``_``
    must be escaped so it matches only a literal underscore, not the ``c`` in ``acme``."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:tenant-underscore",
        scope="public",
        hlc="300.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],  # the ONLY origin-granted tenant
    )
    # peer tenant ``a_me`` would LIKE-match ``"acme"`` if ``_`` is left unescaped.
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"], pull_tenant="default"
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_tenant_percent_does_not_wildcard_match(fed_node: FedNode) -> None:
    """A peer whose allowed_tenants is ``["a%"]`` (percent = LIKE any-run wildcard) must NOT
    receive a relayed fact whose origin_allowed_tenants is ``["acme"]`` — ``%`` must be escaped
    so it matches only a literal percent sign, not ``cme``."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:tenant-percent",
        scope="public",
        hlc="301.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["acme"],
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a%"], pull_tenant="default"
    )
    assert fid not in _pull_ids(fed_node, node_id, priv, ["public"])


def test_relay_on_tenant_exact_metachar_match_still_egresses(fed_node: FedNode) -> None:
    """Positive control: a peer whose allowed_tenants is the LITERAL ``["a_me"]`` DOES receive
    a relayed fact whose origin_allowed_tenants is the literal ``["a_me"]`` — escaping the
    wildcard must not break a legitimate exact match on a metacharacter-bearing tenant name."""
    _set_relay_enabled(True)
    fid = _insert_inbound_fact(
        fed_node.db_path,
        entity="relay:tenant-exact-metachar",
        scope="public",
        hlc="302.000",
        origin_allowed_scopes=["public"],
        origin_allowed_tenants=["a_me"],  # the origin literally granted the ``a_me`` tenant
        tenant_id="a_me",
    )
    node_id, priv = _register_pull_peer(
        fed_node, allowed_scopes=["public"], allowed_tenants=["a_me"], pull_tenant="a_me"
    )
    assert fid in _pull_ids(fed_node, node_id, priv, ["public"])


# ---------------------------------------------------------------------------
# W3.2 — resolve_origin_key_for_relay: fetch-on-first relayed-origin resolution
# (entity-authority uniqueness, https-only fetch, threaded pubkey cache, first-
# contact audit) + relay-trusted-gated ingest with origin scope/tenant gating.
# ---------------------------------------------------------------------------

import base64 as _b64  # noqa: E402

from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

from stigmem_node.identity.key_rotation import generate_key_id  # noqa: E402
from stigmem_node.identity.manifest import (  # noqa: E402
    OrgManifest,
    manifest_to_dict,
    sign_manifest,
)


def _pub_b64(priv: Ed25519PrivateKey) -> str:
    return (
        _b64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )


def _build_manifest(
    priv: Ed25519PrivateKey, *, entity_uri: str, entities: list[str]
) -> OrgManifest:
    """A self-signed, currently-valid OrgManifest whose public_key == priv's pubkey."""
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=_pub_b64(priv),
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=entities,
    )
    sign_manifest(m, priv)
    return m


class _FetchStub:
    """Stub for ``origin_identity.httpx.get`` that serves a manifest at the well-known
    path and counts calls (to prove the per-page cache dedups fetches)."""

    def __init__(self, manifest: OrgManifest | None) -> None:
        self._json = manifest_to_dict(manifest) if manifest is not None else None
        self.calls = 0

    def __call__(self, url, *a, **k):  # type: ignore[no-untyped-def]
        import httpx as _httpx  # noqa: PLC0415

        self.calls += 1
        if self._json is None or not url.endswith("/.well-known/stigmem-manifest.json"):
            return _httpx.Response(404)
        return _httpx.Response(200, json=self._json)


def _neutralize_ssrf_dns(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """No-op the anti-rebind DNS pin in the relay-manifest fetch so a non-resolvable
    .example host can be fetched. The pin (``resolve_pinned_address``) would otherwise
    DNS-resolve the .example host and fail; the HTTPS-only scheme guard is exercised
    separately. The httpx.get stub returns the manifest against the (ignored) pinned URL."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "resolve_pinned_address", lambda url, **k: "203.0.113.7")


_RELAY_ENTITY = "https://relay-origin.example"
_RELAY_NODE = "stigmem:node:relay-origin"


def test_relay_resolve_returns_keyset_for_nonpeer_origin(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (a): a NON-peer origin whose manifest is fetchable from entity_uri and lists
    node_id in entities resolves to the verified key set (fetch-on-first)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    stub = _FetchStub(manifest)
    monkeypatch.setattr(oi.httpx, "get", stub)
    _neutralize_ssrf_dns(monkeypatch)

    keys = oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
    assert _pub_b64(priv) in keys
    assert stub.calls == 1


def test_relay_resolve_fails_closed_when_node_not_in_entities(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (b): FAIL-CLOSED when node_id is NOT listed in the fetched manifest.entities."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    # Manifest does NOT list _RELAY_NODE among its entities.
    manifest = _build_manifest(priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY])
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    try:
        oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
        raise AssertionError("expected OriginIdentityError")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass


def test_relay_resolve_rejects_entity_authority_substitution(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (c) ENTITY-AUTHORITY: a manifest from entity_uri=X claiming a node_id ALREADY
    bound to a DIFFERENT entity_uri is REJECTED (anti-substitution)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415
    from stigmem_node.identity.trust_store import store_peer_manifest  # noqa: PLC0415

    # Pre-existing binding: _RELAY_NODE belongs to the LEGITIMATE entity (stored manifest
    # lists the node in its entities).
    legit_priv = Ed25519PrivateKey.generate()
    legit_uri = "https://legit-owner.example"
    legit_manifest = _build_manifest(
        legit_priv, entity_uri=legit_uri, entities=[legit_uri, _RELAY_NODE]
    )
    store_peer_manifest(legit_uri, legit_manifest, None, trust_mode="relaxed")

    # Hostile org X serves its own valid manifest also claiming _RELAY_NODE.
    hostile_priv = Ed25519PrivateKey.generate()
    hostile_manifest = _build_manifest(
        hostile_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    stub = _FetchStub(hostile_manifest)
    monkeypatch.setattr(oi.httpx, "get", stub)
    _neutralize_ssrf_dns(monkeypatch)

    try:
        oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
        raise AssertionError("expected OriginIdentityError (entity-authority substitution)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
    # The uniqueness check fires BEFORE the fetch — the hostile manifest is never pulled.
    assert stub.calls == 0


def test_relay_resolve_cache_dedups_within_request_and_refetches_fresh(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (d) CACHE: two resolves with the same (entity_uri,key_id) in ONE cache do ONE
    fetch; a FRESH cache (new request) re-fetches (proves it's threaded-local, not global)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    stub = _FetchStub(manifest)
    monkeypatch.setattr(oi.httpx, "get", stub)
    _neutralize_ssrf_dns(monkeypatch)

    cache: dict[str, set[str]] = {}
    oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache=cache)
    oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache=cache)
    assert stub.calls == 1  # second resolve served from the threaded cache

    # A new request threads a FRESH cache → re-fetch (no module-global persisting state).
    oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
    assert stub.calls == 2


def test_relay_resolve_https_only_rejects_http_nonloopback(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (e) HTTPS-ONLY: a relay-origin entity_uri with http scheme (non-loopback) is
    rejected by the anti-rebind pin (resolve_pinned_address, https-only)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    # federation_insecure OFF (production) so the loopback-dev skip cannot apply.
    monkeypatch.setattr(_smod.settings, "federation_insecure", False)
    priv = Ed25519PrivateKey.generate()
    http_uri = "http://relay-origin.example"  # non-loopback http
    manifest = _build_manifest(priv, entity_uri=http_uri, entities=[http_uri, _RELAY_NODE])
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))

    try:
        oi.resolve_origin_key_for_relay(_RELAY_NODE, http_uri, cache={})
        raise AssertionError("expected OriginIdentityError (http rejected)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass


def test_relay_resolve_emits_first_contact_audit(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (f) FIRST-CONTACT AUDIT: binding a new (node_id, entity_uri) via relay emits a
    relay_origin_first_contact audit event."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    seen: list[tuple[str, dict]] = []

    def _spy_emit_nofail(event_type, **kw):  # type: ignore[no-untyped-def]
        seen.append((event_type, kw))

    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", _spy_emit_nofail)

    priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
    events = [e for e, _ in seen]
    assert "relay_origin_first_contact" in events
    detail = next(kw for e, kw in seen if e == "relay_origin_first_contact")
    assert detail["detail"]["node_id"] == _RELAY_NODE
    assert detail["detail"]["entity_uri"] == _RELAY_ENTITY


# ---- W3.2 ingest gating (push endpoint, end-to-end) -----------------------


def _b64_pub(priv: Ed25519PrivateKey) -> str:
    return _pub_b64(priv)


def _make_sender_peer(db_path: str, *, node_id: str, pub_b64: str, relay_trusted: int) -> None:
    """Insert an active sender peer with explicit relay_trusted + tenant map allowing 'acme'."""
    import sqlite3  # noqa: PLC0415

    peer_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes, status,
                declaration_sig, signed_at, ingest_tenant, relay_trusted)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                node_id,
                "https://sender.example",
                pub_b64,
                json.dumps(["public"]),
                "active",
                "SIG",
                "2026-01-01T00:00:00Z",
                "default",  # ingest_tenant pin so the origin tenant 'default' resolves
                relay_trusted,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _relayed_push_body(
    sender_priv: Ed25519PrivateKey,
    origin_priv: Ed25519PrivateKey,
    *,
    scope: str,
    origin_allowed_scopes: list[str],
) -> dict[str, Any]:
    """A v2 push envelope where origin.node_id != sender (a RELAYED fact), signed by the
    ORIGIN key (the fact must verify against the fetched origin manifest)."""
    from .helpers import make_v2_envelope  # noqa: PLC0415

    fact = {
        "id": str(uuid.uuid4()),
        "entity": "stigmem://t/relayed",
        "relation": "r",
        "value": {"type": "string", "v": "x"},
        "source": _RELAY_NODE,
        "scope": scope,
        "timestamp": "2026-06-01T00:00:00Z",
        "confidence": 1.0,
        "valid_until": None,
    }
    origin = {
        "tenant": "default",
        "node_id": _RELAY_NODE,
        "allowed_scopes": origin_allowed_scopes,
        "allowed_tenants": ["default"],
        "entity_uri": _RELAY_ENTITY,
    }
    return make_v2_envelope(origin_priv, facts=[fact], origin=origin)


def _push(fed_node: FedNode, sender_node_id: str, sender_priv: str, body: dict[str, Any]):  # type: ignore[no-untyped-def]
    token = make_peer_token(sender_priv, sender_node_id, fed_node.node_id, ["public"])
    return fed_node.client.post(
        "/v1/federation/facts/push",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )


def test_relay_ingest_trusted_sender_verifying_origin_is_ingested(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (g): relay ON + relay_trusted sender + verifying relayed origin → INGESTED."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender"
    sender_priv_obj = Ed25519PrivateKey.from_private_bytes(
        _b64.urlsafe_b64decode(sender_priv + "=" * (-len(sender_priv) % 4))
    )
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=1)

    body = _relayed_push_body(
        sender_priv_obj, origin_priv, scope="public", origin_allowed_scopes=["public"]
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1, r.json()


def test_relay_ingest_untrusted_sender_is_rejected(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (g): relay ON but sender NOT relay_trusted → relayed fact REJECTED (fail-closed)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender-untrusted"
    sender_priv_obj = Ed25519PrivateKey.from_private_bytes(
        _b64.urlsafe_b64decode(sender_priv + "=" * (-len(sender_priv) % 4))
    )
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=0)

    body = _relayed_push_body(
        sender_priv_obj, origin_priv, scope="public", origin_allowed_scopes=["public"]
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 0
    assert any(e["error"] == "relay_sender_not_trusted" for e in r.json()["errors"]), r.json()


def test_relay_ingest_scope_outside_origin_grant_is_rejected(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (g) INGEST SCOPE GATE: a relayed fact whose scope ∉ origin_allowed_scopes is
    REJECTED even from a relay_trusted sender."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender-scopegate"
    sender_priv_obj = Ed25519PrivateKey.from_private_bytes(
        _b64.urlsafe_b64decode(sender_priv + "=" * (-len(sender_priv) % 4))
    )
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=1)

    # fact.scope = 'public' but the origin only granted 'team' → must be rejected on ingest.
    body = _relayed_push_body(
        sender_priv_obj, origin_priv, scope="public", origin_allowed_scopes=["team"]
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 0
    assert any(e["error"] == "scope_not_in_origin_grant" for e in r.json()["errors"]), r.json()


def test_relay_off_origin_not_sender_rejected_unchanged_2b(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W3.2 (g) regression: with relay OFF, an origin≠sender fact is REJECTED with the
    unchanged 2b error origin_not_sender (byte-identical direct path)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", False)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender-off"
    sender_priv_obj = Ed25519PrivateKey.from_private_bytes(
        _b64.urlsafe_b64decode(sender_priv + "=" * (-len(sender_priv) % 4))
    )
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=1)

    body = _relayed_push_body(
        sender_priv_obj, origin_priv, scope="public", origin_allowed_scopes=["public"]
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    # Relay OFF ⇒ the relay relaxation never engages: the fact (source=origin≠sender) is
    # rejected fail-closed by the unchanged 2b source-non-forgery rule (source_not_owned),
    # NEVER ingested. This proves the relay-OFF path stays byte-identical to 2b.
    assert r.json()["accepted"] == 0
    assert any(e["error"] == "source_not_owned" for e in r.json()["errors"]), r.json()


# ---------------------------------------------------------------------------
# W4.2 — OFFLINE relay trust: operator-pin (tier 1) + stored-binding (tier 2) +
# fetch-on-first TOFU (tier 3), with cross-check + fail-closed. Zero transitive
# trust — a relayed origin's key is accepted ONLY against a first-party/human
# anchor; a stronger reachable anchor that disagrees is an ATTACK (reject+audit).
#
# resolve_origin_key_for_relay gains an OPTIONAL ``origin_manifest`` (the carried,
# self-verifying manifest body the relay attaches for relayed facts) so an
# UNREACHABLE receiver has a candidate to match against its pin/stored binding.
# ---------------------------------------------------------------------------

from stigmem_node.federation.origin_pins import (  # noqa: E402
    fingerprint_from_pubkey,
    put_origin_pin,
)


def _put_pin(*, entity_uri: str, node_id: str, key_fingerprint: str) -> None:
    """Operator-pin an (entity_uri, node_id) → key_fingerprint triple (W4.1 store)."""
    with db() as conn:
        put_origin_pin(
            conn,
            entity_uri=entity_uri,
            node_id=node_id,
            key_fingerprint=key_fingerprint,
            pinned_by="operator:test",
        )
        conn.commit()


def _store_binding(priv: Ed25519PrivateKey, *, entity_uri: str, node_id: str) -> None:
    """Store a first-party manifest binding (entity_uri ↔ key) via the trust store."""
    from stigmem_node.identity.trust_store import store_peer_manifest  # noqa: PLC0415

    manifest = _build_manifest(priv, entity_uri=entity_uri, entities=[entity_uri, node_id])
    store_peer_manifest(entity_uri, manifest, None, trust_mode="relaxed")


def _spy_audit(monkeypatch) -> list[tuple[str, dict]]:  # type: ignore[no-untyped-def]
    """Capture audit_event.emit_nofail calls; returns the (event_type, kwargs) list."""
    seen: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: seen.append((et, kw)))
    return seen


def test_relay_offline_tier1_pin_match_unreachable_accepts(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (a) TIER-1 PIN MATCH: origin UNREACHABLE, an operator pin matches the carried
    manifest's key → ACCEPTED (offline trust via the human anchor)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    carried = _build_manifest(priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE])
    # Origin UNREACHABLE: the fetch stub serves nothing (404 / None).
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))
    _neutralize_ssrf_dns(monkeypatch)
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(priv)),
    )

    keys = oi.resolve_origin_key_for_relay(
        _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
    )
    assert _pub_b64(priv) in keys


def test_relay_offline_tier1_pin_mismatch_rejects(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (b) TIER-1 PIN MISMATCH: the carried manifest's key ≠ the operator pin →
    REJECTED + ``relay_origin_pin_mismatch`` audit; the carried key is NOT trusted."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    pinned_priv = Ed25519PrivateKey.generate()
    impostor_priv = Ed25519PrivateKey.generate()
    carried = _build_manifest(
        impostor_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # unreachable
    _neutralize_ssrf_dns(monkeypatch)
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(pinned_priv)),
    )
    seen = _spy_audit(monkeypatch)

    try:
        oi.resolve_origin_key_for_relay(
            _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
        )
        raise AssertionError("expected OriginIdentityError (pin mismatch)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
    assert "relay_origin_pin_mismatch" in [e for e, _ in seen]


def test_relay_offline_tier1_fetch_disagrees_pin_rejects(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (c) TIER-1 CROSS-CHECK: a pin exists AND the origin is REACHABLE but the FETCHED
    key ≠ the pin → REJECTED + ``relay_origin_fetch_disagrees_pin`` (a reachable fetch that
    disagrees with the human anchor is a MITM/compromise signal)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    pinned_priv = Ed25519PrivateKey.generate()
    served_priv = Ed25519PrivateKey.generate()  # the live endpoint serves a DIFFERENT key
    served = _build_manifest(
        served_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(served))  # REACHABLE
    _neutralize_ssrf_dns(monkeypatch)
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(pinned_priv)),
    )
    seen = _spy_audit(monkeypatch)

    # The carried manifest happens to match the pin, but the live fetch disagrees: ATTACK.
    carried = _build_manifest(
        pinned_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    try:
        oi.resolve_origin_key_for_relay(
            _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
        )
        raise AssertionError("expected OriginIdentityError (fetch disagrees pin)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
    assert "relay_origin_fetch_disagrees_pin" in [e for e, _ in seen]


def test_relay_offline_tier2_stored_binding_match_unreachable_accepts(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (d) TIER-2 STORED BINDING: no pin, but a stored manifest for entity_uri with the
    SAME key exists and the origin is UNREACHABLE → ACCEPTED against the stored binding."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    _store_binding(priv, entity_uri=_RELAY_ENTITY, node_id=_RELAY_NODE)
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # unreachable
    _neutralize_ssrf_dns(monkeypatch)

    carried = _build_manifest(priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE])
    keys = oi.resolve_origin_key_for_relay(
        _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
    )
    assert _pub_b64(priv) in keys


def test_relay_offline_tier2_stored_binding_mismatch_rejects(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (e) TIER-2 MISMATCH: the carried key ≠ the stored binding's key (a key change for
    a known origin) → REJECTED + ``relay_origin_key_changed`` (never a silent update)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    stored_priv = Ed25519PrivateKey.generate()
    changed_priv = Ed25519PrivateKey.generate()
    _store_binding(stored_priv, entity_uri=_RELAY_ENTITY, node_id=_RELAY_NODE)
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # unreachable
    _neutralize_ssrf_dns(monkeypatch)
    seen = _spy_audit(monkeypatch)

    carried = _build_manifest(
        changed_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    try:
        oi.resolve_origin_key_for_relay(
            _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
        )
        raise AssertionError("expected OriginIdentityError (stored binding key changed)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
    assert "relay_origin_key_changed" in [e for e, _ in seen]


def test_relay_offline_tier3_tofu_unchanged(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (f) TIER-3 TOFU UNCHANGED: no pin, no stored binding, REACHABLE, never-seen →
    fetch-on-first ACCEPTS + stores + emits first-contact (the existing W3.2 behaviour)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415
    from stigmem_node.identity.trust_store import get_peer_manifest  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    manifest = _build_manifest(
        priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))  # REACHABLE
    _neutralize_ssrf_dns(monkeypatch)
    seen = _spy_audit(monkeypatch)

    keys = oi.resolve_origin_key_for_relay(_RELAY_NODE, _RELAY_ENTITY, cache={})
    assert _pub_b64(priv) in keys
    # tier-3 stores the manifest + emits the first-contact audit (regression guard).
    assert get_peer_manifest(_RELAY_ENTITY, trust_mode="relaxed") is not None
    assert "relay_origin_first_contact" in [e for e, _ in seen]


def test_relay_offline_fail_closed_unanchored_rejects(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (g) FAIL-CLOSED: no pin, no stored binding, UNREACHABLE (the unknown-AND-
    unreachable case) → REJECTED + ``relay_origin_unanchored``."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    carried = _build_manifest(priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE])
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # unreachable
    _neutralize_ssrf_dns(monkeypatch)
    seen = _spy_audit(monkeypatch)

    try:
        oi.resolve_origin_key_for_relay(
            _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
        )
        raise AssertionError("expected OriginIdentityError (unanchored, unreachable)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
    assert "relay_origin_unanchored" in [e for e, _ in seen]


def test_relay_offline_candidate_must_self_verify_even_with_pin(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 (h) CANDIDATE GATING: a carried manifest that FAILS the W3.2 checks (here:
    node_id ∉ entities) is REJECTED even when a matching pin exists — the candidate must
    pass self-verify + node_id ∈ entities + entity-authority BEFORE any anchor acceptance."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    # Carried manifest does NOT list _RELAY_NODE among its entities → must be rejected.
    carried = _build_manifest(priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY])
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # unreachable
    _neutralize_ssrf_dns(monkeypatch)
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(priv)),  # pin matches the key
    )

    try:
        oi.resolve_origin_key_for_relay(
            _RELAY_NODE, _RELAY_ENTITY, cache={}, origin_manifest=manifest_to_dict(carried)
        )
        raise AssertionError("expected OriginIdentityError (candidate fails node∈entities)")
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass


# ---- W4.2 end-to-end ingest: unreachable origin, pinned vs unpinned ----------


def _relayed_push_body_with_manifest(
    origin_priv: Ed25519PrivateKey,
    *,
    scope: str,
    origin_allowed_scopes: list[str],
    origin_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    """A v2 push envelope (origin.node_id != sender) carrying an OPTIONAL origin_manifest
    body on each entry, so an unreachable receiver has a candidate to anchor-match."""
    from .helpers import make_v2_entry  # noqa: PLC0415

    fact = {
        "id": str(uuid.uuid4()),
        "entity": "stigmem://t/relayed-offline",
        "relation": "r",
        "value": {"type": "string", "v": "x"},
        "source": _RELAY_NODE,
        "scope": scope,
        "timestamp": "2026-06-01T00:00:00Z",
        "confidence": 1.0,
        "valid_until": None,
    }
    origin = {
        "tenant": "default",
        "node_id": _RELAY_NODE,
        "allowed_scopes": origin_allowed_scopes,
        "allowed_tenants": ["default"],
        "entity_uri": _RELAY_ENTITY,
    }
    entry = make_v2_entry(origin_priv, fact=fact, origin=origin)
    if origin_manifest is not None:
        entry["origin_manifest"] = origin_manifest
    return {"v": 2, "facts": [entry], "cursor": None, "has_more": False}


def test_relay_ingest_unreachable_pinned_origin_is_ingested(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 e2e (pinned): a relayed fact from a relay_trusted sender whose UNREACHABLE origin
    is operator-pinned (and carries a matching manifest) is INGESTED."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    carried = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # origin UNREACHABLE
    _neutralize_ssrf_dns(monkeypatch)
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(origin_priv)),
    )

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender-pinned"
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=1)

    body = _relayed_push_body_with_manifest(
        origin_priv,
        scope="public",
        origin_allowed_scopes=["public"],
        origin_manifest=manifest_to_dict(carried),
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 1, r.json()


def test_relay_ingest_unreachable_unpinned_origin_is_rejected(fed_node, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """W4.2 e2e (unpinned): the same relayed fact with NO pin + UNREACHABLE origin (and no
    stored binding) is REJECTED fail-closed (origin_unresolvable)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(_smod.settings, "federation_relay_enabled", True)
    monkeypatch.setattr(_smod.settings, "federation_push_enabled", True)

    origin_priv = Ed25519PrivateKey.generate()
    carried = _build_manifest(
        origin_priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(None))  # origin UNREACHABLE
    _neutralize_ssrf_dns(monkeypatch)

    sender_pub, sender_priv = generate_ed25519_b64()
    sender_node = "stigmem:node:relay-sender-unpinned"
    _make_sender_peer(fed_node.db_path, node_id=sender_node, pub_b64=sender_pub, relay_trusted=1)

    body = _relayed_push_body_with_manifest(
        origin_priv,
        scope="public",
        origin_allowed_scopes=["public"],
        origin_manifest=manifest_to_dict(carried),
    )
    r = _push(fed_node, sender_node, sender_priv, body)
    assert r.status_code == 202, r.text
    assert r.json()["accepted"] == 0
    assert any(e["error"] == "origin_unresolvable" for e in r.json()["errors"]), r.json()


# ---------------------------------------------------------------------------
# CACHE-COLLISION BYPASS (BLOCKER): the per-page relay resolver cache MUST be
# keyed on the (entity_uri, node_id) PAIR, not entity_uri alone. Every check
# after the cache short-circuit (entity-authority/uniqueness, node_id ∈ entities,
# operator-pin lookup) is node_id-scoped — so a cache keyed on entity_uri alone
# lets a SECOND node_id carried with the same entity_uri (within one page) inherit
# the first node_id's resolved key set WITHOUT those node_id checks running.
# ---------------------------------------------------------------------------

_RELAY_NODE_A = "stigmem:node:relay-shared-a"
_RELAY_NODE_B = "stigmem:node:relay-shared-b"


def test_relay_resolve_cache_node_scoped_entity_authority(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """BLOCKER (entity-authority): two node_ids carried with the SAME entity_uri through one
    shared cache. node_a IS in entities (resolves, primes the cache); node_b is NOT in
    entities. With a cache keyed on entity_uri alone, node_b hits the short-circuit and
    wrongly resolves. With the (entity_uri, node_id) key it MISSES the cache and is rejected
    by the node_id ∈ entities check → MUST raise OriginIdentityError."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    priv = Ed25519PrivateKey.generate()
    # Manifest lists ONLY node_a among its entities (node_b is NOT authorized).
    manifest = _build_manifest(
        priv, entity_uri=_RELAY_ENTITY, entities=[_RELAY_ENTITY, _RELAY_NODE_A]
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    cache: dict = {}
    # node_a resolves OK and primes the cache for _RELAY_ENTITY.
    keys_a = oi.resolve_origin_key_for_relay(_RELAY_NODE_A, _RELAY_ENTITY, cache=cache)
    assert _pub_b64(priv) in keys_a

    # node_b shares the entity_uri + cache but is NOT in entities → MUST be rejected,
    # not served the cached key set via an entity_uri-only collision.
    try:
        oi.resolve_origin_key_for_relay(_RELAY_NODE_B, _RELAY_ENTITY, cache=cache)
        raise AssertionError(
            "cache collision: node_b (∉ entities) inherited node_a's cached key set"
        )
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass


def test_relay_resolve_cache_node_scoped_per_node_pin(client, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """BLOCKER (per-node pin): both node_a and node_b are listed in the entity's manifest,
    but the operator has pinned (entity_uri, node_b) to a DIFFERENT key than the manifest's.
    node_a resolves first (primes the cache). node_b shares the entity_uri + cache. With an
    entity_uri-only cache, node_b's tier-1 pin is NEVER consulted and node_b inherits the
    manifest key. With the (entity_uri, node_id) key, node_b's pin IS consulted → the
    manifest key ≠ the pin → REJECT (pin mismatch). The pinned key MUST NOT be bypassed."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    manifest_priv = Ed25519PrivateKey.generate()
    pinned_priv = Ed25519PrivateKey.generate()  # node_b's operator-pinned key (different)
    # Manifest lists BOTH nodes and is served by the (reachable) origin.
    manifest = _build_manifest(
        manifest_priv,
        entity_uri=_RELAY_ENTITY,
        entities=[_RELAY_ENTITY, _RELAY_NODE_A, _RELAY_NODE_B],
    )
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)

    # Operator pins (entity, node_b) to a DIFFERENT key than the manifest serves.
    _put_pin(
        entity_uri=_RELAY_ENTITY,
        node_id=_RELAY_NODE_B,
        key_fingerprint=fingerprint_from_pubkey(_pub_b64(pinned_priv)),
    )

    cache: dict = {}
    # node_a has no pin → resolves via TOFU/fetch and primes the cache for _RELAY_ENTITY.
    keys_a = oi.resolve_origin_key_for_relay(_RELAY_NODE_A, _RELAY_ENTITY, cache=cache)
    assert _pub_b64(manifest_priv) in keys_a

    # node_b shares the entity_uri + cache: its per-node pin MUST be consulted. The manifest
    # key disagrees with the pin → MUST be rejected (NOT served the manifest key via cache).
    try:
        oi.resolve_origin_key_for_relay(_RELAY_NODE_B, _RELAY_ENTITY, cache=cache)
        raise AssertionError(
            "cache collision: node_b's per-node operator pin was bypassed via the shared cache"
        )
    except oi.OriginIdentityError:
        # Expected: the resolver rejected this case (the AssertionError above did not fire).
        pass
