"""Phase 2c W7.2 — multi-node FACT relay PROOF (the W2/W3/W4 capstone).

The fact analogue of the W6.9 tombstone relay proof
(``test_tombstone_relay_4node_2c.py``). It proves that a FACT originated +
origin-signed by node **A** travels A → B → C and is verified at C against
**A's** key (the origin attestation survives the relay hop — it is NOT
re-signed by the relay B), the fact lands attributed to A, and the critical
fail-closed / containment / scope-tenant / anti-tamper properties hold so a
relay can neither forge, re-scope, leak across tenants, nor smuggle a tampered
fact.

Topology (three distinct federation identities):
  * **A** — the ORIGIN that asserted + origin-signed the fact. NOT a peer of C, so
    C must resolve A's key the relay way (fetch-on-first / operator pin), never the
    2a direct-peer chain.
  * **B** — the RELAY. ``fed_node`` plays B: A's fact is seeded into B's DB as an
    INBOUND/relayed row (A's verbatim origin block + A's real v2.1 origin_sig,
    ``received_from = A``), exactly as B would have stored it after pulling from A
    directly (W2.2/W3.2). B re-serves it through its REAL pull GET endpoint
    (``/v1/federation/facts``), exercising the W2.3 egress relay gate +
    ``build_origin_entry`` verbatim-forward.
  * **C** — the DOWNSTREAM node under test. C drives the REAL
    ``pull_from_peer_once`` against B's live GET (via a thin adapter wrapping B's
    ``TestClient``), running the full W3.2/W4.2 secure relay-ingest chain:
    relay-trusted gate → resolve A's key (relay resolver) → verify A's origin sig →
    scope/tenant gate → ingest with A's origin block + ``received_from = B``.

Because the suite runs in-process on ONE physical DB, B and C share storage. To make
the B→C hop a genuine relay-ingest (not a no-op re-read of the seed row), the seed row
is DELETED after B's GET captures the wire body and BEFORE C ingests — so the row C
ends up with is the one its OWN secure chain wrote (origin A, received_from B). The
wire body + the A-key verification are real; only the transport is in-process. This is
the same "clear-then-pull" technique the tombstone proof uses.

Tests:
  (a) HAPPY PATH (reachable origin): A reachable via fetch-on-first → C verifies A's
      origin sig against A's FETCHED key → INGESTED. C's row has ``origin_node_id == A``
      and ``received_from == B``; the fact is recallable at C.
  (b) HAPPY PATH (unreachable origin + pin): A UNREACHABLE, C has an operator PIN for
      A's key → C accepts via the pin (tier-1) → INGESTED, attributed to A.
  (c) RELAY-OFF CONTAINMENT: ``federation_relay_enabled=False`` at C → C DROPS B's
      relayed fact (origin_not_sender); fact NOT at C.
  (d) UNANCHORED FAIL-CLOSED: C has NO pin, A UNREACHABLE, B relay_trusted → the relay
      resolver raises → C does NOT ingest.
  (e) SCOPE/TENANT PROPAGATION: a relayed fact whose origin grant excludes C's
      tenant/scope is NOT delivered to C (blocked at B's egress and/or C's ingest); a
      sibling within-grant IS delivered.
  (f) ANTI-TAMPER: B alters the fact body on the wire → A's origin sig no longer
      verifies → C DROPS it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import time
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.cid import compute_cid
from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.federation_ingest import _encode_v
from stigmem_node.federation.origin_pins import fingerprint_from_pubkey, put_origin_pin
from stigmem_node.federation.origin_signature import sign_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest
from stigmem_node.identity.trust_store import store_peer_manifest

from .helpers import generate_ed25519_b64

_TENANT = "default"


# ---------------------------------------------------------------------------
# Identity + crypto helpers
# ---------------------------------------------------------------------------


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


class _Node:
    """A federation identity used as origin A or downstream C in the proof."""

    def __init__(self, label: str) -> None:
        self.pub_b64, self.priv_b64 = generate_ed25519_b64()
        self.priv = _priv_from_b64(self.priv_b64)
        self.node_id = f"stigmem://{label}-{uuid.uuid4()}"
        self.entity_uri = f"https://{label}-{uuid.uuid4()}.example"
        self.key_id = generate_key_id(self.priv.public_key())

    def manifest(self) -> OrgManifest:
        """A self-signed, currently-valid manifest binding entity_uri ↔ key ↔ node_id."""
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


def _origin_block(
    node: _Node, *, allowed_scopes: list[str], allowed_tenants: list[str] | None = None
) -> dict[str, Any]:
    return {
        "tenant": _TENANT,
        "node_id": node.node_id,
        "allowed_scopes": allowed_scopes,
        "allowed_tenants": allowed_tenants if allowed_tenants is not None else [_TENANT],
        "entity_uri": node.entity_uri,
    }


def _fact_cid(fact: dict[str, Any]) -> str:
    """Compute the CID exactly as ``_verify_inbound_cid`` recomputes it at C."""
    value = fact["value"]
    return compute_cid(
        entity=fact["entity"],
        relation=fact["relation"],
        value_type=value["type"],
        value_v=_encode_v(value),
        source=fact["source"],
        scope=fact["scope"],
        confidence=float(fact.get("confidence", 1.0)),
        interpret_as=str(value.get("interpret_as", "content")),
    )


def _build_fact(a: _Node, *, entity: str, scope: str, hlc_offset_ms: int = 0) -> dict[str, Any]:
    """A fact ASSERTED by origin A (source == A.node_id), with its CID computed.

    The HLC is anchored to the current wall clock (+ ``hlc_offset_ms`` for stable ordering
    across sibling facts) so C's ingest HLC-skew bound (``node_hlc.receive``) accepts it."""
    hlc = f"{int(time.time() * 1000) + hlc_offset_ms}.000"
    fact: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "entity": entity,
        "relation": "relay4:value",
        "value": {"type": "string", "v": "from-origin-a"},
        "source": a.node_id,
        "timestamp": "2026-06-10T00:00:00Z",
        "hlc": hlc,
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }
    fact["cid"] = _fact_cid(fact)
    return fact


def _origin_sig(a: _Node, fact: dict[str, Any], origin: dict[str, Any], *,
                sign_cid: str | None = None) -> str:
    """A's origin-attestation signature over the v2.1 fact tuple.

    ``sign_cid`` lets the anti-tamper case (f) sign over the ORIGINAL cid while the wire
    fact body is mutated, so a relay that alters the body invalidates the signature."""
    return sign_origin(
        a.priv,
        fact_id=fact["id"],
        cid=sign_cid if sign_cid is not None else fact["cid"],
        origin=origin,
        valid_until=fact.get("valid_until"),
    )


# ---------------------------------------------------------------------------
# B-side DB seeding: store A's fact on B as an INBOUND/relayed row, exactly as B
# would have stored it after pulling DIRECTLY from A (W2.2/W3.2). B will then
# re-serve it from its real pull GET endpoint under the W2.3 egress relay gate.
# ---------------------------------------------------------------------------


def _seed_relayed_fact_on_b(
    db_path: str,
    *,
    fact: dict[str, Any],
    origin: dict[str, Any],
    origin_sig: str,
    received_from: str,
) -> None:
    """Insert A's fact into B's DB with A's verbatim origin block + ``received_from=A``.

    Mirrors the columns ``ingest_fact`` writes on B after a direct pull from A; the
    origin_* JSON uses the canonical ``json.dumps(sorted([...]))`` encoding the W2.3
    egress LIKE-membership gate matches.
    """
    value = fact["value"]
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
                fact["id"],
                fact["entity"],
                fact["relation"],
                value["type"],
                _encode_v(value),
                fact["source"],
                fact["timestamp"],
                float(fact.get("confidence", 1.0)),
                fact["scope"],
                fact["hlc"],
                _TENANT,
                received_from,  # received_from non-NULL => relayed
                origin["node_id"],
                json.dumps(sorted(origin["allowed_scopes"])),
                0,
                origin["tenant"],
                json.dumps(sorted(origin["allowed_tenants"])),
                origin_sig,
                fact["cid"],
                origin["entity_uri"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _register_relay_peer_on_b(
    db_path: str, peer_node_id: str, peer_pub_b64: str, *, allowed_tenants: list[str]
) -> None:
    """Register C as an active pull peer on B so C's pull GET token is accepted + scoped."""
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
                json.dumps(["public", "team", "*"]),
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


def _delete_fact(db_path: str, fact_id: str) -> None:
    """Clear B's seed row so C's relay-ingest writes its OWN row instead of no-op re-reading.

    The ``facts`` table is append-only (a ``facts_no_delete`` trigger RAISEs on DELETE). This
    is a TEST-HARNESS clear of the in-process seed only — the ephemeral per-test DB makes the
    "clear-then-pull" technique (B and C share one physical DB) possible without weakening any
    production path. The trigger is dropped only on this throwaway DB; C's subsequent ingest is
    an INSERT (unaffected by the delete trigger)."""
    conn = sqlite3.connect(db_path)
    try:
        # Drop the append-only DELETE guard + the FTS-mirror DELETE trigger (the latter writes
        # the external-content FTS5 table, which errors here) so the seed clear succeeds.
        conn.execute("DROP TRIGGER IF EXISTS facts_no_delete")
        conn.execute("DROP TRIGGER IF EXISTS facts_fts_ad")
        conn.execute("DELETE FROM facts WHERE id = ?", (fact_id,))
        conn.commit()
    finally:
        conn.close()


def _fact_row(entity: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM facts WHERE entity = ?", (entity,)
        ).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------
# Adapter so C's REAL pull client talks to B's REAL GET endpoint in-process.
# ---------------------------------------------------------------------------


class _CapturedResponse:
    """A pre-captured wire response replayed to C's pull client."""

    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _BGetClient:
    """Replays B's REAL GET wire body to C's pull client.

    ``pull_from_peer_once`` calls ``client.get(...)`` and reads ``.status_code`` /
    ``.json()``. We capture B's wire body up front by calling B's REAL in-process pull
    route (its W2.2 v2 emit + W2.3 egress relay gate run, authenticated as the
    downstream peer C), then replay that captured body here. The wire body + C's full
    verification chain are real; only the transport is in-process. Capturing up front
    lets the harness DELETE B's seed row before C's relay-ingest runs — so the surviving
    row is the one C's OWN secure chain writes (origin A, received_from B), not a no-op
    re-read (B and C share one physical DB in-process).
    """

    def __init__(self, captured_body: dict[str, Any]) -> None:
        self._body = captured_body

    async def get(self, url: str, *, params: dict[str, Any] | None = None,
                  headers: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        return _CapturedResponse(self._body)


def _c_relay_peer_dict(b_node_id: str) -> dict[str, Any]:
    """The peer row C uses to identify SENDER B (relay_trusted) when pulling from B.

    ``b_node_id`` is the RELAY B's node_id (== ``fed_node.node_id``), marked relay_trusted —
    C accepts B as a relay and independently verifies the origin (A) below the trust gate.
    ``id`` + ``ingest_tenant`` let the per-origin tenant resolver fall back to the single-
    tenant pin (no peer_tenant_map rows, origin_tenant == "default")."""
    return {
        "id": str(uuid.uuid4()),
        "node_id": b_node_id,
        "node_url": "http://relay-b",  # adapter ignores host; path is fixed
        "allowed_scopes": json.dumps(["public", "team", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": 1,
    }


def _set_relay_enabled(value: bool) -> None:
    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    _settings_mod.settings.federation_relay_enabled = value


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    """trust_mode=off so a peer-JWT Bearer token passes B's poll auth (mirrors W6.5/W6.6)."""
    import sys as _sys

    fed_mod = _sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_mod.settings, "trust_mode", "off", raising=False)


def _no_fetch(monkeypatch: Any) -> None:
    """Make A UNREACHABLE: the relay-origin manifest fetch returns 404 (and neutralize SSRF)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    def _get(*_a: Any, **_k: Any) -> Any:
        import httpx as _httpx  # noqa: PLC0415

        return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _get)
    monkeypatch.setattr(oi, "assert_safe_url", lambda *a, **k: None)


def _fetch_serves_a(monkeypatch: Any, a: _Node) -> None:
    """Make A REACHABLE: the relay-origin manifest fetch serves A's manifest (fetch-on-first)."""
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
    """C's peer-JWT for B's pull GET auth: ``iss = C.node_id`` (registered relay peer on B),
    ``sub = B.node_id`` (== fed_node.node_id)."""
    from conftest import make_peer_token  # noqa: PLC0415

    return "Bearer " + make_peer_token(
        c.priv_b64, c.node_id, fed_node.node_id, ["public", "team", "*"]
    )


def _capture_b_egress(fed_node: Any, a: _Node, c: _Node, fact: dict[str, Any],
                      origin: dict[str, Any], origin_sig: str) -> dict[str, Any]:
    """Seed A's fact on B, register C as a relay peer on B, capture B's REAL GET wire body.

    Returns B's v2 envelope (its W2.2 emit + W2.3 egress relay gate run), authed as the
    downstream peer C (iss=C.node_id, sub=B.node_id). This is what would travel B→C."""
    _seed_relayed_fact_on_b(
        fed_node.db_path, fact=fact, origin=origin, origin_sig=origin_sig,
        received_from=a.node_id,
    )
    _register_relay_peer_on_b(
        fed_node.db_path, c.node_id, c.pub_b64, allowed_tenants=[_TENANT]
    )
    b_resp = fed_node.client.get(
        "/v1/federation/facts",
        params={"limit": 200},
        headers={"Authorization": _bearer(fed_node, c)},
    )
    assert b_resp.status_code == 200, b_resp.text
    return b_resp.json()  # type: ignore[no-any-return]


def _run_bc_relay(
    fed_node: Any, a: _Node, c: _Node, fact: dict[str, Any], origin: dict[str, Any],
    origin_sig: str, *, wire_mutator: Any = None
) -> str | None:
    """Drive the B→C relay hop. ``fed_node`` is the RELAY B; ``c`` is the downstream puller.

    Captures B's real egress body, optionally mutates it on the wire (``wire_mutator`` — the
    anti-tamper case), clears B's seed row so the surviving row (if any) is the one C's OWN
    secure relay-ingest chain wrote (origin A, received_from B), then drives C's REAL
    ``pull_from_peer_once``. Returns the cursor."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once

    b_body = _capture_b_egress(fed_node, a, c, fact, origin, origin_sig)
    if wire_mutator is not None:
        wire_mutator(b_body)
    _delete_fact(fed_node.db_path, fact["id"])
    return asyncio.run(
        pull_from_peer_once(_c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None)
    )


@pytest.fixture()
def relay_topology(fed_node: Any, _trust_off: None) -> tuple[Any, _Node, _Node]:
    """Build origin A + downstream C identities (B = fed_node).

    Roles: ``fed_node`` is the RELAY B (serves the GET). ``a`` is the ORIGIN that asserted +
    origin-signed the fact (NOT a peer of C, so C resolves A's key the relay way). ``c`` is
    the downstream puller registered as a relay-trusted peer on B."""
    a = _Node("origin-a")
    c = _Node("downstream-c")
    return fed_node, a, c


# ---------------------------------------------------------------------------
# (a) HAPPY PATH — reachable origin: C verifies A's origin sig against A's FETCHED key.
# ---------------------------------------------------------------------------


def test_a_happy_path_reachable_origin_ingests_attributed_to_a(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(a) A→B→C: A reachable (fetch-on-first). C verifies the ORIGIN sig against **A's**
    key, then ingests. C's row is attributed to A (origin_node_id == A, received_from == B);
    the fact is recallable at C. THE capstone assertion: the origin attestation survived the
    relay hop — it was NOT re-signed by B."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-alice"
    fact = _build_fact(a, entity=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public", "team"])
    osig = _origin_sig(a, fact, origin)

    new_cursor = _run_bc_relay(fed_node, a, c, fact, origin, osig)
    assert new_cursor is not None  # B's page consumed

    row = _fact_row(entity_x)
    assert row is not None, "C did not ingest the relayed fact"
    # Attribution: the fact is A's, relayed via B (NOT re-signed by B).
    assert row["origin_node_id"] == a.node_id
    assert row["origin_entity_uri"] == a.entity_uri
    assert row["received_from"] == fed_node.node_id  # received FROM the relay B
    assert row["origin_sig"] == osig  # A's verbatim origin sig, forwarded + stored
    assert json.loads(row["origin_allowed_scopes"]) == ["public", "team"]
    assert row["source"] == a.node_id
    # Recallable at C: the ingested fact is queryable by entity.
    with _db_ctx() as conn:
        hit = conn.execute(
            "SELECT id FROM facts WHERE entity = ? AND tenant_id = ? AND confidence > 0.0",
            (entity_x, _TENANT),
        ).fetchone()
    assert hit is not None, "C's ingested fact is not recallable"
    assert hit["id"] == fact["id"]


# ---------------------------------------------------------------------------
# (b) HAPPY PATH — unreachable origin + operator pin (tier-1).
# ---------------------------------------------------------------------------


def test_b_happy_path_unreachable_origin_with_pin_ingests(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(b) A→B→C with A UNREACHABLE from C, but C holds an OPERATOR PIN for A's
    (entity_uri, node_id, key_fingerprint). C accepts A's key via the pin (tier-1) and
    ingests. Proves offline relay trust through the human anchor.

    The relayed fact carries A's manifest (``origin_manifest``) so C has a candidate to
    anchor-match against the pin — B emits it because A's manifest is stored at B (the seed
    + a stored binding). A's manifest is stored at B's trust store here for the carry."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)  # A unreachable from C's resolver
    # B carries A's manifest body on the wire (W4.2): store it at B so build_origin_entry
    # attaches it. (B is fed_node; the trust store is shared in-process.)
    store_peer_manifest(a.entity_uri, a.manifest(), None, trust_mode="relaxed")
    # Operator-pin A's key at C (shared DB in-process).
    with _db_ctx() as conn:
        put_origin_pin(
            conn,
            entity_uri=a.entity_uri,
            node_id=a.node_id,
            key_fingerprint=fingerprint_from_pubkey(a.pub_b64),
            pinned_by="operator:test",
        )
        conn.commit()

    entity_x = "user:relay4-bob"
    fact = _build_fact(a, entity=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)

    new_cursor = _run_bc_relay(fed_node, a, c, fact, origin, osig)
    assert new_cursor is not None

    row = _fact_row(entity_x)
    assert row is not None, "C did not ingest the pinned-unreachable relayed fact"
    assert row["origin_node_id"] == a.node_id
    assert row["received_from"] == fed_node.node_id  # received FROM the relay B


# ---------------------------------------------------------------------------
# (c) RELAY-OFF CONTAINMENT — default-OFF safety.
# ---------------------------------------------------------------------------


def test_c_relay_off_drops_relayed_fact(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(c) Same topology but ``federation_relay_enabled=False`` at C → C DROPS B's relayed
    fact (origin_not_sender) even though A is reachable + B is relay_trusted. The fact is
    NOT at C. Proves default-OFF containment.

    With relay OFF, B's W2.3 egress gate ALSO withholds the relayed row (received_from IS
    NULL only), AND C's ingest would drop it (origin_not_sender). Either way C must NOT end
    up with the fact."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(False)  # relay OFF at C (and at B's egress)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-carol"
    fact = _build_fact(a, entity=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)

    _run_bc_relay(fed_node, a, c, fact, origin, osig)
    assert _fact_row(entity_x) is None, "relay OFF must not ingest a relayed fact at C"


# ---------------------------------------------------------------------------
# (d) UNANCHORED FAIL-CLOSED — no acceptance of an unknown, unreachable origin.
# ---------------------------------------------------------------------------


def test_d_unanchored_unreachable_origin_fails_closed(
    fed_node: Any, _trust_off: None, monkeypatch: Any
) -> None:
    """(d) C has NO pin for A, A is UNREACHABLE, B is relay_trusted → C's relay key resolver
    raises (relay_origin_unanchored) → C does NOT ingest. Proves a relay cannot get an
    unknown, unreachable origin's fact accepted at C (fail-closed)."""
    a = _Node("origin-a")
    c = _Node("downstream-c")
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)  # A unreachable, NO pin, NO stored binding for A.

    entity_x = "user:relay4-dave"
    fact = _build_fact(a, entity=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)

    _run_bc_relay(fed_node, a, c, fact, origin, osig)
    assert _fact_row(entity_x) is None, (
        "unanchored + unreachable origin must fail closed — no ingest at C"
    )


# ---------------------------------------------------------------------------
# (e) SCOPE/TENANT PROPAGATION — a relay can't deliver outside the origin's grant.
# ---------------------------------------------------------------------------


def test_e_scope_tenant_propagation_blocks_out_of_grant_allows_within(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(e) Two relayed facts from A, both reachable + relay_trusted:

      * BLOCKED: ``origin_allowed_tenants`` excludes C's tenant ('default') — granted only
        for tenant 'acme'. B's W2.3 egress tenant gate (origin_allowed_tenants ∩
        peer.allowed_tenants = ∅) withholds it; it never reaches C.
      * ALLOWED: a sibling fully within the origin grant (scope ∈ grant, tenant ∋ default)
        IS delivered + ingested at C.

    Proves the scope/tenant propagation limits travel with the relayed fact."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    # BLOCKED sibling: origin grants tenant 'acme' only — excludes C's tenant 'default'.
    blocked_entity = "user:relay4-erin-blocked"
    blocked_fact = _build_fact(a, entity=blocked_entity, scope="public", hlc_offset_ms=0)
    blocked_origin = _origin_block(a, allowed_scopes=["public"], allowed_tenants=["acme"])
    blocked_sig = _origin_sig(a, blocked_fact, blocked_origin)

    # ALLOWED sibling: fully within grant for C's tenant 'default'.
    allowed_entity = "user:relay4-erin-allowed"
    allowed_fact = _build_fact(a, entity=allowed_entity, scope="public", hlc_offset_ms=1)
    allowed_origin = _origin_block(a, allowed_scopes=["public"], allowed_tenants=["default"])
    allowed_sig = _origin_sig(a, allowed_fact, allowed_origin)

    # Seed BOTH on B, then capture B's egress once (both rows are candidates for the page).
    _seed_relayed_fact_on_b(
        fed_node.db_path, fact=blocked_fact, origin=blocked_origin,
        origin_sig=blocked_sig, received_from=a.node_id,
    )
    _seed_relayed_fact_on_b(
        fed_node.db_path, fact=allowed_fact, origin=allowed_origin,
        origin_sig=allowed_sig, received_from=a.node_id,
    )
    _register_relay_peer_on_b(
        fed_node.db_path, c.node_id, c.pub_b64, allowed_tenants=[_TENANT]
    )
    b_resp = fed_node.client.get(
        "/v1/federation/facts",
        params={"limit": 200},
        headers={"Authorization": _bearer(fed_node, c)},
    )
    assert b_resp.status_code == 200, b_resp.text
    b_body = b_resp.json()

    # B's W2.3 egress tenant gate withholds the BLOCKED fact entirely.
    emitted_ids = {e["fact"]["id"] for e in b_body["facts"]}
    assert blocked_fact["id"] not in emitted_ids, (
        "out-of-tenant-grant fact must NOT egress from the relay B"
    )
    assert allowed_fact["id"] in emitted_ids, "within-grant fact must egress from B"

    _delete_fact(fed_node.db_path, blocked_fact["id"])
    _delete_fact(fed_node.db_path, allowed_fact["id"])
    from stigmem_node.federation.federation_pull import pull_from_peer_once

    asyncio.run(
        pull_from_peer_once(_c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None)
    )

    assert _fact_row(blocked_entity) is None, "blocked fact must be absent at C"
    allowed_row = _fact_row(allowed_entity)
    assert allowed_row is not None, "within-grant fact must be ingested at C"
    assert allowed_row["origin_node_id"] == a.node_id
    assert allowed_row["received_from"] == fed_node.node_id


# ---------------------------------------------------------------------------
# (f) ANTI-TAMPER — a relay can't alter the fact body undetected.
# ---------------------------------------------------------------------------


def test_f_relay_tampered_fact_body_fails_origin_sig(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(f) B (a malicious relay) ALTERS the fact body on the wire after A signed it. The cid
    binds the body and the origin sig binds the cid, so C recomputes a DIFFERENT cid →
    A's origin signature no longer verifies → C DROPS the fact. Entity X is NOT at C.

    The mutation rewrites the value AND its cid to the new (self-consistent) body, so the
    cid-vs-body check passes but the origin sig (signed over the ORIGINAL cid) fails — this
    isolates the origin-signature binding as the property under test, not the cid check."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-frank"
    fact = _build_fact(a, entity=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)  # signed over the ORIGINAL cid/body

    def _tamper(body: dict[str, Any]) -> None:
        for entry in body["facts"]:
            if entry["fact"]["id"] == fact["id"]:
                # Rewrite the value to a malicious payload + recompute a self-consistent cid
                # so the cid-vs-body check passes; only the origin sig (over the old cid) breaks.
                entry["fact"]["value"] = {"type": "string", "v": "TAMPERED-BY-RELAY"}
                entry["fact"]["cid"] = _fact_cid(entry["fact"])

    _run_bc_relay(fed_node, a, c, fact, origin, osig, wire_mutator=_tamper)
    assert _fact_row(entity_x) is None, (
        "a relay-tampered fact body must invalidate the origin sig — no ingest at C"
    )
