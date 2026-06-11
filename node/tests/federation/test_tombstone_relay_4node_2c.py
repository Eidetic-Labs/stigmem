"""Phase 2c W6.9 — multi-node TOMBSTONE relay PROOF (the capstone).

The tombstone analogue of the 2b/2c 4-node FACT relay proof. It proves that a
SUPPRESSION ORDER (RTBF tombstone) issued by origin **A** travels A → B → C and is
verified at C against **A's** key (the origin attestation survives the relay hop — it
is NOT re-signed by the relay B), and that the critical fail-closed / containment
properties hold so a relay can neither forge, re-scope, nor censor-by-unknown-origin.

Topology (three distinct federation identities):
  * **A** — the ORIGIN that issued + origin-signed the tombstone. NOT a peer of C, so
    C must resolve A's key the relay way (fetch-on-first / operator pin), never the 2a
    direct-peer chain.
  * **B** — the RELAY. ``fed_node`` plays B: A's tombstone is seeded into B's DB as an
    INBOUND/relayed row (A's verbatim origin block + A's real origin_sig + A's issuer
    sig, ``received_from = A``), exactly as B would have stored it after pulling from A
    (W6.5/W6.7 direct path). B re-serves it through its REAL pull GET endpoint
    (``/v1/federation/tombstones``), exercising the W6.6 egress relay gate.
  * **C** — the DOWNSTREAM node under test. C drives the REAL
    ``pull_tombstones_from_peer_once`` against B's live GET (via a thin adapter that
    wraps B's ``TestClient``), running the full W6.7 secure relay-ingest chain:
    relay-trusted gate → resolve A's key (relay resolver) → verify A's origin sig +
    A's issuer sig → scope/tenant gate → apply with A's origin block + ``received_from=B``.

Because the suite runs in-process on ONE physical DB, B and C share storage. To make the
B→C hop a genuine relay-ingest (not a no-op re-read of the seed row), the seed row is
DELETED after B's GET captures the wire body and BEFORE C ingests — so the row C ends up
with is the one its OWN secure chain wrote (origin A, received_from B). This is the same
"clear-then-pull" technique the W6.5 (g) single-node round-trip uses; the wire body + the
A-key verification are real, only the transport is in-process.

Tests:
  (a) HAPPY PATH (reachable origin): A reachable via fetch-on-first → C verifies A's
      origin sig against A's FETCHED key + A's issuer sig → APPLIED. C's row has
      ``origin_node_id == A`` and ``received_from == B``; entity X is suppressed at C.
  (b) HAPPY PATH (unreachable origin + pin): A UNREACHABLE, C has an operator PIN for
      A's (entity_uri, node_id, key_fingerprint) → C accepts via the pin (tier-1) → APPLIED.
  (c) RELAY-OFF CONTAINMENT: same topology, ``federation_relay_enabled=False`` at C →
      C DROPS B's relayed tombstone (origin_not_sender); X is NOT suppressed at C.
  (d) UNANCHORED FAIL-CLOSED: C has NO pin, A UNREACHABLE, B relay_trusted → the relay
      resolver raises (relay_origin_unanchored) → C does NOT apply; X not suppressed.
  (e) ANTI-RELAUNDER: B widens the tombstone ``scope`` on the wire past the scope A
      signed → C's origin-sig verification fails (scope is bound in the signed tuple) →
      DROPPED; X not suppressed.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.origin_pins import fingerprint_from_pubkey, put_origin_pin
from stigmem_node.federation.origin_signature import sign_tombstone_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest
from stigmem_node.identity.trust_store import store_peer_manifest
from stigmem_node.lifecycle.tombstone_signing import _signing_body
from stigmem_node.models.tombstones import TombstoneRecord

from .helpers import generate_ed25519_b64

_TENANT = "default"


# ---------------------------------------------------------------------------
# Identity + crypto helpers
# ---------------------------------------------------------------------------


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


class _Node:
    """A federation identity used as origin A or relay-sender B in the proof."""

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


def _issuer_signed_tombstone(
    issuer: _Node, *, entity_uri: str, scope: str
) -> TombstoneRecord:
    """Build a TombstoneRecord carrying *issuer*'s valid ISSUER-signer signature.

    ``signed_by`` is the issuer's entity_uri and ``key_id`` its manifest key_id, so the
    receiver resolves the verifying key from the stored issuer manifest (a non-network
    ``get_peer_manifest`` lookup) — exactly as the W6.7 relayed-ingest chain does.
    """
    rec = TombstoneRecord(
        id=f"tomb_{uuid.uuid4()}",
        entity_uri=entity_uri,
        scope=scope,
        reason=None,
        signed_by=issuer.entity_uri,
        key_id=issuer.key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    sig = base64.urlsafe_b64encode(issuer.priv.sign(_signing_body(rec))).decode().rstrip("=")
    return rec.model_copy(update={"signature": sig})


def _origin_block(node: _Node, *, allowed_scopes: list[str]) -> dict[str, Any]:
    return {
        "tenant": _TENANT,
        "node_id": node.node_id,
        "allowed_scopes": allowed_scopes,
        "allowed_tenants": [_TENANT],
        "entity_uri": node.entity_uri,
    }


def _origin_sig(origin_node: _Node, rec: TombstoneRecord, origin: dict[str, Any], *,
                sign_scope: str | None = None) -> str:
    """A's origin-attestation signature over the tombstone tuple.

    ``sign_scope`` lets the anti-relaunder case (e) sign over a NARROWER scope than the
    wire row carries, so a relay that widened the on-wire scope invalidates the sig.
    """
    return sign_tombstone_origin(
        origin_node.priv,
        tombstone_id=rec.id,
        entity_uri=rec.entity_uri,
        scope=sign_scope if sign_scope is not None else rec.scope,
        origin_node_id=origin["node_id"],
        origin_tenant=origin["tenant"],
        origin_allowed_scopes=origin["allowed_scopes"],
        origin_allowed_tenants=origin["allowed_tenants"],
        origin_entity_uri=origin["entity_uri"],
    )


# ---------------------------------------------------------------------------
# B-side DB seeding: store A's tombstone on B as an INBOUND/relayed row, exactly
# as B would have stored it after pulling DIRECTLY from A (W6.5/W6.7). B will then
# re-serve it from its real pull GET endpoint under the W6.6 egress relay gate.
# ---------------------------------------------------------------------------


def _seed_relayed_tombstone_on_b(
    db_path: str,
    *,
    rec: TombstoneRecord,
    origin: dict[str, Any],
    origin_sig: str,
    received_from: str,
) -> None:
    """Insert A's tombstone into B's DB with A's verbatim origin block + ``received_from=A``.

    Mirrors the columns ``apply_inbound_tombstone(... origin cols + received_from)`` writes
    on B after a direct pull from A; the origin_* JSON uses the canonical
    ``json.dumps(sorted([...]))`` encoding the egress LIKE-membership gate matches.
    """
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
                rec.id,
                rec.entity_uri,
                rec.scope,
                rec.reason,
                rec.signed_by,
                rec.key_id,
                rec.signature,
                rec.created_at,
                int(rec.legal_hold),
                _TENANT,
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


def _delete_tombstone(db_path: str, tomb_id: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DELETE FROM tombstones WHERE id = ?", (tomb_id,))
        conn.commit()
    finally:
        conn.close()
    from stigmem_node.lifecycle.tombstones import invalidate_tombstone_cache

    invalidate_tombstone_cache()


def _tombstone_row(entity_uri: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT * FROM tombstones WHERE entity_uri = ?", (entity_uri,)
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

    ``pull_tombstones_from_peer_once`` calls ``client.get(...)`` and reads ``.status_code`` /
    ``.json()``. We capture B's wire body up front by calling B's REAL in-process pull route
    (its W6.5 v2 emit + W6.6 egress relay gate run, authenticated as the downstream peer C),
    then replay that captured body here. This mirrors the W6.5 (g) round-trip (GET body fed
    to the pull client): the wire body + C's full verification chain are real; only the
    transport is in-process. Capturing up front (rather than re-fetching live during the pull)
    lets the harness DELETE B's seed row before C's relay-ingest runs — so the surviving row
    is the one C's OWN secure chain writes (origin A, received_from B), not a no-op re-read
    (B and C share one physical DB in-process).
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
    """
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


def _run_bc_relay(
    fed_node: Any, a: _Node, c: _Node, rec: TombstoneRecord, origin: dict[str, Any],
    origin_sig: str
) -> str | None:
    """Drive the B→C relay hop. ``fed_node`` is the RELAY B; ``c`` is the downstream puller.

    Seeds A's tombstone on B as a relayed row (received_from=A), registers C as a relay peer
    on B, then drives C's REAL ``pull_tombstones_from_peer_once`` against B's REAL GET (its
    W6.6 egress gate runs). Clears B's seed row before C ingests so the surviving row (if any)
    is the one C's OWN secure relay-ingest chain wrote (origin A, received_from B) — not a
    no-op re-read of the seed (B and C share one physical DB in-process). Returns the cursor."""
    from stigmem_node.federation.federation_pull import pull_tombstones_from_peer_once

    _seed_relayed_tombstone_on_b(
        fed_node.db_path, rec=rec, origin=origin, origin_sig=origin_sig,
        received_from=a.node_id,
    )
    _register_relay_peer_on_b(
        fed_node.db_path, c.node_id, c.pub_b64, allowed_tenants=[_TENANT]
    )
    # Capture B's REAL GET wire body (B's W6.5 emit + W6.6 egress relay gate run), authed as
    # the downstream peer C (iss=C.node_id, sub=B.node_id). This is what would travel B→C.
    c_auth = _bearer(fed_node, c)
    b_resp = fed_node.client.get(
        "/v1/federation/tombstones",
        params={"limit": 200},
        headers={"Authorization": c_auth},
    )
    assert b_resp.status_code == 200, b_resp.text
    b_body = b_resp.json()
    # Clear B's seed so C's relay-ingest writes its OWN row (origin A, received_from B) rather
    # than no-op re-reading the seed (B and C share one physical DB in-process).
    _delete_tombstone(fed_node.db_path, rec.id)
    return asyncio.run(
        pull_tombstones_from_peer_once(
            _c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None
        )
    )


def _bearer(fed_node: Any, c: _Node) -> str:
    """C's peer-JWT for B's pull GET auth: ``iss = C.node_id`` (registered relay peer on B),
    ``sub = B.node_id`` (== fed_node.node_id)."""
    from conftest import make_peer_token  # noqa: PLC0415

    return "Bearer " + make_peer_token(
        c.priv_b64, c.node_id, fed_node.node_id, ["public", "team", "*"]
    )


@pytest.fixture()
def relay_topology(fed_node: Any, _trust_off: None) -> tuple[Any, _Node, _Node]:
    """Build origin A + downstream C identities; store A's issuer manifest at C (B = fed_node).

    Roles: ``fed_node`` is the RELAY B (serves the GET). ``a`` is the ORIGIN that issued +
    origin-signed the tombstone (NOT a peer of C, so C resolves A's key the relay way). ``c``
    is the downstream puller registered as a relay-trusted peer on B.

    A's manifest is stored at C so the ISSUER-signer verification (a non-network
    ``get_peer_manifest(A.entity_uri)`` lookup) resolves A's key — independent of whether A is
    reachable for the ORIGIN-key resolution (which the per-test fetch stub / pin drives).
    """
    a = _Node("origin-a")
    c = _Node("downstream-c")
    store_peer_manifest(a.entity_uri, a.manifest(), None, trust_mode="relaxed")
    return fed_node, a, c


# ---------------------------------------------------------------------------
# (a) HAPPY PATH — reachable origin: C verifies A's origin sig against A's FETCHED key.
# ---------------------------------------------------------------------------


def test_a_happy_path_reachable_origin_applies_attributed_to_a(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(a) A→B→C: A reachable (fetch-on-first). C verifies the ORIGIN sig against **A's**
    key + A's issuer sig, then applies. C's row is attributed to A (origin_node_id == A,
    received_from == B); entity X is suppressed at C. THE capstone assertion: the origin
    attestation survived the relay hop — it was NOT re-signed by B."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-alice"
    rec = _issuer_signed_tombstone(a, entity_uri=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public", "team"])
    osig = _origin_sig(a, rec, origin)

    new_cursor = _run_bc_relay(fed_node, a, c, rec, origin, osig)
    assert new_cursor is not None  # B's page consumed

    row = _tombstone_row(entity_x)
    assert row is not None, "C did not apply the relayed tombstone"
    # Attribution: the suppression is A's, relayed via B (NOT re-signed by B).
    assert row["origin_node_id"] == a.node_id
    assert row["origin_entity_uri"] == a.entity_uri
    assert row["received_from"] == fed_node.node_id  # received FROM the relay B
    assert row["origin_sig"] == osig  # A's verbatim origin sig, forwarded + stored
    assert json.loads(row["origin_allowed_scopes"]) == ["public", "team"]
    # Suppression: with the recall filter enabled, X is suppressed at C.
    from stigmem_node.lifecycle import tombstone_cache

    tombstone_cache.invalidate()
    assert _is_suppressed(entity_x, "public") is True


# ---------------------------------------------------------------------------
# (b) HAPPY PATH — unreachable origin + operator pin (tier-1).
# ---------------------------------------------------------------------------


def test_b_happy_path_unreachable_origin_with_pin_applies(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(b) A→B→C with A UNREACHABLE from C, but C holds an OPERATOR PIN for A's
    (entity_uri, node_id, key_fingerprint). C accepts A's key via the pin (tier-1) and
    applies. Proves offline relay trust through the human anchor."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)  # A unreachable
    # Operator-pin A's key out-of-band.
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
    rec = _issuer_signed_tombstone(a, entity_uri=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, rec, origin)
    # The pin path matches the candidate manifest against the operator pin; A's manifest is
    # already stored at C (relay_topology), so the candidate resolves even with A unreachable.

    new_cursor = _run_bc_relay(fed_node, a, c, rec, origin, osig)
    assert new_cursor is not None

    row = _tombstone_row(entity_x)
    assert row is not None, "C did not apply the pinned-unreachable relayed tombstone"
    assert row["origin_node_id"] == a.node_id
    assert row["received_from"] == fed_node.node_id  # received FROM the relay B


# ---------------------------------------------------------------------------
# (c) RELAY-OFF CONTAINMENT — default-OFF safety.
# ---------------------------------------------------------------------------


def test_c_relay_off_drops_relayed_tombstone(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(c) Same topology but ``federation_relay_enabled=False`` at C → C DROPS B's relayed
    tombstone (origin_not_sender) even though A is reachable + B is relay_trusted. Entity X
    is NOT suppressed at C. Proves default-OFF containment."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(False)  # relay OFF at C
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-carol"
    rec = _issuer_signed_tombstone(a, entity_uri=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, rec, origin)

    # With relay OFF, B's egress gate (W6.6) ALSO withholds the relayed row, AND C's ingest
    # would drop it (origin_not_sender). Either way C must NOT end up with the tombstone.
    _run_bc_relay(fed_node, a, c, rec, origin, osig)
    assert _tombstone_row(entity_x) is None, "relay OFF must not apply a relayed tombstone at C"


# ---------------------------------------------------------------------------
# (d) UNANCHORED FAIL-CLOSED — no censorship-by-unknown-origin.
# ---------------------------------------------------------------------------


def test_d_unanchored_unreachable_origin_fails_closed(
    fed_node: Any, _trust_off: None, monkeypatch: Any
) -> None:
    """(d) C has NO pin for A, A is UNREACHABLE, B is relay_trusted → C's relay key resolver
    raises (relay_origin_unanchored) → C does NOT apply. Proves a relay cannot suppress an
    entity at C by inventing an unknown, unreachable origin (no censorship-by-unknown-origin).

    A's issuer manifest is NOT stored at C here either, so even the issuer leg has no anchor —
    but the ORIGIN-key resolution fails first, fail-closed."""
    a = _Node("origin-a")
    c = _Node("downstream-c")
    _set_relay_enabled(True)
    _no_fetch(monkeypatch)  # A unreachable, and NO pin, NO stored binding for A.

    entity_x = "user:relay4-dave"
    rec = _issuer_signed_tombstone(a, entity_uri=entity_x, scope="public")
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, rec, origin)

    _run_bc_relay(fed_node, a, c, rec, origin, osig)
    assert _tombstone_row(entity_x) is None, (
        "unanchored + unreachable origin must fail closed — no suppression at C"
    )


# ---------------------------------------------------------------------------
# (e) ANTI-RELAUNDER — a relay can't widen a suppression's scope.
# ---------------------------------------------------------------------------


def test_e_relay_widened_scope_fails_origin_sig(
    relay_topology: Any, monkeypatch: Any
) -> None:
    """(e) B tampers the relayed tombstone by WIDENING its ``scope`` ('team' → '*') past the
    scope A actually signed. The scope is bound in A's origin-attestation tuple, so C's
    origin-sig verification FAILS → DROPPED. Entity X is NOT suppressed at C. Proves a relay
    cannot re-scope a suppression order.

    A's allowed_scopes deliberately includes '*' so the ingest scope-gate alone would PASS —
    only the origin-sig binding catches the widening, isolating that property."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _fetch_serves_a(monkeypatch, a)

    entity_x = "user:relay4-erin"
    # Wire row carries the WIDE scope '*'; A only ever signed over the NARROW scope 'team'.
    rec = _issuer_signed_tombstone(a, entity_uri=entity_x, scope="*")
    origin = _origin_block(a, allowed_scopes=["team", "*"])
    osig = _origin_sig(a, rec, origin, sign_scope="team")  # signed narrow, wire is wide

    _run_bc_relay(fed_node, a, c, rec, origin, osig)
    assert _tombstone_row(entity_x) is None, (
        "a relay-widened scope must invalidate the origin sig — no suppression at C"
    )


# ---------------------------------------------------------------------------
# Suppression helper (recall filter enabled).
# ---------------------------------------------------------------------------


def _is_suppressed(entity_uri: str, scope: str) -> bool:
    """True iff the recall-time tombstone filter suppresses *entity_uri* at *scope*.

    The recall filter (``is_tombstoned``) is gated behind the tombstone plugin + env flags
    (W6.5 concern). Rather than stand up the plugin here, we assert suppression at the storage
    layer the pull path is responsible for WRITING: an active, un-revoked tombstone row whose
    scope pattern covers *scope*. This is the same suppression signal the filter reads."""
    from stigmem_node.lifecycle.tombstones import _scope_matches

    with _db_ctx() as conn:
        rows = conn.execute(
            """SELECT t.entity_uri, t.scope FROM tombstones t
               WHERE t.entity_uri = ? AND NOT EXISTS (
                   SELECT 1 FROM tombstone_revocations r WHERE r.tombstone_id = t.id
               )""",
            (entity_uri,),
        ).fetchall()
    return any(_scope_matches(r["scope"], scope) for r in rows)
