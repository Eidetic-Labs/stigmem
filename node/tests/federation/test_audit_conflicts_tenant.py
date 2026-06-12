"""Tenant-scoping for the conflict-audit read surface + inbound tombstone keying.

Federation multi-tenancy Phase 1, Task 6.

Surface A: GET /v1/conflicts (routes/federation/audit_conflicts.py) exposed an
operator view over conflicts + the facts involved WITHOUT a tenant filter, so an
admin scoped to tenant-a could see a conflict whose facts live in tenant-b. Now
that ingest stamps tenant on facts AND conflict facts (Task 3), the conflict and
fact reads MUST be scoped by identity.tenant_id.

Surface B: inbound federation tombstones (apply_inbound_tombstone) used to land
in the 'default' tenant unconditionally. The recall-time suppression filter
(lifecycle/tombstone_cache.is_tombstoned) keys on (entity_uri, tenant_id), so a
tombstone stamped 'default' could never suppress a tenant-a fact — and, worse, a
tombstone meant for tenant-a would suppress a default-tenant fact with the same
entity. The application path must stamp the peer's resolved ingest tenant.
"""

from __future__ import annotations

import importlib
import sqlite3
import sys
import uuid
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.multi_tenant_gate as mtg
import stigmem_node.settings as settings_module
from stigmem_node.hlc import node_hlc
from stigmem_node.main import create_app
from stigmem_node.plugins.testing import stigmem_plugins

from .helpers import generate_ed25519_b64

_TOMBSTONE_PLUGIN_SRC = Path(__file__).resolve().parents[3] / "experimental" / "tombstones" / "src"

_PLUGIN_SRC = Path(__file__).resolve().parents[3] / "experimental" / "multi-tenant" / "src"
if str(_PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_SRC))

_PLUGIN = importlib.import_module("stigmem_plugin_multi_tenant")

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings
plugin_manifest = _PLUGIN.plugin_manifest


# ---------------------------------------------------------------------------
# Surface A — conflict-audit reads scoped by identity.tenant_id
# ---------------------------------------------------------------------------


@pytest.fixture()
def two_tenant_app(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TestClient, str, str, str], None, None]:
    """Single DB, two tenant API keys, multi-tenant plugin active.

    Yields (client, db_path, key_a, key_b) where key_a/key_b are read-capable
    keys scoped to tenant-a / tenant-b respectively.
    """
    db_file = str(tmp_path) + "/audit_conflicts_mt.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    original = settings_module.settings
    test_settings = Settings(db_path=db_file, auth_required=True, node_url="http://testnode")
    settings_module.settings = test_settings
    auth_mod.settings = test_settings
    db_mod.settings = test_settings

    key_a = create_api_key("agent:alice", ["read", "write"], tenant_id="tenant-a")
    key_b = create_api_key("agent:bob", ["read", "write"], tenant_id="tenant-b")

    monkeypatch.setenv("STIGMEM_MULTI_TENANT_ENABLED", "true")
    with stigmem_plugins([plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c, db_file, key_a, key_b

    settings_module.settings = original
    auth_mod.settings = original
    db_mod.settings = original


def _seed_conflict(db_path: str, tenant_id: str) -> tuple[str, str, str]:
    """Seed two conflicting facts + a conflicts row, all stamped ``tenant_id``.

    Returns (conflict_id, fact_a_id, fact_b_id).
    """
    entity = f"audit:conflict:{tenant_id}:{uuid.uuid4()}"
    fact_a_id = str(uuid.uuid4())
    fact_b_id = str(uuid.uuid4())
    conflict_id = f"stigmem:conflict:{uuid.uuid4()}"
    now = datetime.now(UTC).isoformat()

    conn = sqlite3.connect(db_path)
    try:
        for fid, val in ((fact_a_id, "from-a"), (fact_b_id, "from-b")):
            conn.execute(
                """INSERT INTO facts
                   (id, entity, relation, value_type, value_v, source, timestamp,
                    confidence, scope, hlc, tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fid,
                    entity,
                    "test:value",
                    "string",
                    val,
                    "stigmem://node-b",
                    now,
                    1.0,
                    "public",
                    node_hlc.tick(),
                    tenant_id,
                ),
            )
        conn.execute(
            """INSERT INTO conflicts (id, fact_a_id, fact_b_id, status, detected_at)
               VALUES (?,?,?,?,?)""",
            (conflict_id, fact_a_id, fact_b_id, "unresolved", now),
        )
        conn.commit()
    finally:
        conn.close()
    return conflict_id, fact_a_id, fact_b_id


def test_conflict_audit_does_not_leak_other_tenant_conflict(
    two_tenant_app: tuple[TestClient, str, str, str],
) -> None:
    """A tenant-a admin must NOT see a conflict whose facts live in tenant-b."""
    client, db_path, key_a, _key_b = two_tenant_app

    a_conflict, a_fa, a_fb = _seed_conflict(db_path, "tenant-a")
    b_conflict, b_fa, b_fb = _seed_conflict(db_path, "tenant-b")

    r = client.get("/v1/conflicts", headers={"Authorization": f"Bearer {key_a}"})
    assert r.status_code == 200, r.text
    body = r.json()
    conflict_ids = {c["conflict_id"] for c in body["conflicts"]}

    # tenant-a's own conflict is visible
    assert a_conflict in conflict_ids
    # tenant-b's conflict (and its facts) must NOT leak to tenant-a
    assert b_conflict not in conflict_ids
    seen_fact_ids = set()
    for c in body["conflicts"]:
        for side in ("fact_a", "fact_b"):
            if c[side]:
                seen_fact_ids.add(c[side]["id"])
    assert b_fa not in seen_fact_ids
    assert b_fb not in seen_fact_ids


def test_conflict_audit_tenant_b_sees_only_its_own(
    two_tenant_app: tuple[TestClient, str, str, str],
) -> None:
    """Symmetric check: tenant-b sees its conflict, not tenant-a's."""
    client, db_path, key_a, key_b = two_tenant_app

    a_conflict, _a_fa, _a_fb = _seed_conflict(db_path, "tenant-a")
    b_conflict, _b_fa, _b_fb = _seed_conflict(db_path, "tenant-b")

    r = client.get("/v1/conflicts", headers={"Authorization": f"Bearer {key_b}"})
    assert r.status_code == 200, r.text
    conflict_ids = {c["conflict_id"] for c in r.json()["conflicts"]}
    assert b_conflict in conflict_ids
    assert a_conflict not in conflict_ids


def test_resolution_facts_stamped_with_resolver_tenant(
    two_tenant_app: tuple[TestClient, str, str, str],
) -> None:
    """When a tenant-a admin resolves a tenant-a conflict, every facts row the
    resolution writes must carry tenant_id='tenant-a' — NOT the schema default
    'default'. Otherwise the resolution facts cross the tenant boundary and the
    conflict can still read as unresolved in tenant-a's view.
    """
    client, db_path, key_a, _key_b = two_tenant_app

    conflict_id, fact_a_id, fact_b_id = _seed_conflict(db_path, "tenant-a")

    # Snapshot facts already present so we can isolate the rows written by resolve.
    conn = sqlite3.connect(db_path)
    try:
        before = {
            r[0] for r in conn.execute("SELECT id FROM facts").fetchall()
        }
    finally:
        conn.close()

    r = client.post(
        f"/v1/conflicts/{conflict_id}/resolve",
        headers={"Authorization": f"Bearer {key_a}"},
        json={"winning_fact_id": fact_a_id},
    )
    assert r.status_code == 200, r.text

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        new_rows = conn.execute(
            "SELECT id, entity, relation, tenant_id FROM facts"
        ).fetchall()
    finally:
        conn.close()

    written = [row for row in new_rows if row["id"] not in before]
    # Sanity: the resolution path writes facts (resolution fact + resolves meta +
    # status fact). If this is 0 the test is meaningless.
    assert written, "resolution wrote no facts rows"

    for row in written:
        assert row["tenant_id"] == "tenant-a", (
            f"resolution fact {row['entity']}/{row['relation']} landed in "
            f"tenant {row['tenant_id']!r}, expected 'tenant-a'"
        )


# ---------------------------------------------------------------------------
# Surface B — inbound tombstone lands in the peer's ingest tenant, not 'default'
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.status_code = 200
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._payload


class _StubClient:
    """Serves an empty facts page and a single tombstone page, then drains."""

    def __init__(self, tombstones: list[dict[str, Any]]) -> None:
        self._tombstones = tombstones
        self._served = False

    async def __aenter__(self) -> _StubClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get(self, url: str, **kwargs: Any) -> _StubResponse:
        if "/tombstones" in url:
            # W6.5: tombstone pull now consumes the v2 signed-origin envelope.
            if self._served:
                return _StubResponse(
                    {"v": 2, "tombstones": [], "revocations": [], "cursor": None}
                )
            self._served = True
            return _StubResponse(
                {"v": 2, "tombstones": self._tombstones, "revocations": [], "cursor": None}
            )
        # W6.5: facts pull also requires the v2 envelope (v key present).
        return _StubResponse({"v": 2, "facts": [], "cursor": None})


def _bound_peer_for_pull(fed_node: Any, *, ingest_tenant: str) -> tuple[str, str, Any, str]:
    """Insert an active, entity_uri-bound peer (origin == issuer) pinned to *ingest_tenant*.

    Returns (node_id, entity_uri, priv, manifest_key_id) so the test can sign a v2 tombstone
    envelope the pull path will accept (resolve_origin_key + get_peer_manifest both resolve).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from stigmem_node.identity.key_rotation import generate_key_id

    # Single import style for stigmem_node.db: the module alias (db_mod) is required
    # because this test monkeypatches db_mod.settings, so bind db() from it.
    _db_ctx = db_mod.db

    from .helpers import make_bound_peer

    pub_b64, priv_b64 = generate_ed25519_b64()
    import base64 as _b64

    priv = Ed25519PrivateKey.from_private_bytes(
        _b64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    )
    node_id = f"stigmem://peer-{uuid.uuid4()}"
    entity_uri = f"https://peer-{uuid.uuid4()}.example"
    key_id = generate_key_id(priv.public_key())
    with _db_ctx() as conn:
        peer_id = make_bound_peer(
            conn, node_id=node_id, entity_uri=entity_uri, pub_b64=pub_b64, priv=priv
        )
        conn.execute(
            "UPDATE peers SET ingest_tenant = ? WHERE id = ?", (ingest_tenant, peer_id)
        )
        conn.commit()
    return node_id, entity_uri, priv, key_id


def _make_v2_tombstone_entry(
    entity_uri: str,
    *,
    sender_node_id: str,
    sender_entity_uri: str,
    sender_priv: Any,
    key_id: str,
) -> dict[str, Any]:
    """Build one v2 DIRECT tombstone envelope entry signed by the bound sender peer.

    Both signatures are produced with the sender's key (origin == issuer == sender), so the
    pull path's origin-sig AND issuer-sig checks both pass. Mirrors the W6.5 wire shape.
    """
    import base64 as _base64

    from stigmem_node.federation.origin_signature import sign_tombstone_origin
    from stigmem_node.lifecycle.tombstone_signing import _signing_body
    from stigmem_node.models.tombstones import TombstoneRecord

    rec = TombstoneRecord(
        id="tomb_" + str(uuid.uuid4()),
        entity_uri=entity_uri,
        scope="*",
        reason="rtbf",
        signed_by=sender_entity_uri,  # issuer == the bound sender (manifest stored)
        key_id=key_id,
        signature="",
        created_at=datetime.now(UTC).isoformat(),
        legal_hold=False,
    )
    issuer_sig = (
        _base64.urlsafe_b64encode(sender_priv.sign(_signing_body(rec))).decode().rstrip("=")
    )
    rec = rec.model_copy(update={"signature": issuer_sig})
    origin = {
        "tenant": "default",
        "node_id": sender_node_id,
        "allowed_scopes": ["*"],
        "allowed_tenants": ["default"],
        "entity_uri": sender_entity_uri,
    }
    origin_sig = sign_tombstone_origin(
        sender_priv,
        tombstone_id=rec.id,
        entity_uri=rec.entity_uri,
        scope=rec.scope,
        origin_node_id=sender_node_id,
        origin_tenant="default",
        origin_allowed_scopes=["*"],
        origin_allowed_tenants=["default"],
        origin_entity_uri=sender_entity_uri,
    )
    return {"tombstone": rec.model_dump(), "origin": origin, "origin_sig": origin_sig}


def test_inbound_tombstone_lands_in_peer_ingest_tenant(
    fed_node: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An inbound tombstone from a peer pinned to 'tenant-a' is stored under
    'tenant-a' (NOT 'default'), so it cannot suppress a default-tenant fact and
    DOES suppress the matching tenant-a fact.
    """
    import asyncio

    from stigmem_node.federation import federation_pull

    entity = f"rtbf:entity:{uuid.uuid4()}"

    peer_node_id, peer_entity_uri, peer_priv, key_id = _bound_peer_for_pull(
        fed_node, ingest_tenant="tenant-a"
    )

    entry = _make_v2_tombstone_entry(
        entity,
        sender_node_id=peer_node_id,
        sender_entity_uri=peer_entity_uri,
        sender_priv=peer_priv,
        key_id=key_id,
    )
    tomb_id = entry["tombstone"]["id"]

    # Non-default pin requires the multi-tenant plugin to be honored.
    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: True)
    monkeypatch.setattr(
        federation_pull, "_make_pull_client", lambda: _StubClient([entry])
    )

    asyncio.run(federation_pull.pull_all_peers_once())

    conn = sqlite3.connect(fed_node.db_path)
    try:
        row = conn.execute(
            "SELECT tenant_id FROM tombstones WHERE id = ?", (tomb_id,)
        ).fetchone()
    finally:
        conn.close()
    assert row is not None, "inbound tombstone was not applied"
    assert row[0] == "tenant-a", f"expected tenant-a, got {row[0]!r}"


def _tombstone_plugin_manifest() -> Any:
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    plugin = importlib.import_module("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


def test_inbound_tombstone_does_not_retract_other_tenant_fact(
    fed_node: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An inbound tombstone for tenant-a does NOT suppress a default-tenant fact
    with the same entity (recall-time filter keys on (entity_uri, tenant_id))."""
    import asyncio

    from stigmem_node.federation import federation_pull
    from stigmem_node.lifecycle.tombstone_cache import invalidate, is_tombstoned

    entity = f"rtbf:shared:{uuid.uuid4()}"

    peer_node_id, peer_entity_uri, peer_priv, key_id = _bound_peer_for_pull(
        fed_node, ingest_tenant="tenant-a"
    )

    entry = _make_v2_tombstone_entry(
        entity,
        sender_node_id=peer_node_id,
        sender_entity_uri=peer_entity_uri,
        sender_priv=peer_priv,
        key_id=key_id,
    )

    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: True)
    monkeypatch.setattr(
        federation_pull, "_make_pull_client", lambda: _StubClient([entry])
    )

    # Enable the recall-time tombstone filter so is_tombstoned() is live.
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER", "true")
    with stigmem_plugins([_tombstone_plugin_manifest()]):
        asyncio.run(federation_pull.pull_all_peers_once())
        invalidate()

        # The tombstone suppresses the tenant-a entity but NOT the default-tenant one.
        assert is_tombstoned(entity, "tenant-a") is True
        assert is_tombstoned(entity, "default") is False
