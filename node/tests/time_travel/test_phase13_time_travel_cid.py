"""Phase 13 — Time-travel (as_of) and content-addressing (CID) conformance tests.

Covers spec §24 (time-travel) and §25 (content-addressing):

  CID:
    - Computation is deterministic across identical inputs
    - Different facts produce different CIDs
    - Assert path writes non-null cid to facts + fact_cid_aliases
    - GET /v1/facts/{sha256:...} resolves via alias table
    - POST /v1/facts/{id}/verify-cid: match, null stored, mismatch
    - GET /v1/admin/cid-backfill/status counts correctly

  Time-travel:
    - GET /v1/facts?as_of=T returns only facts timestamped <= T
    - Retracted facts (retracted_at <= T) excluded; active facts visible
    - expired facts (valid_until <= T) excluded
    - future as_of rejected 400
    - POST /v1/recall with as_of

  Tombstones + as_of:
    - Tombstoned entity suppressed retroactively even for as_of < tombstone.created_at
    - legal_hold=True: admin caller sees fact + tombstone_notice; non-admin silently excluded

  Backfill:
    - _cmd_backfill_cids idempotency (direct function test on raw DB)
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import sqlite3
import sys
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.cid import compute_cid, is_valid_cid
from stigmem_node.main import create_app
from stigmem_node.plugins import PluginContext, PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins

apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings
logger = logging.getLogger(__name__)
_TIME_TRAVEL_PLUGIN_SRC = (
    Path(__file__).resolve().parents[3]
    / "experimental"
    / "time-travel"
    / "src"
)
_TOMBSTONE_PLUGIN_SRC = (
    Path(__file__).resolve().parents[3] / "experimental" / "tombstones" / "src"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PATCHABLE = [
    "stigmem_node.federation_pull",
    "stigmem_node.peer_token",
    "stigmem_node.federation_ingest",
    "stigmem_node.routes.federation",
    "stigmem_node.routes.identity",
    "stigmem_node.identity.trust_store",
    "stigmem_node.decay",
    "stigmem_node.routes.decay",
    "stigmem_node.routes.lint",
    "stigmem_node.routes.synthesize",
    "stigmem_node.routes.recall",
    "stigmem_node.routes.cards",
    "stigmem_node.card_materializer",
    "stigmem_node.rate_limit",
]


def _patch_settings(test_settings: Settings) -> list:
    mods = []
    for name in _PATCHABLE:
        try:
            mod = importlib.import_module(name)
            mods.append(mod)
        except ImportError as exc:
            logger.debug("patchable module %s is unavailable in this test process: %s", name, exc)
            continue
    settings_module.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    for mod in mods:
        if hasattr(mod, "settings"):
            mod.settings = test_settings
    return mods


def _gen_test_private_key() -> str:
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    priv = Ed25519PrivateKey.generate()
    return (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )


def _restore_settings(original: Settings, mods: list) -> None:
    settings_module.settings = original  # type: ignore[assignment]
    auth_mod.settings = original  # type: ignore[assignment]
    db_mod.settings = original  # type: ignore[assignment]
    wk_mod.settings = original  # type: ignore[assignment]
    for mod in mods:
        if hasattr(mod, "settings"):
            mod.settings = original


def _time_travel_plugin_manifest() -> object:
    if str(_TIME_TRAVEL_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TIME_TRAVEL_PLUGIN_SRC))
    plugin = importlib.import_module("stigmem_plugin_time_travel")
    return plugin.plugin_manifest()


def _tombstone_plugin_manifest() -> object:
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    os.environ.setdefault("STIGMEM_TOMBSTONES_ENABLED", "true")
    os.environ.setdefault("STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER", "true")
    plugin = importlib.import_module("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


def _insert_tombstone(
    db_path: str,
    entity_uri: str,
    *,
    legal_hold: bool = False,
    scope: str = "*",
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO tombstones
               (id, entity_uri, scope, reason, signed_by, signature,
                created_at, legal_hold, tenant_id)
               VALUES (?, ?, ?, 'test', 'agent:admin', 'sig', ?, ?, 'default')""",
            (
                f"tomb_{uuid.uuid4().hex}",
                entity_uri,
                scope,
                datetime.now(UTC).isoformat(),
                1 if legal_hold else 0,
            ),
        )


@pytest.fixture()
def p13_client(tmp_path) -> Generator[TestClient, None, None]:
    """Unauthenticated TestClient on a fresh Phase-13 migrated DB."""
    db_file = str(tmp_path / "p13.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    _restore_settings(original, mods)


@pytest.fixture()
def p13_client_with_db(tmp_path) -> Generator[tuple[TestClient, str], None, None]:
    """Unauthenticated TestClient plus the SQLite DB path for direct tamper tests."""
    db_file = str(tmp_path / "p13_cid_read.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, db_file
    _restore_settings(original, mods)


@pytest.fixture()
def p13_time_travel_client(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    """Unauthenticated TestClient with the experimental time-travel plugin loaded."""
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ALLOW_FACT_QUERY_AS_OF", "true")
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ALLOW_RECALL_AS_OF", "true")
    db_file = str(tmp_path / "p13_time_travel.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
    _restore_settings(original, mods)


@pytest.fixture()
def p13_authed(tmp_path) -> Generator[tuple[TestClient, str, str], None, None]:
    """Auth-enabled TestClient; yields (client, agent_key, admin_key)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    db_file = str(tmp_path / "p13_auth.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    priv = Ed25519PrivateKey.generate()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    ts = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        node_private_key=priv_b64,
    )
    mods = _patch_settings(ts)
    agent_key = auth_mod.create_api_key("agent:test", ["read", "write"])
    admin_key = auth_mod.create_api_key("agent:admin", ["read", "write", "federate", "admin"])
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c, agent_key, admin_key
    _restore_settings(original, mods)


def _assert(
    client: TestClient,
    entity: str,
    relation: str,
    value: str,
    scope: str = "local",
    api_key: str | None = None,
    **kw,
) -> dict:
    body: dict = {
        "entity": entity,
        "relation": relation,
        "value": {"type": "string", "v": value},
        "source": "agent:test",
        "scope": scope,
        "confidence": 1.0,
        **kw,
    }
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    r = client.post("/v1/facts", json=body, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


def _insert_legacy_fact_row(
    db_path: str,
    *,
    fact_id: str,
    entity: str,
    relation: str,
    value: str,
    timestamp: str = "2026-05-17T00:00:00+00:00",
    scope: str = "local",
    cid: str | None = None,
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO facts "
            "(id, entity, relation, value_type, value_v, source, timestamp, "
            "confidence, scope, tenant_id, cid) "
            "VALUES (?, ?, ?, 'string', ?, 'agent:test', ?, 1.0, ?, 'default', ?)",
            (fact_id, entity, relation, value, timestamp, scope, cid),
        )


def _tamper_fact_value_after_admin_bypass(db_path: str, fact_id: str, value: str) -> None:
    """Simulate an admin-level store mutation that bypasses L2 SQLite triggers."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TRIGGER IF EXISTS facts_no_update")
        conn.execute("DROP TRIGGER IF EXISTS facts_fts_au")
        conn.execute("UPDATE facts SET value_v = ? WHERE id = ?", (value, fact_id))


# ---------------------------------------------------------------------------
# CID computation unit tests
# ---------------------------------------------------------------------------


def test_cid_format():
    cid = compute_cid("ent:a", "rel:b", "string", "hello", "agent:s", "local")
    assert cid.startswith("sha256:")
    assert is_valid_cid(cid)
    assert len(cid) == len("sha256:") + 64


def test_cid_determinism():
    c1 = compute_cid("ent:x", "rel:y", "string", "val", "src:z", "team")
    c2 = compute_cid("ent:x", "rel:y", "string", "val", "src:z", "team")
    assert c1 == c2


def test_cid_field_sensitivity():
    base = compute_cid("ent:x", "rel:y", "string", "val", "src:z", "team")
    assert compute_cid("ent:X", "rel:y", "string", "val", "src:z", "team") != base  # entity
    assert compute_cid("ent:x", "rel:Y", "string", "val", "src:z", "team") != base  # relation
    assert compute_cid("ent:x", "rel:y", "text", "val", "src:z", "team") != base  # value_type
    assert compute_cid("ent:x", "rel:y", "string", "VAL", "src:z", "team") != base  # value_v
    assert compute_cid("ent:x", "rel:y", "string", "val", "src:other", "team") != base  # source
    assert compute_cid("ent:x", "rel:y", "string", "val", "src:z", "local") != base  # scope


def test_cid_canonical_key_order():
    """CID must not change if we compute it via an independent reference implementation."""
    body = {
        "confidence": 1.0,
        "entity": "stigmem://a/b/1",
        "interpret_as": "content",
        "relation": "test:value",
        "scope": "local",
        "source": "agent:ci",
        "value_type": "string",
        "value_v": "hello",
    }
    # Independent: sort_keys + compact separators + utf-8, no ASCII escaping (CID v2 — 8 fields incl interpret_as)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    expected = "sha256:" + hashlib.sha256(canonical).hexdigest()
    actual = compute_cid(
        entity=body["entity"],
        relation=body["relation"],
        value_type=body["value_type"],
        value_v=body["value_v"],
        source=body["source"],
        scope=body["scope"],
        confidence=body["confidence"],
    )
    assert actual == expected


# ---------------------------------------------------------------------------
# Write path: facts.cid column + fact_cid_aliases populated
# ---------------------------------------------------------------------------


def test_assert_fact_stores_cid(p13_client: TestClient):
    f = _assert(p13_client, "stigmem://e/1", "rel:x", "alpha")
    assert f["cid"] is not None
    assert is_valid_cid(f["cid"])

    expected = compute_cid(
        entity=f["entity"],
        relation=f["relation"],
        value_type="string",
        value_v="alpha",
        source=f["source"],
        scope=f["scope"],
    )
    assert f["cid"] == expected


def test_assert_fact_creates_alias_row(tmp_path):
    """fact_cid_aliases must contain a row for every locally-asserted fact."""
    db_file = str(tmp_path / "alias_check.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        f = _assert(c, "stigmem://e/alias", "rel:p", "qwerty")
    _restore_settings(original, mods)

    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM fact_cid_aliases WHERE fact_id = ?", (f["id"],)).fetchone()
    assert row is not None
    assert row["cid"] == f["cid"]
    conn.close()


# ---------------------------------------------------------------------------
# CID-based lookup  GET /v1/facts/{sha256:...}
# ---------------------------------------------------------------------------


def test_get_fact_by_cid(p13_client: TestClient):
    f = _assert(p13_client, "stigmem://e/2", "rel:lookup", "data")
    cid = f["cid"]
    assert cid is not None

    r = p13_client.get(f"/v1/facts/{cid}")
    assert r.status_code == 200
    got = r.json()
    assert got["id"] == f["id"]
    assert got["cid"] == cid


def test_get_fact_by_cid_not_found(p13_client: TestClient):
    # sha256: prefix with valid format but nonexistent
    fake = "sha256:" + "a" * 64
    r = p13_client.get(f"/v1/facts/{fake}")
    assert r.status_code == 404


def test_get_fact_by_cid_malformed(p13_client: TestClient):
    r = p13_client.get("/v1/facts/sha256:tooshort")
    assert r.status_code == 400
    assert "cid_malformed" in r.text


def test_get_fact_rejects_cid_mismatch_on_read_path(
    p13_client_with_db: tuple[TestClient, str],
) -> None:
    client, db_path = p13_client_with_db
    fact = _assert(client, "stigmem://e/cid-read-mismatch", "rel", "original")

    _tamper_fact_value_after_admin_bypass(db_path, fact["id"], "tampered")

    response = client.get(f"/v1/facts/{fact['id']}")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "cid_mismatch"
    assert detail["fact_id"] == fact["id"]
    assert detail["stored_cid"] == fact["cid"]
    assert detail["computed_cid"] != fact["cid"]


def test_query_facts_rejects_cid_mismatch_on_read_path(
    p13_client_with_db: tuple[TestClient, str],
) -> None:
    client, db_path = p13_client_with_db
    fact = _assert(client, "stigmem://e/cid-query-mismatch", "rel", "original")

    _tamper_fact_value_after_admin_bypass(db_path, fact["id"], "tampered")

    response = client.get("/v1/facts", params={"entity": "stigmem://e/cid-query-mismatch"})
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "cid_mismatch"
    assert detail["fact_id"] == fact["id"]


def test_recall_rejects_cid_mismatch_during_hydration(
    p13_client_with_db: tuple[TestClient, str],
) -> None:
    client, db_path = p13_client_with_db
    fact = _assert(client, "stigmem://e/cid-recall-mismatch", "rel", "original")

    _tamper_fact_value_after_admin_bypass(db_path, fact["id"], "tampered")

    response = client.post(
        "/v1/recall",
        json={
            "query": "cid-recall-mismatch",
            "scope": "local",
            "limit": 5,
            "weights": {"lexical": 1.0, "semantic": 0.0, "graph": 0.0},
        },
    )
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "cid_mismatch"
    assert detail["fact_id"] == fact["id"]


# ---------------------------------------------------------------------------
# POST /v1/facts/{id}/verify-cid
# ---------------------------------------------------------------------------


def test_verify_cid_valid(p13_client: TestClient):
    f = _assert(p13_client, "stigmem://e/3", "rel:verify", "check")
    r = p13_client.post(f"/v1/facts/{f['id']}/verify-cid")
    assert r.status_code == 200
    body = r.json()
    assert body["cid_valid"] is True
    assert body["computed_cid"] == f["cid"]
    assert body["stored_cid"] == f["cid"]
    assert body["mismatch_reason"] is None


def test_verify_cid_null_stored(tmp_path):
    """Facts with NULL stored cid return cid_valid=False + descriptive reason."""
    db_file = str(tmp_path / "null_cid.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    app = create_app()
    fid = f"legacy-null-cid-{uuid.uuid4()}"
    _insert_legacy_fact_row(
        db_file,
        fact_id=fid,
        entity="stigmem://e/null_cid",
        relation="rel:old",
        value="legacy",
    )
    with TestClient(app, raise_server_exceptions=True) as c:
        r = c.post(f"/v1/facts/{fid}/verify-cid")
    _restore_settings(original, mods)

    assert r.status_code == 200
    body = r.json()
    assert body["cid_valid"] is False
    assert body["stored_cid"] is None
    assert (
        "null" in body["mismatch_reason"].lower() or "backfill" in body["mismatch_reason"].lower()
    )


def test_verify_cid_not_found(p13_client: TestClient):
    r = p13_client.post(f"/v1/facts/{uuid.uuid4()}/verify-cid")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# GET /v1/admin/cid-backfill/status
# ---------------------------------------------------------------------------


def test_backfill_status_all_backfilled(p13_client: TestClient):
    _assert(p13_client, "stigmem://e/bs1", "rel:a", "v1")
    _assert(p13_client, "stigmem://e/bs2", "rel:a", "v2")
    r = p13_client.get("/v1/admin/cid-backfill/status")
    assert r.status_code == 200
    body = r.json()
    assert body["total_facts"] >= 2
    # Every newly asserted fact should have a CID — pending should be 0
    assert body["pending_facts"] == 0
    assert body["backfill_complete"] is True


def test_backfill_status_pending(tmp_path):
    """Insert a legacy cid-null fact to simulate a pre-Phase-13 row."""
    db_file = str(tmp_path / "pending_cid.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    app = create_app()
    _insert_legacy_fact_row(
        db_file,
        fact_id=f"legacy-pending-{uuid.uuid4()}",
        entity="stigmem://e/pending",
        relation="rel:p",
        value="pv",
    )
    with TestClient(app, raise_server_exceptions=True) as c:
        r = c.get("/v1/admin/cid-backfill/status")
    _restore_settings(original, mods)

    assert r.status_code == 200
    body = r.json()
    assert body["pending_facts"] >= 1
    assert body["backfill_complete"] is False


# ---------------------------------------------------------------------------
# Time-travel: GET /v1/facts?as_of=T
# ---------------------------------------------------------------------------


def _ts(offset_seconds: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


def test_as_of_default_install_requires_time_travel_plugin(p13_client: TestClient):
    r_facts = p13_client.get("/v1/facts", params={"as_of": _ts(-1)})
    assert r_facts.status_code == 501
    assert r_facts.json()["detail"]["code"] == "time_travel_plugin_not_loaded"

    r_recall = p13_client.post(
        "/v1/recall",
        json={"query": "snapshot content", "scope": "local", "as_of": _ts(-1)},
    )
    assert r_recall.status_code == 501
    assert r_recall.json()["detail"]["code"] == "time_travel_plugin_not_loaded"


def test_as_of_basic(p13_time_travel_client: TestClient):
    before = _ts(-2)
    f = _assert(p13_time_travel_client, "stigmem://tt/1", "rel:tt", "snap")
    after = _ts(2)

    # as_of after the fact was written: should see it
    r = p13_time_travel_client.get(
        "/v1/facts", params={"as_of": after, "entity": "stigmem://tt/1"}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()["facts"]]
    assert f["id"] in ids

    # as_of before the fact was written: should NOT see it
    r2 = p13_time_travel_client.get(
        "/v1/facts", params={"as_of": before, "entity": "stigmem://tt/1"}
    )
    assert r2.status_code == 200
    ids2 = [x["id"] for x in r2.json()["facts"]]
    assert f["id"] not in ids2


def test_as_of_retracted_fact_excluded(tmp_path):
    """A fact retracted at T is invisible for as_of >= T but visible before T."""
    db_file = str(tmp_path / "retract_asof.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts)
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            fact_id = f"retract-asof-{uuid.uuid4()}"
            fact_ts = _ts(-10)
            retract_at = _ts(-5)  # retracted 5 seconds ago
            before = _ts(-7)  # 7 seconds ago: fact existed, no retraction yet
            after_retract = _ts(-3)  # 3 seconds ago: retraction already applied
            _insert_legacy_fact_row(
                db_file,
                fact_id=fact_id,
                entity="stigmem://tt/ret1",
                relation="rel:retract",
                value="will_be_retracted",
                timestamp=fact_ts,
            )

            conn = sqlite3.connect(db_file)
            conn.execute(
                "INSERT INTO fact_retractions (id, fact_id, retracted_by, retracted_at)"
                " VALUES (?, ?, ?, ?)",
                (str(uuid.uuid4()), fact_id, "agent:test", retract_at),
            )
            conn.commit()
            conn.close()

            # as_of before retraction: visible (fact existed at -7s, retracted at -5s)
            r_before = c.get(
                "/v1/facts", params={"as_of": before, "entity": "stigmem://tt/ret1"}
            )
            assert r_before.status_code == 200
            ids_before = [x["id"] for x in r_before.json()["facts"]]
            assert fact_id in ids_before

            # as_of after retraction: suppressed (retraction applied at -5s)
            r_after = c.get(
                "/v1/facts",
                params={"as_of": after_retract, "entity": "stigmem://tt/ret1"},
            )
            assert r_after.status_code == 200
            ids_after = [x["id"] for x in r_after.json()["facts"]]
            assert fact_id not in ids_after

    _restore_settings(original, mods)


def test_as_of_expired_fact_excluded(p13_time_travel_client: TestClient):
    valid_until = _ts(-1)  # already expired
    f = _assert(
        p13_time_travel_client,
        "stigmem://tt/exp1",
        "rel:expires",
        "ephemeral",
        valid_until=valid_until,
    )
    r = p13_time_travel_client.get(
        "/v1/facts", params={"as_of": _ts(0), "entity": "stigmem://tt/exp1"}
    )
    assert r.status_code == 200
    ids = [x["id"] for x in r.json()["facts"]]
    assert f["id"] not in ids


def test_as_of_query_rejects_cid_mismatch_on_historical_read(tmp_path):
    """as_of fact queries must fail closed when a historical row has been tampered."""
    db_file = str(tmp_path / "asof_cid_mismatch.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            fact_id = f"asof-cid-mismatch-{uuid.uuid4()}"
            _insert_legacy_fact_row(
                db_file,
                fact_id=fact_id,
                entity="stigmem://tt/cid-mismatch",
                relation="rel:cid",
                value="original",
                timestamp=_ts(-10),
                cid=compute_cid(
                    "stigmem://tt/cid-mismatch",
                    "rel:cid",
                    "string",
                    "original",
                    "agent:test",
                    "local",
                ),
            )
            _tamper_fact_value_after_admin_bypass(db_file, fact_id, "tampered")

            response = c.get(
                "/v1/facts",
                params={"as_of": _ts(-1), "entity": "stigmem://tt/cid-mismatch"},
            )

    _restore_settings(original, mods)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "cid_mismatch"


def test_as_of_future_rejected(p13_time_travel_client: TestClient):
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    r = p13_time_travel_client.get("/v1/facts", params={"as_of": future})
    assert r.status_code == 400
    assert "as_of_future" in r.text or "future" in r.text.lower()


def test_as_of_invalid_ts_rejected(p13_time_travel_client: TestClient):
    r = p13_time_travel_client.get("/v1/facts", params={"as_of": "not-a-date"})
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Time-travel with tombstones
# ---------------------------------------------------------------------------


def test_as_of_tombstone_retroactive_suppression(tmp_path):
    """Tombstoned entity must be excluded even for as_of before tombstone.created_at."""
    db_file = str(tmp_path / "tomb_asof.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        node_private_key=_gen_test_private_key(),
    )
    mods = _patch_settings(ts_settings)
    agent_key = auth_mod.create_api_key("agent:user", ["read", "write"])
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            pre_fact = (datetime.now(UTC) - timedelta(seconds=5)).isoformat()
            fact_id = f"tomb-asof-{uuid.uuid4()}"
            _insert_legacy_fact_row(
                db_file,
                fact_id=fact_id,
                entity="stigmem://rtbf/user1",
                relation="rel:name",
                value="Alice",
                timestamp=pre_fact,
            )

            _insert_tombstone(db_file, "stigmem://rtbf/user1")

            # as_of after the fact but before the tombstone should still suppress the fact.
            before_tombstone = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
            r = c.get(
                "/v1/facts",
                params={"as_of": before_tombstone, "entity": "stigmem://rtbf/user1"},
                headers={"Authorization": f"Bearer {agent_key}"},
            )
            assert r.status_code == 200
            assert r.json()["facts"] == []

    _restore_settings(original, mods)


def test_as_of_legal_hold_admin_sees_notice(tmp_path):
    """Admin caller receives tombstone_notices for legal_hold entities."""
    db_file = str(tmp_path / "lh_asof.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        node_private_key=_gen_test_private_key(),
    )
    mods = _patch_settings(ts_settings)
    admin_key = auth_mod.create_api_key("agent:admin", ["read", "write", "federate", "admin"])
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            f = _assert(
                c,
                "stigmem://rtbf/legal1",
                "rel:value",
                "sensitive",
                scope="local",
                api_key=admin_key,
            )
            _insert_tombstone(db_file, "stigmem://rtbf/legal1", legal_hold=True)

            # Admin as_of query: fact still returned with tombstone_notice
            r = c.get(
                "/v1/facts",
                params={"as_of": _ts(2), "entity": "stigmem://rtbf/legal1"},
                headers={"Authorization": f"Bearer {admin_key}"},
            )
            assert r.status_code == 200
            body = r.json()
            ids = [x["id"] for x in body["facts"]]
            assert f["id"] in ids
            notices = body.get("tombstone_notices", [])
            assert any(n["entity_uri"] == "stigmem://rtbf/legal1" for n in notices)
            assert any(n["legal_hold"] for n in notices)

    _restore_settings(original, mods)


def test_as_of_legal_hold_non_admin_excluded(tmp_path):
    """Non-admin caller silently gets empty results for legal_hold entities."""
    db_file = str(tmp_path / "lh_excl.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        node_private_key=_gen_test_private_key(),
    )
    mods = _patch_settings(ts_settings)
    admin_key = auth_mod.create_api_key("agent:admin", ["read", "write", "federate", "admin"])
    agent_key = auth_mod.create_api_key("agent:user", ["read", "write"])
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            _assert(
                c,
                "stigmem://rtbf/legal2",
                "rel:val",
                "sensitive",
                scope="local",
                api_key=admin_key,
            )
            _insert_tombstone(db_file, "stigmem://rtbf/legal2", legal_hold=True)
            # Non-admin as_of: silently empty, no error, no notices
            r = c.get(
                "/v1/facts",
                params={"as_of": _ts(2), "entity": "stigmem://rtbf/legal2"},
                headers={"Authorization": f"Bearer {agent_key}"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["facts"] == []
            assert body.get("tombstone_notices", []) == []

    _restore_settings(original, mods)


def test_as_of_legal_hold_non_admin_matches_non_legal_hold_suppression(tmp_path):
    """Agent callers must not distinguish legal hold from ordinary tombstone absence."""
    db_file = str(tmp_path / "lh_oracle.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        node_private_key=_gen_test_private_key(),
    )
    mods = _patch_settings(ts_settings)
    agent_key = auth_mod.create_api_key("agent:user", ["read", "write"])
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            for entity in ("stigmem://rtbf/legal-oracle", "stigmem://rtbf/plain-oracle"):
                _insert_legacy_fact_row(
                    db_file,
                    fact_id=f"oracle-{uuid.uuid4()}",
                    entity=entity,
                    relation="rel:val",
                    value="sensitive",
                    timestamp=_ts(-30),
                )
            as_of_before_tombstones = _ts(-20)
            _insert_tombstone(db_file, "stigmem://rtbf/legal-oracle", legal_hold=True)
            _insert_tombstone(db_file, "stigmem://rtbf/plain-oracle", legal_hold=False)

            legal_response = c.get(
                "/v1/facts",
                params={"as_of": as_of_before_tombstones, "entity": "stigmem://rtbf/legal-oracle"},
                headers={"Authorization": f"Bearer {agent_key}"},
            )
            plain_response = c.get(
                "/v1/facts",
                params={"as_of": as_of_before_tombstones, "entity": "stigmem://rtbf/plain-oracle"},
                headers={"Authorization": f"Bearer {agent_key}"},
            )

    _restore_settings(original, mods)
    assert legal_response.status_code == 200
    assert plain_response.status_code == 200
    legal_body = legal_response.json()
    plain_body = plain_response.json()
    assert legal_body["facts"] == plain_body["facts"] == []
    assert legal_body["total"] is plain_body["total"] is None
    assert legal_body.get("tombstone_notices", []) == plain_body.get("tombstone_notices", []) == []
    assert "x-total-count" not in legal_response.headers
    assert "x-total-count" not in plain_response.headers


# ---------------------------------------------------------------------------
# POST /v1/recall with as_of
# ---------------------------------------------------------------------------


def test_recall_as_of(p13_time_travel_client: TestClient):
    before = _ts(-2)
    _assert(p13_time_travel_client, "stigmem://recall/e1", "rel:bio", "snapshot content")
    after = _ts(1)

    # as_of after write: recall should surface the fact
    r_after = p13_time_travel_client.post(
        "/v1/recall",
        json={"query": "snapshot content", "scope": "local", "as_of": after},
    )
    assert r_after.status_code == 200

    # as_of before write: recall should NOT surface the fact
    r_before = p13_time_travel_client.post(
        "/v1/recall",
        json={"query": "snapshot content", "scope": "local", "as_of": before},
    )
    assert r_before.status_code == 200
    results_before = r_before.json().get("facts", [])
    ids_before = [x["id"] for x in results_before]
    # The fact was asserted AFTER `before`, so must not appear
    for f_check in p13_time_travel_client.get(
        "/v1/facts", params={"entity": "stigmem://recall/e1"}
    ).json()["facts"]:
        assert f_check["id"] not in ids_before


def test_recall_as_of_non_legal_tombstone_retroactive_suppression(tmp_path):
    """Recall as_of must suppress ordinary tombstones even before tombstone creation."""
    db_file = str(tmp_path / "recall_plain_tombstone.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            fact_id = f"recall-plain-tombstone-{uuid.uuid4()}"
            _insert_legacy_fact_row(
                db_file,
                fact_id=fact_id,
                entity="stigmem://recall/plain-tombstone",
                relation="rel:history",
                value="retroactive suppression marker",
                timestamp=_ts(-30),
            )
            as_of_before_tombstone = _ts(-20)
            _insert_tombstone(db_file, "stigmem://recall/plain-tombstone", legal_hold=False)

            response = c.post(
                "/v1/recall",
                json={
                    "query": "retroactive suppression marker",
                    "scope": "local",
                    "as_of": as_of_before_tombstone,
                    "max_chunks": 10,
                },
            )

    _restore_settings(original, mods)
    assert response.status_code == 200
    body = response.json()
    returned_ids = {item["fact"]["id"] for item in body["facts"]}
    assert fact_id not in returned_ids
    assert body["tombstone_notices"] == []
    assert body["total_scored"] is None


def test_recall_as_of_retention_floor_rejected(tmp_path):
    """Recall uses the same as_of_before_retention_floor contract as fact queries."""
    db_file = str(tmp_path / "recall_retention_floor.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    floor = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    too_old = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    ts_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        as_of_retention_floor=floor,
    )
    mods = _patch_settings(ts_settings)
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            response = c.post(
                "/v1/recall",
                json={"query": "historical", "scope": "local", "as_of": too_old},
            )

    _restore_settings(original, mods)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "as_of_before_retention_floor"


def test_recall_as_of_scores_recency_relative_to_requested_timestamp(tmp_path):
    """Historical recall recency is computed against as_of, not wall-clock now."""
    db_file = str(tmp_path / "recall_asof_scoring.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    as_of_dt = datetime.now(UTC) - timedelta(days=1)
    older_ts = (as_of_dt - timedelta(days=120)).isoformat()
    newer_ts = (as_of_dt - timedelta(days=10)).isoformat()
    with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            older_id = f"recall-asof-older-{uuid.uuid4()}"
            newer_id = f"recall-asof-newer-{uuid.uuid4()}"
            _insert_legacy_fact_row(
                db_file,
                fact_id=older_id,
                entity="stigmem://recall/older",
                relation="rel:history",
                value="historical anchor",
                timestamp=older_ts,
            )
            _insert_legacy_fact_row(
                db_file,
                fact_id=newer_id,
                entity="stigmem://recall/newer",
                relation="rel:history",
                value="historical anchor",
                timestamp=newer_ts,
            )

            response = c.post(
                "/v1/recall",
                json={
                    "query": "historical anchor",
                    "scope": "local",
                    "as_of": as_of_dt.isoformat(),
                    "weights": {"lexical": 1.0, "recency": 1.0},
                    "max_chunks": 10,
                },
            )

    _restore_settings(original, mods)
    assert response.status_code == 200
    scored = {item["fact"]["id"]: item for item in response.json()["facts"]}
    assert {older_id, newer_id}.issubset(scored)
    assert (
        scored[newer_id]["score_breakdown"]["recency"]
        > scored[older_id]["score_breakdown"]["recency"]
    )
    assert scored[newer_id]["score"] > scored[older_id]["score"]


def test_recall_rank_hooks_only_receive_historically_visible_facts(tmp_path):
    """Source-trust-style rank deltas cannot resurrect facts after the as_of visibility cut."""
    db_file = str(tmp_path / "recall_rank_visibility.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    as_of = _ts(-20)
    visible_id = f"visible-rank-{uuid.uuid4()}"
    future_id = f"future-rank-{uuid.uuid4()}"
    seen_by_rank_hook: list[str] = []

    def rank(
        _ctx: PluginContext,
        scored_results: list[object],
        **_: object,
    ) -> dict[str, float]:
        ids = [result.fact.id for result in scored_results if hasattr(result, "fact")]
        seen_by_rank_hook.extend(ids)
        return {fact_id: 100.0 for fact_id in ids}

    trust_rank_manifest = PluginManifest(
        name="source-trust-as-of-visibility-test",
        version="1.0.0",
        hooks={"recall_rank": rank},
    )
    with stigmem_plugins(
        [_time_travel_plugin_manifest(), _tombstone_plugin_manifest(), trust_rank_manifest]
    ):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            _insert_legacy_fact_row(
                db_file,
                fact_id=visible_id,
                entity="stigmem://recall/visible-rank",
                relation="rel:history",
                value="ranked historical fact",
                timestamp=_ts(-30),
            )
            _insert_legacy_fact_row(
                db_file,
                fact_id=future_id,
                entity="stigmem://recall/future-rank",
                relation="rel:history",
                value="ranked historical fact",
                timestamp=_ts(-10),
            )

            response = c.post(
                "/v1/recall",
                json={
                    "query": "ranked historical",
                    "scope": "local",
                    "as_of": as_of,
                    "max_chunks": 10,
                },
            )

    _restore_settings(original, mods)
    assert response.status_code == 200
    returned_ids = {item["fact"]["id"] for item in response.json()["facts"]}
    assert visible_id in returned_ids
    assert future_id not in returned_ids
    assert visible_id in seen_by_rank_hook
    assert future_id not in seen_by_rank_hook


def test_recall_as_of_rejects_cid_mismatch_before_ranking(tmp_path):
    """Tampered historical rows fail CID validation before recall ranking can score them."""
    db_file = str(tmp_path / "recall_asof_cid_mismatch.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    rank_seen = False

    def rank(
        _ctx: PluginContext,
        scored_results: list[object],
        **_: object,
    ) -> dict[str, float]:
        nonlocal rank_seen
        rank_seen = True
        return {}

    trust_rank_manifest = PluginManifest(
        name="source-trust-as-of-cid-test",
        version="1.0.0",
        hooks={"recall_rank": rank},
    )
    with stigmem_plugins(
        [_time_travel_plugin_manifest(), _tombstone_plugin_manifest(), trust_rank_manifest]
    ):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            fact_id = f"recall-asof-cid-mismatch-{uuid.uuid4()}"
            _insert_legacy_fact_row(
                db_file,
                fact_id=fact_id,
                entity="stigmem://recall/cid-mismatch",
                relation="rel:cid",
                value="original recall value",
                timestamp=_ts(-10),
                cid=compute_cid(
                    "stigmem://recall/cid-mismatch",
                    "rel:cid",
                    "string",
                    "original recall value",
                    "agent:test",
                    "local",
                ),
            )
            _tamper_fact_value_after_admin_bypass(db_file, fact_id, "tampered recall value")

            response = c.post(
                "/v1/recall",
                json={
                    "query": "recall value",
                    "scope": "local",
                    "as_of": _ts(-1),
                },
            )

    _restore_settings(original, mods)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "cid_mismatch"
    assert rank_seen is False


# ---------------------------------------------------------------------------
# Backfill CLI idempotency (direct function test)
# ---------------------------------------------------------------------------


def test_backfill_cids_idempotent(tmp_path):
    """_cmd_backfill_cids must be callable twice with the same outcome."""
    from stigmem_node.cli import _cmd_backfill_cids

    db_file = str(tmp_path / "backfill.db")
    apply_migrations(db_path=db_file)
    original = settings_module.settings
    ts_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    mods = _patch_settings(ts_settings)
    _insert_legacy_fact_row(
        db_file,
        fact_id=f"legacy-bf-1-{uuid.uuid4()}",
        entity="stigmem://bf/e1",
        relation="rel:bf",
        value="v1",
    )
    _insert_legacy_fact_row(
        db_file,
        fact_id=f"legacy-bf-2-{uuid.uuid4()}",
        entity="stigmem://bf/e2",
        relation="rel:bf",
        value="v2",
    )

    # First backfill run
    class _Args:
        db = db_file
        batch_size = 100
        quiet = True

    _cmd_backfill_cids(_Args())

    # Verify CIDs were projected through aliases/backfill rows. The base facts
    # table remains immutable, so facts.cid stays null for these legacy rows.
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    null_count = conn.execute("SELECT COUNT(*) FROM facts WHERE cid IS NULL").fetchone()[0]
    alias_count = conn.execute("SELECT COUNT(*) FROM fact_cid_aliases").fetchone()[0]
    fact_count = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
    complete_count = conn.execute(
        "SELECT COUNT(*) FROM fact_cid_backfill WHERE status = 'complete'"
    ).fetchone()[0]
    conn.close()
    assert null_count == fact_count
    assert alias_count >= 2  # at least one per user fact (conflict/meta facts may lack aliases)
    assert complete_count == fact_count

    # Second backfill run must be idempotent (no errors, same counts)
    _cmd_backfill_cids(_Args())

    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    null_count2 = conn.execute("SELECT COUNT(*) FROM facts WHERE cid IS NULL").fetchone()[0]
    alias_count2 = conn.execute("SELECT COUNT(*) FROM fact_cid_aliases").fetchone()[0]
    complete_count2 = conn.execute(
        "SELECT COUNT(*) FROM fact_cid_backfill WHERE status = 'complete'"
    ).fetchone()[0]
    conn.close()
    assert null_count2 == fact_count
    assert alias_count2 == alias_count
    assert complete_count2 == complete_count

    _restore_settings(original, mods)
