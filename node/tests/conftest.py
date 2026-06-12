"""Test fixtures for the Stigmem reference node."""

from __future__ import annotations

import base64
import contextlib
import importlib
import json
import logging
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import NamedTuple

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.routes.wellknown as wk_mod
import stigmem_node.settings as settings_module
from stigmem_node.main import create_app
from stigmem_node.plugins.manifest import PluginManifest
from stigmem_node.plugins.testing import stigmem_plugins

logger = logging.getLogger(__name__)

create_api_key = auth_mod.create_api_key
apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings

# Path to migrations/ directory — used when building libSQL test databases.
_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
_TIME_TRAVEL_PLUGIN_SRC = (
    Path(__file__).resolve().parents[2] / "experimental" / "time-travel" / "src"
)
_TOMBSTONE_PLUGIN_SRC = (
    Path(__file__).resolve().parents[2] / "experimental" / "tombstones" / "src"
)


@pytest.fixture(autouse=True)
def _allow_unsigned_plugin_test_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings_module.settings,
        "plugin_unsigned_ack",
        "i-understand-plugins-are-unsigned",
    )


@pytest.fixture(autouse=True)
def _isolate_entry_point_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_lifecycle = importlib.import_module("stigmem_node.plugins.lifecycle")
    monkeypatch.setattr(plugin_lifecycle, "discover_plugin_manifests", lambda: ())


# ---------------------------------------------------------------------------
# Backend selection CLI option (Phase 8 — multi-backend conformance)
# ---------------------------------------------------------------------------


_ENCRYPT_PASSPHRASE_ENV = "_STIGMEM_TEST_PASSPHRASE"
_ENCRYPT_PASSPHRASE = "ci-test-passphrase-not-for-production-use"


def pytest_addoption(parser: pytest.Parser) -> None:  # type: ignore[name-defined]
    parser.addoption(
        "--backend",
        default="sqlite",
        choices=["sqlite", "libsql", "postgres"],
        help="Storage backend to test against (default: sqlite)",
    )
    parser.addoption(
        "--encrypt",
        default="off",
        choices=["off", "on"],
        help="Run conformance suite against encrypted storage (default: off)",
    )


@pytest.fixture()
def backend(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--backend")  # type: ignore[no-any-return]


@pytest.fixture()
def encrypt(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--encrypt")  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def _encryption_env(encrypt: str, monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Set test passphrase env var and flush key cache when --encrypt=on."""
    if encrypt == "on":
        from stigmem_node.storage.encryption import _reset_key_cache

        monkeypatch.setenv(_ENCRYPT_PASSPHRASE_ENV, _ENCRYPT_PASSPHRASE)
        _reset_key_cache()
        yield
        _reset_key_cache()
    else:
        yield


@pytest.fixture(autouse=True)
def _reset_tombstone_cache() -> Generator[None, None, None]:
    """Reset the process-global tombstone cache around every test.

    ``stigmem_node.lifecycle.tombstone_cache`` refreshes from the DB at most once
    per 60 s (monotonic) and keeps its set in a module-global ``_state``. Across
    the in-process test suite that means a test which warms the cache leaks its
    tombstone set into later tests that share the process but use a *different*
    ``tmp_db`` — intermittently suppressing subscription delivery (an event whose
    entity appears tombstoned in the stale set is dropped, so ``post`` is never
    called). Per-test ``invalidate()`` guards added in #604 were lost when the
    tests were reorganized (#466); resetting here is reorg-proof and keeps every
    test reading tombstones from its own DB.
    """
    from stigmem_node.lifecycle import tombstone_cache

    tombstone_cache.invalidate()
    yield
    tombstone_cache.invalidate()


@pytest.fixture(autouse=True)
def _drain_subscription_delivery_lock() -> Generator[None, None, None]:
    """Guarantee the process-global subscription-delivery lock is free per test.

    ``subscription_delivery.deliver_pending()`` acquires ``_DELIVER_PENDING_LOCK``
    non-blocking and SKIPS (no delivery, no failure recorded) when it is already
    held — the #47 concurrency guard against double-delivery. A test that runs the
    background ``sweep_loop`` (``test_subscription_delivery_race`` sets ``sweep_s=0``)
    can leave an in-flight ``deliver_pending()`` *thread* holding the lock after its
    asyncio task is cancelled: ``task.cancel()`` cancels the awaiting coroutine, not
    the OS thread ``asyncio.to_thread`` already launched. If that holder overlaps a
    later test's explicit ``deliver_pending()`` call, the call silently no-ops —
    intermittently breaking ``test_circuit_breaker_opens_after_threshold`` (a delivery
    that should fail is skipped, so ``consecutive_failures`` never reaches the circuit
    threshold and ``circuit_open`` stays 0). Draining here — wait for any leaked holder
    to finish, then release — makes every test start with a free lock. Reorg-proof,
    like the tombstone-cache reset above.
    """
    from stigmem_node import subscription_delivery as _sd

    if _sd._DELIVER_PENDING_LOCK.acquire(timeout=10):
        _sd._DELIVER_PENDING_LOCK.release()
    yield


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    """Return (pub_b64url, priv_b64url) for a fresh Ed25519 keypair."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return pub_b64, priv_b64


def sign_declaration(priv_b64: str, signed_fields: dict) -> str:
    """Sign a PeerDeclaration canonical JSON blob (spec §6.1)."""
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    canonical = json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(privkey.sign(canonical)).decode().rstrip("=")


def make_peer_token(
    priv_b64: str,
    iss: str,
    sub: str,
    scopes: list[str],
    ttl_ms: int = 3_600_000,
    nonce: str | None = None,
    offset_ms: int = 0,
) -> str:
    """Mint an Ed25519-signed peer JWT (spec §3.5)."""
    import jwt

    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    now_ms = int(time.time() * 1000) + offset_ms
    payload = {
        "iss": iss,
        "sub": sub,
        "iat": now_ms,
        "exp": now_ms + ttl_ms,
        "nonce": nonce or str(uuid.uuid4()),
        "scopes": scopes,
    }
    return jwt.encode(payload, privkey, algorithm="EdDSA")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Settings patching helpers
# ---------------------------------------------------------------------------

_PATCHABLE_MODULES = [
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


def _get_extra_modules():
    mods = []
    for name in _PATCHABLE_MODULES:
        with contextlib.suppress(ImportError):
            mods.append(importlib.import_module(name))
    return mods


def _patch_settings(test_settings: Settings) -> list:
    extra = _get_extra_modules()
    settings_module.settings = test_settings  # type: ignore[assignment]
    auth_mod.settings = test_settings  # type: ignore[assignment]
    db_mod.settings = test_settings  # type: ignore[assignment]
    wk_mod.settings = test_settings  # type: ignore[assignment]
    for mod in extra:
        if hasattr(mod, "settings"):
            mod.settings = test_settings
    return extra


def _restore_settings(original: Settings, extra: list) -> None:
    settings_module.settings = original  # type: ignore[assignment]
    auth_mod.settings = original  # type: ignore[assignment]
    db_mod.settings = original  # type: ignore[assignment]
    wk_mod.settings = original  # type: ignore[assignment]
    for mod in extra:
        if hasattr(mod, "settings"):
            mod.settings = original


# ---------------------------------------------------------------------------
# Basic fixtures (Phase 2 compatible; Phase 8: multi-backend via --backend)
# ---------------------------------------------------------------------------


def _make_enc_settings(db_file: str, backend: str, encrypt: str, **overrides: object) -> Settings:
    """Build a Settings object for the given backend/encrypt combination.

    For the postgres backend, ``db_file`` may be the sentinel string
    ``"pg:<dsn>:<schema>"`` produced by the ``tmp_db`` fixture.  In that case
    ``pg_dsn`` and ``pg_schema`` are extracted automatically unless supplied
    in *overrides*.
    """
    kwargs: dict[str, object] = {
        "db_path": db_file,
        "storage_backend": backend,
        "subscription_delivery_sweep_s": 86400,
        **overrides,
    }
    if backend == "postgres" and db_file.startswith("pg:") and "pg_dsn" not in overrides:
        _, dsn, schema = db_file.split(":", 2)
        kwargs["pg_dsn"] = dsn
        kwargs["pg_schema"] = schema
        kwargs["db_path"] = "pg_test"
    if encrypt == "on":
        kwargs["at_rest_encryption"] = "on"
        kwargs["at_rest_key_passphrase_env"] = _ENCRYPT_PASSPHRASE_ENV
    return Settings(**kwargs)


@pytest.fixture()
def tmp_db(tmp_path: object, backend: str, encrypt: str) -> Generator[str, None, None]:
    """Create a migrated test database, honouring --backend and --encrypt."""
    db_file = str(tmp_path) + "/test.db"  # type: ignore[operator]
    if backend == "postgres":
        import os
        import uuid

        pytest.importorskip("psycopg2", reason="psycopg2 not installed")
        pg_dsn = os.environ.get("STIGMEM_TEST_PG_DSN", "")
        if not pg_dsn:
            pytest.skip("STIGMEM_TEST_PG_DSN not set")
        from stigmem_node.storage import make_backend as _make_backend

        schema = f"node_test_{uuid.uuid4().hex[:12]}"
        b = _make_backend(
            _settings=_make_enc_settings(db_file, backend, "off", pg_dsn=pg_dsn, pg_schema=schema)
        )
        b.apply_migrations(_MIGRATIONS_DIR)
        sentinel = f"pg:{pg_dsn}:{schema}"
        yield sentinel
        # Drop the per-test schema to avoid accumulating stale schemas.
        try:
            import psycopg2  # type: ignore[import]

            conn = psycopg2.connect(pg_dsn)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")  # noqa: S608
            conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to drop postgres test schema %s: %s", schema, exc)
        return
    if encrypt == "on" or backend == "libsql":
        if backend == "libsql":
            pytest.importorskip("libsql_experimental", reason="libsql-experimental not installed")
        from stigmem_node.storage import make_backend as _make_backend

        b = _make_backend(_settings=_make_enc_settings(db_file, backend, encrypt))
        b.apply_migrations(_MIGRATIONS_DIR)
    else:
        apply_migrations(db_path=db_file)
    yield db_file


@pytest.fixture()
def migrated_db(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    """Provide a fully-migrated SQLite DB and patch db_mod.settings to point at it.

    Tests that do not request the ``client`` fixture (and therefore skip the
    normal ``tmp_db`` → ``client`` setup path) must request this fixture
    explicitly if they invoke code paths that call ``db()`` internally — e.g.
    any recall-ranking path that touches ``caller_visible_gardens``.

    Using ``monkeypatch`` ensures the settings override is automatically
    reverted at test teardown with no manual restore needed.
    """
    db_file = str(tmp_path) + "/test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)
    test_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    monkeypatch.setattr(settings_module, "settings", test_settings)
    monkeypatch.setattr(db_mod, "settings", test_settings)
    yield db_file


@pytest.fixture()
def client(tmp_db: str, backend: str, encrypt: str) -> Generator[TestClient, None, None]:
    """TestClient with auth disabled and a fresh in-process DB."""
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db, backend, encrypt, auth_required=False, node_url="http://testnode"
    )
    extra = _patch_settings(test_settings)
    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
    finally:
        _restore_settings(original, extra)


def _time_travel_plugin_manifest() -> PluginManifest:
    if str(_TIME_TRAVEL_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TIME_TRAVEL_PLUGIN_SRC))
    plugin = importlib.import_module("stigmem_plugin_time_travel")
    return plugin.plugin_manifest()


def _tombstone_plugin_manifest() -> PluginManifest:
    if str(_TOMBSTONE_PLUGIN_SRC) not in sys.path:
        sys.path.insert(0, str(_TOMBSTONE_PLUGIN_SRC))
    os.environ.setdefault("STIGMEM_TOMBSTONES_ENABLED", "true")
    os.environ.setdefault("STIGMEM_TOMBSTONES_ALLOW_RECALL_FILTER", "true")
    plugin = importlib.import_module("stigmem_plugin_tombstones")
    return plugin.plugin_manifest()


@pytest.fixture()
def time_travel_client(
    tmp_db: str, backend: str, encrypt: str, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    """TestClient with the experimental time-travel plugin registered."""
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ENABLED", "true")
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ALLOW_FACT_QUERY_AS_OF", "true")
    monkeypatch.setenv("STIGMEM_TIME_TRAVEL_ALLOW_RECALL_AS_OF", "true")
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db, backend, encrypt, auth_required=False, node_url="http://testnode"
    )
    extra = _patch_settings(test_settings)
    try:
        with stigmem_plugins([_time_travel_plugin_manifest(), _tombstone_plugin_manifest()]):
            app = create_app()
            with TestClient(app, raise_server_exceptions=True) as c:
                yield c
    finally:
        _restore_settings(original, extra)


@pytest.fixture()
def client_async_threshold(
    tmp_db: str, backend: str, encrypt: str
) -> Generator[TestClient, None, None]:
    """TestClient with async_job_threshold=0 to force the async 202 path in tests."""
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db,
        backend,
        encrypt,
        auth_required=False,
        node_url="http://testnode",
        async_job_threshold=0,
    )
    extra = _patch_settings(test_settings)
    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c
    finally:
        _restore_settings(original, extra)


@pytest.fixture()
def authed_client(
    tmp_db: str, backend: str, encrypt: str
) -> Generator[tuple[TestClient, str], None, None]:
    """TestClient with auth enabled; yields (client, raw_key)."""
    original = settings_module.settings
    test_settings = _make_enc_settings(
        tmp_db, backend, encrypt, auth_required=True, node_url="http://testnode"
    )
    extra = _patch_settings(test_settings)
    raw_key = create_api_key("agent:test", ["read", "write"])
    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield c, raw_key
    finally:
        _restore_settings(original, extra)


# ---------------------------------------------------------------------------
# Federation fixture
# ---------------------------------------------------------------------------


class FedNode(NamedTuple):
    client: TestClient
    db_path: str
    node_id: str
    pub_b64: str
    priv_b64: str
    federate_key: str  # raw API key with read+write+federate permissions
    node_url: str


@pytest.fixture()
def fed_node(tmp_path: object) -> Generator[FedNode, None, None]:
    """A federation-enabled node with a test Ed25519 keypair."""
    import stigmem_node.peer_token as token_mod

    db_file = str(tmp_path) + "/fed_test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    pub_b64, priv_b64 = generate_keypair()
    node_id = "stigmem://test-node-a"
    node_url = "http://test-node-a"

    # Store keys and node_id in node_meta
    conn = sqlite3.connect(db_file)
    conn.execute("INSERT OR REPLACE INTO node_meta (key, value) VALUES ('node_id', ?)", (node_id,))
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_pubkey', ?)", (pub_b64,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_privkey', ?)",
        (priv_b64,),
    )
    conn.commit()
    conn.close()

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url=node_url,
        federation_enabled=True,
        federation_insecure=True,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )
    extra = _patch_settings(test_settings)

    # Seed the peer_token cache with this node's keys
    token_mod._cached_pub = pub_b64
    token_mod._cached_priv = priv_b64

    raw_key = create_api_key("agent:test-fed", ["read", "write", "federate"])

    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield FedNode(
                client=c,
                db_path=db_file,
                node_id=node_id,
                pub_b64=pub_b64,
                priv_b64=priv_b64,
                federate_key=raw_key,
                node_url=node_url,
            )
    finally:
        _restore_settings(original, extra)
        token_mod._cached_pub = None
        token_mod._cached_priv = None


@pytest.fixture()
def fed_node_a(tmp_path: object) -> Generator[FedNode, None, None]:
    """Alias for fed_node — test_federation.py uses this name by convention."""
    import stigmem_node.peer_token as token_mod

    db_file = str(tmp_path) + "/fed_test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)

    pub_b64, priv_b64 = generate_keypair()
    node_id = "stigmem://test-node-a"
    node_url = "http://test-node-a"

    conn = sqlite3.connect(db_file)
    conn.execute("INSERT OR REPLACE INTO node_meta (key, value) VALUES ('node_id', ?)", (node_id,))
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_pubkey', ?)", (pub_b64,)
    )
    conn.execute(
        "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_privkey', ?)",
        (priv_b64,),
    )
    conn.commit()
    conn.close()

    original = settings_module.settings
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url=node_url,
        federation_enabled=True,
        federation_insecure=True,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )
    extra = _patch_settings(test_settings)

    token_mod._cached_pub = pub_b64
    token_mod._cached_priv = priv_b64

    raw_key = create_api_key("agent:test-fed", ["read", "write", "federate"])

    try:
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as c:
            yield FedNode(
                client=c,
                db_path=db_file,
                node_id=node_id,
                pub_b64=pub_b64,
                priv_b64=priv_b64,
                federate_key=raw_key,
                node_url=node_url,
            )
    finally:
        _restore_settings(original, extra)
        token_mod._cached_pub = None
        token_mod._cached_priv = None
