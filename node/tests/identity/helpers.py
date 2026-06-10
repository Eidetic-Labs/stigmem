"""Shared helpers for identity route and capability tests."""

from __future__ import annotations

import base64
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import _patch_settings, _restore_settings, generate_keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
from stigmem_node.identity.manifest import OrgManifest, sign_manifest
from stigmem_node.main import create_app

apply_migrations = db_mod.apply_migrations
Settings = settings_module.Settings


@contextmanager
def patched_test_settings(test_settings: Settings) -> Generator[None, None, None]:
    original = settings_module.settings
    extra = _patch_settings(test_settings)
    try:
        yield
    finally:
        _restore_settings(original, extra)


def gen_keypair() -> tuple[Ed25519PrivateKey, str, str]:
    """Return (private_key_obj, pub_b64url, priv_b64url)."""
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
    return priv, pub_b64, priv_b64


def fed_keypair() -> tuple[Ed25519PrivateKey, str, str]:
    """Return (private_key_obj, pub_b64url, priv_b64url) for THIS node's federation key.

    Fed Phase 2a: PUT /v1/federation/manifest only accepts a manifest whose public_key
    equals the node's federation/peer-token key. Route-level manifest tests must therefore
    build their manifest with this keypair (representing the node publishing its own manifest)
    rather than a random one from gen_keypair().
    """
    from stigmem_node.federation.peer_token import init_federation_keys

    pub_b64, priv_b64 = init_federation_keys()
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    return priv, pub_b64, priv_b64


@contextmanager
def seed_fed_keypair(pub_b64: str, priv_b64: str) -> Generator[None, None, None]:
    """Seed the peer_token cache so get_local_pubkey() returns *pub_b64* for the block.

    Fed Phase 2a: PUT /manifest checks manifest.public_key == get_local_pubkey(). Self-app
    capability-token tests that build their own Settings/app must make this node's federation
    key equal the manifest's signing key. Used together with Settings(federation_pubkey=...,
    federation_privkey=...). Resets the cache on exit for test isolation.
    """
    import stigmem_node.federation.peer_token as token_mod

    token_mod._cached_pub = pub_b64
    token_mod._cached_priv = priv_b64
    try:
        yield
    finally:
        token_mod._cached_pub = None
        token_mod._cached_priv = None


def make_manifest(
    priv: Ed25519PrivateKey,
    pub_b64: str,
    entity_uri: str = "https://example.org",
    entities: list[str] | None = None,
    key_id: str = "key-1",
    days_valid: int = 365,
) -> OrgManifest:
    now = datetime.now(UTC)
    manifest = OrgManifest(
        entity_uri=entity_uri,
        key_id=key_id,
        public_key=pub_b64,
        issued_at=now.replace(microsecond=0).isoformat(),
        expires_at=(now + timedelta(days=days_valid)).replace(microsecond=0).isoformat(),
        entities=entities if entities is not None else [entity_uri],
    )
    sign_manifest(manifest, priv)
    return manifest


@pytest.fixture()
def identity_client(tmp_path: Path) -> Generator[TestClient, None, None]:
    db_file = str(tmp_path / "identity_test.db")
    apply_migrations(db_path=db_file)

    # Seed this node's federation keypair so the peer_token cache is deterministic for
    # the whole fixture lifetime (Fed Phase 2a: PUT /manifest requires the manifest
    # public_key to equal this node's federation key, read via get_local_pubkey()).
    # seed_fed_keypair() encapsulates the cache seed/reset (try/finally).
    fed_pub, fed_priv = generate_keypair()

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        federation_pubkey=fed_pub,
        federation_privkey=fed_priv,
    )

    with seed_fed_keypair(fed_pub, fed_priv), patched_test_settings(test_settings):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            yield client


@pytest.fixture()
def strict_client(tmp_path: Path) -> Generator[TestClient, None, None]:
    db_file = str(tmp_path / "strict_test.db")
    apply_migrations(db_path=db_file)

    fed_pub, fed_priv = generate_keypair()

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="strict",
        tl_backend="off",
        federation_pubkey=fed_pub,
        federation_privkey=fed_priv,
    )

    with seed_fed_keypair(fed_pub, fed_priv), patched_test_settings(test_settings):
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client
