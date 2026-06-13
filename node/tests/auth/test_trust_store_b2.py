"""B2 coverage push for stigmem_node.identity.trust_store (37 missing).

Targets:
  - store_peer_manifest UPDATE branch + rotation-chain regression check (83-90)
  - get_peer_manifest expired-but-no-refresh path (170-171)
  - get_peer_manifest expired + refresh fails (177-182)
  - refresh_peer_manifests loop body (193-218)
  - _try_fetch_manifest non-HTTP entity_uri (230) + HTTP path (234-244)
  - cleanup_expired_tokens (263)
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gen_keypair() -> tuple[Ed25519PrivateKey, str, str]:
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


def _make_manifest(
    priv: Ed25519PrivateKey,
    pub_b64: str,
    entity_uri: str,
    *,
    days_valid: int = 365,
    issued_offset_days: int = 0,
    key_id: str = "key-1",
) -> Any:
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest

    issued = datetime.now(UTC) + timedelta(days=issued_offset_days)
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=key_id,
        public_key=pub_b64,
        issued_at=issued.isoformat(),
        expires_at=(issued + timedelta(days=days_valid)).isoformat(),
        entities=[entity_uri],
    )
    sign_manifest(m, priv)
    return m


def _patched_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from stigmem_node import db as db_mod
    from stigmem_node.db import apply_migrations

    db_file = str(tmp_path / "ts_b2.db")
    apply_migrations(db_path=db_file)
    monkeypatch.setattr(db_mod.settings, "db_path", db_file)
    return db_file


# ---------------------------------------------------------------------------
# store_peer_manifest
# ---------------------------------------------------------------------------


class TestStorePeerManifest:
    def test_first_store_inserts_row(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import sqlite3

        from stigmem_node.identity.trust_store import store_peer_manifest

        db = _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-store-1.example"
        m = _make_manifest(priv, pub, entity)

        store_peer_manifest(entity, m)

        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT entity_uri, key_id FROM federation_manifests WHERE entity_uri = ?",
            (entity,),
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == entity

    def test_update_with_same_key_id_succeeds(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from stigmem_node.identity.trust_store import store_peer_manifest

        _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-update.example"

        m1 = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m1)

        # Re-store with same key_id → no rotation chain check needed
        m2 = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m2)  # should not raise

    def test_update_with_different_key_without_rotation_chain_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from stigmem_node.identity.manifest import ManifestError
        from stigmem_node.identity.trust_store import store_peer_manifest

        _patched_db(tmp_path, monkeypatch)
        priv1, pub1, _ = _gen_keypair()
        priv2, pub2, _ = _gen_keypair()
        entity = "https://test-rotate-bad.example"

        m1 = _make_manifest(priv1, pub1, entity, key_id="key-1")
        store_peer_manifest(entity, m1)

        # New key but no rotation_events linking back → rotation chain check fails
        m2 = _make_manifest(priv2, pub2, entity, key_id="key-2")
        with pytest.raises(ManifestError, match="manifest update rejected"):
            store_peer_manifest(entity, m2)


# ---------------------------------------------------------------------------
# get_peer_manifest
# ---------------------------------------------------------------------------


class TestGetPeerManifest:
    def test_unknown_entity_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from stigmem_node.identity.trust_store import get_peer_manifest

        _patched_db(tmp_path, monkeypatch)
        assert get_peer_manifest("https://unknown.example") is None

    def test_returns_stored_manifest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from stigmem_node.identity.trust_store import (
            get_peer_manifest,
            store_peer_manifest,
        )

        _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-get.example"
        m = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m)

        retrieved = get_peer_manifest(entity)
        assert retrieved is not None
        assert retrieved.entity_uri == entity
        assert retrieved.key_id == "key-1"

    def test_expired_manifest_with_refresh_off_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sqlite3 as _sqlite3

        from stigmem_node.identity.trust_store import (
            get_peer_manifest,
            store_peer_manifest,
        )

        db = _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-expired.example"
        m = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m)

        # Backdate the expires_at directly in the DB
        conn = _sqlite3.connect(db)
        conn.execute(
            "UPDATE federation_manifests SET expires_at = ? WHERE entity_uri = ?",
            ((datetime.now(UTC) - timedelta(days=1)).isoformat(), entity),
        )
        conn.commit()
        conn.close()

        # refresh_if_expired=False → returns None
        assert get_peer_manifest(entity, refresh_if_expired=False) is None

    def test_expired_manifest_refresh_fails_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sqlite3 as _sqlite3

        from stigmem_node.identity import trust_store as ts_mod
        from stigmem_node.identity.trust_store import (
            get_peer_manifest,
            store_peer_manifest,
        )

        db = _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-refresh-fail.example"
        m = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m)

        # Backdate expiry
        conn = _sqlite3.connect(db)
        conn.execute(
            "UPDATE federation_manifests SET expires_at = ? WHERE entity_uri = ?",
            ((datetime.now(UTC) - timedelta(days=1)).isoformat(), entity),
        )
        conn.commit()
        conn.close()

        # Force _try_fetch_manifest to return None (refresh fails)
        monkeypatch.setattr(ts_mod, "_try_fetch_manifest", lambda uri: None)

        assert get_peer_manifest(entity, refresh_if_expired=True) is None


# ---------------------------------------------------------------------------
# _try_fetch_manifest
# ---------------------------------------------------------------------------


class TestTryFetchManifest:
    def test_non_http_uri_returns_none(self) -> None:
        from stigmem_node.identity.trust_store import _try_fetch_manifest

        # stigmem:// URIs can't be HTTP-fetched
        assert _try_fetch_manifest("stigmem://node-a") is None

    def test_http_404_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from stigmem_node.identity import trust_store as ts_mod

        class _Resp:
            status_code = 404

            def json(self) -> dict:
                return {}

        monkeypatch.setattr(httpx, "get", lambda *a, **kw: _Resp())
        # Resolve the host to a public IP so the anti-rebind pin (R-5 / F-SSRF1)
        # admits it; the fetch then returns 404 → None.
        monkeypatch.setattr(
            "stigmem_node.utility.net_util.socket.getaddrinfo",
            lambda *a, **k: [(2, 1, 6, "", ("8.8.8.8", 0))],
        )

        assert ts_mod._try_fetch_manifest("https://example.test") is None


# ---------------------------------------------------------------------------
# refresh_peer_manifests + cleanup_expired_tokens
# ---------------------------------------------------------------------------


class TestRefreshPeerManifests:
    def test_empty_db_runs_without_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from stigmem_node.identity.trust_store import refresh_peer_manifests

        _patched_db(tmp_path, monkeypatch)
        # No peers → loop body skipped, just calls cleanup_expired_tokens
        refresh_peer_manifests()  # must not raise

    def test_skips_when_fetch_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from stigmem_node.identity import trust_store as ts_mod
        from stigmem_node.identity.trust_store import (
            refresh_peer_manifests,
            store_peer_manifest,
        )

        _patched_db(tmp_path, monkeypatch)
        priv, pub, _ = _gen_keypair()
        entity = "https://test-refresh-noop.example"
        m = _make_manifest(priv, pub, entity)
        store_peer_manifest(entity, m)

        # _try_fetch_manifest returns None → refresh loop body continues
        monkeypatch.setattr(ts_mod, "_try_fetch_manifest", lambda uri: None)
        refresh_peer_manifests()  # must not raise


class TestCleanupExpiredTokens:
    def test_runs_on_empty_db(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from stigmem_node.identity.trust_store import cleanup_expired_tokens

        _patched_db(tmp_path, monkeypatch)
        # No expired tokens → returns 0 (or whatever the count is)
        result = cleanup_expired_tokens()
        assert isinstance(result, int)
        assert result >= 0
