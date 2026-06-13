"""Argon2id API-key storage and legacy SHA-256 migration coverage."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

import stigmem_node.db as db_mod
from stigmem_node.auth import (
    _hash_key,
    _verify_key_hash,
    register_api_key,
)

_ARGON2_VERIFY_P99_BUDGET_SECONDS = 0.100


def _insert_legacy_sha256_key(
    raw_key: str,
    *,
    entity_uri: str = "agent:legacy",
    permissions: list[str] | None = None,
) -> str:
    key_id = str(uuid.uuid4())
    if permissions is None:
        permissions = ["read", "write"]
    with db_mod.db() as conn:
        conn.execute(
            """INSERT INTO api_keys
               (id, key_hash, entity_uri, permissions, description,
                created_at, expires_at, oidc_sub, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                key_id,
                hashlib.sha256(raw_key.encode()).hexdigest(),
                entity_uri,
                json.dumps(permissions),
                "legacy SHA-256 test key",
                datetime.now(UTC).isoformat(),
                None,
                None,
                "default",
            ),
        )
    return key_id


def test_new_api_keys_are_argon2id_hashed(authed_client: tuple[TestClient, str]) -> None:
    _client, raw_key = authed_client

    with db_mod.db() as conn:
        rows = conn.execute("SELECT key_hash FROM api_keys").fetchall()

    assert rows
    assert any(row["key_hash"].startswith("$argon2id$") for row in rows)
    assert any(_verify_key_hash(raw_key, row["key_hash"]) for row in rows)


def test_legacy_sha256_key_rehashes_on_successful_auth(
    authed_client: tuple[TestClient, str],
) -> None:
    client, _admin_key = authed_client
    raw_key = f"legacy-{uuid.uuid4().hex}"
    key_id = _insert_legacy_sha256_key(raw_key)

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {raw_key}"})

    assert response.status_code == 200, response.text
    assert response.json()["entity_uri"] == "agent:legacy"
    with db_mod.db() as conn:
        row = conn.execute("SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        audit = conn.execute(
            "SELECT detail FROM fact_audit_log WHERE event_type = 'api_key_rehashed'"
        ).fetchone()

    assert row is not None
    assert row["key_hash"].startswith("$argon2id$")
    assert _verify_key_hash(raw_key, row["key_hash"])
    assert audit is not None
    detail = json.loads(audit["detail"])
    assert detail["key_id"] == key_id
    assert detail["from"] == "sha256"
    assert detail["to"] == "argon2id"


def test_legacy_sha256_key_rejected_after_acceptance_deadline(
    authed_client: tuple[TestClient, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _admin_key = authed_client
    raw_key = f"legacy-{uuid.uuid4().hex}"
    _insert_legacy_sha256_key(raw_key)
    expired_deadline = datetime.now(UTC) - timedelta(seconds=1)
    monkeypatch.setattr(db_mod.settings, "legacy_sha256_accept_until", expired_deadline)

    response = client.get("/v1/me", headers={"Authorization": f"Bearer {raw_key}"})

    assert response.status_code == 401
    assert "Legacy API key hashes are no longer accepted" in response.json()["detail"]


def test_legacy_sha256_acceptance_logs_deprecation_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """F-SAUTH2: accepting a legacy hash emits a per-acceptance deprecation warning."""
    import logging

    monkeypatch.setattr(db_mod.settings, "legacy_sha256_accept_until", None)
    raw_key = f"legacy-{uuid.uuid4().hex}"
    stored = hashlib.sha256(raw_key.encode()).hexdigest()

    with caplog.at_level(logging.WARNING, logger="stigmem.auth"):
        assert _verify_key_hash(raw_key, stored) is True

    assert "DEPRECATION" in caplog.text
    assert "legacy unsalted SHA-256" in caplog.text


def test_legacy_sha256_mismatch_does_not_warn(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A non-matching legacy hash must NOT emit the acceptance deprecation warning."""
    import logging

    monkeypatch.setattr(db_mod.settings, "legacy_sha256_accept_until", None)
    stored = hashlib.sha256(b"the-real-key").hexdigest()

    with caplog.at_level(logging.WARNING, logger="stigmem.auth"):
        assert _verify_key_hash("a-different-key", stored) is False

    assert "DEPRECATION" not in caplog.text


def test_legacy_sha256_past_cutoff_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-SAUTH2: a past cutoff date rejects legacy-hash verification (raises 401)."""
    from fastapi import HTTPException

    expired = datetime.now(UTC) - timedelta(seconds=1)
    monkeypatch.setattr(db_mod.settings, "legacy_sha256_accept_until", expired)
    raw_key = f"legacy-{uuid.uuid4().hex}"
    stored = hashlib.sha256(raw_key.encode()).hexdigest()

    with pytest.raises(HTTPException) as exc:
        _verify_key_hash(raw_key, stored)
    assert exc.value.status_code == 401


def test_invalid_key_does_not_rehash_legacy_rows(
    authed_client: tuple[TestClient, str],
) -> None:
    client, _admin_key = authed_client
    raw_key = f"legacy-{uuid.uuid4().hex}"
    key_id = _insert_legacy_sha256_key(raw_key)

    response = client.get("/v1/me", headers={"Authorization": "Bearer wrong-key"})

    assert response.status_code == 401
    with db_mod.db() as conn:
        row = conn.execute("SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        audit_count = conn.execute(
            "SELECT COUNT(*) AS n FROM fact_audit_log WHERE event_type = 'api_key_rehashed'"
        ).fetchone()["n"]
    assert row is not None
    assert row["key_hash"] == hashlib.sha256(raw_key.encode()).hexdigest()
    assert audit_count == 0


def test_argon2id_verify_p99_within_budget() -> None:
    raw_key = f"latency-{uuid.uuid4().hex}"
    stored_hash = _hash_key(raw_key)
    durations: list[float] = []

    for _ in range(5):
        started = time.perf_counter()
        assert _verify_key_hash(raw_key, stored_hash)
        durations.append(time.perf_counter() - started)

    observed_p99 = max(durations)
    assert observed_p99 < _ARGON2_VERIFY_P99_BUDGET_SECONDS


def test_register_api_key_duplicate_raw_material_is_rejected(
    authed_client: tuple[TestClient, str],
) -> None:
    _client, raw_key = authed_client

    with pytest.raises(ValueError, match="raw API key already exists"):
        register_api_key(raw_key, "agent:duplicate", ["read"])
