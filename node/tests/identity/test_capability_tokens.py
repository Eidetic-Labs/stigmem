from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
from stigmem_node.identity.capability import CapabilityTokenError, verify_token
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest
from stigmem_node.main import create_app

from .helpers import (
    Settings,
    apply_migrations,
    fed_keypair,
    gen_keypair,
    make_manifest,
    patched_test_settings,
    seed_fed_keypair,
)


def test_expired_manifest_rejects_token_issuance(tmp_path: Path):
    """Issuing a token from an expired manifest must be rejected (H1)."""
    db_file = str(tmp_path / "h1_test.db")
    apply_migrations(db_path=db_file)

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
    )
    with patched_test_settings(test_settings):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            priv, pub_b64, _ = gen_keypair()
            issuer = "https://expired-issuer.org"
            # Create manifest that is already expired
            now = datetime.now(UTC)
            m = OrgManifest(
                entity_uri=issuer,
                key_id="exp-key",
                public_key=pub_b64,
                issued_at=(now - timedelta(days=10)).isoformat(),
                expires_at=(now - timedelta(seconds=1)).isoformat(),  # already expired
                entities=[issuer, "https://subject.org"],
            )
            sign_manifest(m, priv)

            # Insert into federation_manifests directly so it's "known" but expired
            conn = sqlite3.connect(db_file)
            mid = str(uuid.uuid4())
            mj = json.dumps(manifest_to_dict(m))
            conn.execute(
                "INSERT INTO federation_manifests "
                "(id,entity_uri,manifest_json,signature,key_id,issued_at,expires_at,"
                "log_entry_json,created_at,updated_at) "
                "VALUES (?,?,?,?,?,?,?,NULL,?,?)",
                (
                    mid,
                    issuer,
                    mj,
                    m.signature,
                    m.key_id,
                    m.issued_at,
                    m.expires_at,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
            conn.commit()
            conn.close()

            # Mint an API key so the caller authenticates as the issuer (H-SEC-1 BOLA guard)
            issuer_key = auth_mod.create_api_key(issuer, ["read", "write"])

            resp = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": issuer,
                    "verb": "read",
                    "object": "stigmem://test/facts",
                },
                headers={"Authorization": f"Bearer {issuer_key}"},
            )
            # H1: expired manifest → 422 (manifest not found or expired)
            assert resp.status_code == 422, resp.text
            assert "expired" in resp.json().get("detail", "").lower()


# ===========================================================================
# 5. External-entity subject → token rejected (C1 regression)
# ===========================================================================


def test_external_entity_subject_rejected(identity_client: TestClient):
    """Token subject not in issuer's entities list must be rejected (C1)."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://issuer.org"
    # Entity list does NOT include the subject we'll request
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])

    # Register the manifest
    resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    assert resp.status_code == 200, resp.text

    # Mint an API key so the caller authenticates as the issuer (H-SEC-1 BOLA guard)
    api_key = auth_mod.create_api_key(issuer, ["read", "write"])

    # Attempt to issue a token with an external subject
    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": "https://attacker.org",  # NOT in entities list
            "verb": "read",
            "object": "stigmem://facts",
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 403, resp.text
    assert "C1" in resp.json().get("detail", "") or "entities list" in resp.json().get("detail", "")


def test_subject_in_entities_succeeds(identity_client: TestClient):
    """Token issuance succeeds when subject is in the issuer's entities list."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://myorg.org"
    subject = "https://myorg.org/agent-1"
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer, subject])

    resp = identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    assert resp.status_code == 200, resp.text

    # Mint an API key so the caller authenticates as the issuer (H-SEC-1 BOLA guard)
    api_key = auth_mod.create_api_key(issuer, ["read", "write"])

    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": subject,
            "verb": "read",
            "object": "stigmem://facts",
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["subject"] == subject
    assert data["issuer"] == issuer
    assert len(data["nonce"]) == 64
    assert data["nonce"] == data["nonce"].lower()


# ===========================================================================
# 6. Nonce replay via capability_tokens.nonce UNIQUE constraint
# ===========================================================================


def test_nonce_uniqueness_enforced(tmp_path: Path):
    """Inserting two capability_tokens with the same nonce must fail (DB constraint)."""
    db_file = str(tmp_path / "nonce_test.db")
    apply_migrations(db_path=db_file)

    conn = sqlite3.connect(db_file)
    now = datetime.now(UTC).isoformat()
    nonce = uuid.uuid4().hex + uuid.uuid4().hex  # valid 64-char hex

    conn.execute(
        "INSERT INTO capability_tokens "
        "(id,token_json,issuer,subject,verb,object,issued_at,expiry,nonce,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), "{}", "iss", "sub", "read", "obj", now, now, nonce, now),
    )
    conn.commit()

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        conn.execute(
            "INSERT INTO capability_tokens "
            "(id,token_json,issuer,subject,verb,object,issued_at,expiry,nonce,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), "{}", "iss", "sub", "read", "obj", now, now, nonce, now),
        )
        conn.commit()
    conn.close()


def test_nonce_check_constraint_rejects_wrong_format(tmp_path: Path):
    """nonce CHECK(length=64 and all lowercase hex) must reject non-conforming values."""
    db_file = str(tmp_path / "nonce_check.db")
    apply_migrations(db_path=db_file)

    conn = sqlite3.connect(db_file)
    now = datetime.now(UTC).isoformat()

    bad_nonces = [
        "ABCD" + "a" * 60,  # uppercase → should fail
        "a" * 63,  # too short
        "a" * 65,  # too long
        "g" * 64,  # non-hex lowercase character → should fail
        "a" * 63 + "!",  # special character → should fail
    ]

    for bad_nonce in bad_nonces:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO capability_tokens "
                "(id,token_json,issuer,subject,verb,object,issued_at,expiry,nonce,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), "{}", "iss", "sub", "read", "obj", now, now, bad_nonce, now),
            )
            conn.commit()
        conn.rollback()
    conn.close()


# ===========================================================================
# 7. Quarantine route: reader cannot see fact value (M3 regression)
# ===========================================================================


def test_revoke_token_by_issuer_succeeds(identity_client: TestClient):
    """Issuer can revoke their own token."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://issuer-revoke.org"
    subject = "https://issuer-revoke.org/agent"
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer, subject])

    identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))

    # Mint API key for the issuer so the H-SEC-1 BOLA guard on issuance passes
    issuer_key = auth_mod.create_api_key(issuer, ["read", "write"])

    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": subject,
            "verb": "read",
            "object": "stigmem://facts",
        },
        headers={"Authorization": f"Bearer {issuer_key}"},
    )
    assert resp.status_code == 201
    token_id = resp.json()["token_id"]

    # Revoke with no auth header → anon identity "anon:trusted" ≠ issuer/subject → 403
    resp = identity_client.post(f"/v1/federation/capability-tokens/{token_id}/revoke", json={})
    assert resp.status_code == 403, resp.text
    assert "not authorized" in resp.json().get("detail", "").lower()


def test_revoke_token_unknown_returns_404(identity_client: TestClient):
    """Revoking a non-existent token returns 404, not 403."""
    resp = identity_client.post("/v1/federation/capability-tokens/non-existent-id/revoke", json={})
    assert resp.status_code == 404


def test_revoke_token_unauthorized_third_party_blocked(identity_client: TestClient):
    """A third-party (not issuer or subject) cannot revoke the token (H-SEC-3)."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://org-a.org"
    subject = "https://org-a.org/agent"
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer, subject])

    identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))

    # Mint API key for the issuer so the H-SEC-1 BOLA guard on issuance passes
    issuer_key = auth_mod.create_api_key(issuer, ["read", "write"])

    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": subject,
            "verb": "read",
            "object": "stigmem://facts",
        },
        headers={"Authorization": f"Bearer {issuer_key}"},
    )
    assert resp.status_code == 201
    token_id = resp.json()["token_id"]

    # Revoke with no auth header → anon identity "anon:trusted",
    # which is neither issuer (https://org-a.org) nor subject (https://org-a.org/agent)
    resp = identity_client.post(
        f"/v1/federation/capability-tokens/{token_id}/revoke",
        json={"reason": "unauthorised revocation attempt"},
    )
    assert resp.status_code == 403, resp.text


# ===========================================================================
# 9. LocalAppendOnlyLog — basic submit + verify
# ===========================================================================


def test_issuer_must_match_caller_entity_uri(identity_client: TestClient):
    """Caller cannot forge a token claiming a different org as issuer (H-SEC-1 BOLA).

    With auth_required=False the unauthenticated caller's entity_uri is "anon:trusted".
    Requesting a token with issuer="https://bob.org" must be rejected with 403
    before any manifest lookup occurs.
    """
    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": "https://bob.org",
            "subject": "https://bob.org",
            "verb": "read",
            "object": "stigmem://facts",
        },
    )
    assert resp.status_code == 403, resp.text
    assert "issuer" in resp.json().get("detail", "").lower()


# ===========================================================================
# 14. C-SEC-1 / M-SEC-2 — Ed25519 token signing and verify_token
# ===========================================================================


@pytest.fixture()
def signed_identity_client(tmp_path: Path) -> Generator[tuple[TestClient, str, str], None, None]:
    """Client with node_private_key configured; yields (client, issuer_uri, priv_b64url).

    The issuer manifest is pre-registered so token issuance can succeed.
    auth_required=False → entity_uri is 'anon:trusted', which means the H-SEC-1
    issuer==caller guard would block us.  We patch identity_mod._manifest_submit_log
    and issue tokens directly using a pre-registered manifest trick: register the
    manifest under 'anon:trusted' so the caller can issue its own token.
    """
    db_file = str(tmp_path / "csec1_test.db")
    apply_migrations(db_path=db_file)

    priv, pub_b64, priv_b64 = gen_keypair()
    issuer = "anon:trusted"  # matches auth_required=False entity_uri

    # Fed Phase 2a: the published manifest's public_key must equal this node's federation
    # key. Make the node's federation key == this fixture's keypair (also used as the
    # token-signing node_private_key, i.e. a coherent single-key node).
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        node_private_key=priv_b64,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            # Register issuer manifest under 'anon:trusted' so the route's H-SEC-1 guard passes
            m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])
            resp = client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            assert resp.status_code == 200, resp.text
            yield client, issuer, priv_b64


def test_signed_token_has_token_version_and_signature(
    signed_identity_client: tuple[TestClient, str, str],
) -> None:
    """Issued tokens must include token_version=1 and a signature field (C-SEC-1 / M-SEC-2)."""
    client, issuer, _ = signed_identity_client

    resp = client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": issuer,
            "verb": "read",
            "object": "stigmem://facts",
        },
    )
    assert resp.status_code == 201, resp.text
    token_json_str = resp.json()["token_json"]
    token = json.loads(token_json_str)

    assert token.get("token_version") == 1, "token_version must be 1 (M-SEC-2)"
    assert "signature" in token, "signature field must be present (C-SEC-1)"
    assert len(token["signature"]) > 0, "signature must not be empty"


def test_verify_token_rejects_mutated_token(
    signed_identity_client: tuple[TestClient, str, str],
) -> None:
    """Mutating any token field after signing must cause verify_token to raise (C-SEC-1)."""
    client, issuer, _ = signed_identity_client

    resp = client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": issuer,
            "verb": "read",
            "object": "stigmem://facts",
        },
    )
    assert resp.status_code == 201, resp.text
    original_token_json = resp.json()["token_json"]

    # Mutate the verb field — signature no longer matches the canonical body
    token = json.loads(original_token_json)
    token["verb"] = "write"
    mutated_token_json = json.dumps(token)

    # get_peer_manifest is the production trust-store resolver; settings are patched
    # by signed_identity_client so it uses the test DB
    from stigmem_node.identity.trust_store import get_peer_manifest

    with pytest.raises(CapabilityTokenError, match="signature"):
        verify_token(mutated_token_json, get_peer_manifest)


def test_verify_token_rejects_missing_token_version() -> None:
    """verify_token must reject a token that has no token_version field (M-SEC-2)."""
    token_without_version = json.dumps(
        {
            "token_id": str(uuid.uuid4()),
            "issuer": "https://example.org",
            "subject": "https://example.org",
            "verb": "read",
            "object": "stigmem://facts",
            "issued_at": datetime.now(UTC).isoformat(),
            "expiry": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "nonce": "a" * 64,
            "signature": "fakesig",
            # token_version intentionally absent
        }
    )

    with pytest.raises(CapabilityTokenError, match="token_version"):
        verify_token(token_without_version, lambda _uri: None)


def test_verify_token_rejects_wrong_token_version() -> None:
    """verify_token must reject token_version != 1 (M-SEC-2)."""
    token_wrong_version = json.dumps(
        {
            "token_id": str(uuid.uuid4()),
            "token_version": 2,
            "issuer": "https://example.org",
            "subject": "https://example.org",
            "verb": "read",
            "object": "stigmem://facts",
            "issued_at": datetime.now(UTC).isoformat(),
            "expiry": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            "nonce": "a" * 64,
            "signature": "fakesig",
        }
    )

    with pytest.raises(CapabilityTokenError, match="token_version"):
        verify_token(token_wrong_version, lambda _uri: None)


# ===========================================================================
# 15. M-SEC-1 — 90-day TTL cap on capability token issuance
# ===========================================================================


def test_ttl_over_90_days_rejected(identity_client: TestClient) -> None:
    """ttl_seconds > 7,776,000 (90 days) must be rejected with 422 (M-SEC-1)."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://ttl-cap-test.org"
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])

    identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    api_key = auth_mod.create_api_key(issuer, ["read", "write"])

    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": issuer,
            "verb": "read",
            "object": "stigmem://facts",
            "ttl_seconds": 7_776_001,  # one second over 90 days
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 422, resp.text
    assert (
        "90-day" in resp.json().get("detail", "").lower()
        or "maximum" in resp.json().get("detail", "").lower()
    )


def test_ttl_exactly_90_days_accepted(identity_client: TestClient) -> None:
    """ttl_seconds == 7,776,000 (exactly 90 days) must be accepted."""
    priv, pub_b64, _ = fed_keypair()
    issuer = "https://ttl-cap-exact.org"
    m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])

    identity_client.put("/v1/federation/manifest", json=manifest_to_dict(m))
    api_key = auth_mod.create_api_key(issuer, ["read", "write"])

    resp = identity_client.post(
        "/v1/federation/capability-tokens",
        json={
            "issuer": issuer,
            "subject": issuer,
            "verb": "read",
            "object": "stigmem://facts",
            "ttl_seconds": 7_776_000,
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert resp.status_code == 201, resp.text


# ===========================================================================
# 16. M-SEC-4 — audit log entries for capability token lifecycle
# ===========================================================================


def test_capability_issuance_writes_audit_log(tmp_path: Path) -> None:
    """Issue a capability token — fact_audit_log must get a capability_issued row."""
    import sqlite3 as _sqlite3

    db_file = str(tmp_path / "audit_issue.db")
    apply_migrations(db_path=db_file)

    # Fed Phase 2a: published manifest public_key must equal this node's federation key.
    priv, pub_b64, priv_b64 = gen_keypair()

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            issuer = "https://audit-issue.org"
            m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])
            client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            api_key = auth_mod.create_api_key(issuer, ["read", "write"])

            resp = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": issuer,
                    "verb": "write",
                    "object": "stigmem://facts",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 201, resp.text
            token_id = resp.json()["token_id"]

        conn = _sqlite3.connect(db_file)
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT * FROM fact_audit_log WHERE fact_id = ? AND event_type = 'capability_issued'",
            (token_id,),
        ).fetchone()
        conn.close()

        assert row is not None, "capability_issued audit row must exist"
        assert row["entity_uri"] == issuer
        detail = json.loads(row["detail"])
        assert detail["verb"] == "write"
        assert detail["issuer"] == issuer


def test_capability_revocation_writes_audit_log(tmp_path: Path) -> None:
    """Revoke a capability token — fact_audit_log must get a capability_revoked row."""
    import sqlite3 as _sqlite3

    db_file = str(tmp_path / "audit_revoke.db")
    apply_migrations(db_path=db_file)

    # Fed Phase 2a: published manifest public_key must equal this node's federation key.
    priv, pub_b64, priv_b64 = gen_keypair()

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            issuer = "https://audit-revoke.org"
            m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])
            client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            api_key = auth_mod.create_api_key(issuer, ["read", "write"])

            resp = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": issuer,
                    "verb": "write",
                    "object": "stigmem://facts",
                },
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp.status_code == 201, resp.text
            token_id = resp.json()["token_id"]

            resp2 = client.post(
                f"/v1/federation/capability-tokens/{token_id}/revoke",
                json={"reason": "audit-log-test"},
                headers={"Authorization": f"Bearer {api_key}"},
            )
            assert resp2.status_code == 200, resp2.text

        conn = _sqlite3.connect(db_file)
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT * FROM fact_audit_log WHERE fact_id = ? AND event_type = 'capability_revoked'",
            (token_id,),
        ).fetchone()
        conn.close()

        assert row is not None, "capability_revoked audit row must exist"
        detail = json.loads(row["detail"])
        assert detail["reason"] == "audit-log-test"


# ===========================================================================
# 17. H-SEC-2 — Capability-token wire integration on push_facts
# ===========================================================================


def test_verify_endpoint_valid_signed_token(tmp_path: Path) -> None:
    """POST /verify returns {valid: true} for a properly signed token."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )

    db_file = str(tmp_path / "verify_ep_test.db")
    apply_migrations(db_path=db_file)

    # Fed Phase 2a: published manifest public_key must equal this node's federation key.
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        node_private_key=priv_b64,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        # auth_required=False → identity.entity_uri = "anon:trusted"; BOLA guard
        # requires issuer == entity_uri so we use that as both issuer and subject.
        issuer = "anon:trusted"
        subject = issuer
        m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])

        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            # Register manifest
            resp = client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            assert resp.status_code == 200, resp.text

            # Issue a token
            resp = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": subject,
                    "verb": "write",
                    "object": "stigmem://facts",
                },
            )
            assert resp.status_code == 201, resp.text
            token_json = resp.json()["token_json"]

            # Verify the token via the endpoint
            resp = client.post(
                "/v1/federation/capability-tokens/verify", json={"token_json": token_json}
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["valid"] is True, data


def test_verify_endpoint_revoked_token_invalid(tmp_path: Path) -> None:
    """POST /verify returns {valid: false} for a revoked token."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv = Ed25519PrivateKey.generate()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )

    db_file = str(tmp_path / "verify_rev_test.db")
    apply_migrations(db_path=db_file)

    # Fed Phase 2a: published manifest public_key must equal this node's federation key.
    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
        node_private_key=priv_b64,
        federation_pubkey=pub_b64,
        federation_privkey=priv_b64,
    )

    with patched_test_settings(test_settings), seed_fed_keypair(pub_b64, priv_b64):
        # auth_required=False → identity.entity_uri = "anon:trusted"; BOLA guard
        # requires issuer == entity_uri so we use that as both issuer and subject.
        issuer = "anon:trusted"
        subject = issuer
        m = make_manifest(priv, pub_b64, entity_uri=issuer, entities=[issuer])

        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            client.put("/v1/federation/manifest", json=manifest_to_dict(m))
            resp = client.post(
                "/v1/federation/capability-tokens",
                json={
                    "issuer": issuer,
                    "subject": subject,
                    "verb": "write",
                    "object": "stigmem://facts",
                },
            )
            assert resp.status_code == 201
            token_id = resp.json()["token_id"]
            token_json = resp.json()["token_json"]

            # Directly mark revoked in DB for test isolation
            # (revoke endpoint also has a BOLA guard; direct DB write is cleaner here)
            import sqlite3 as _sqlite3

            conn = _sqlite3.connect(db_file)
            conn.execute(
                """UPDATE capability_tokens
                   SET revoked_at = '2026-01-01T00:00:00+00:00'
                   WHERE id = ?""",
                (token_id,),
            )
            conn.commit()
            conn.close()

            resp = client.post(
                "/v1/federation/capability-tokens/verify", json={"token_json": token_json}
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["valid"] is False
            assert "revoked" in data.get("reason", "").lower()


def test_verify_endpoint_missing_body_returns_422(tmp_path: Path) -> None:
    """POST /verify with empty body returns 422."""
    db_file = str(tmp_path / "verify_422.db")
    apply_migrations(db_path=db_file)

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
        tl_backend="off",
    )

    with patched_test_settings(test_settings):
        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.post("/v1/federation/capability-tokens/verify", json={})
            assert resp.status_code == 422, resp.text
