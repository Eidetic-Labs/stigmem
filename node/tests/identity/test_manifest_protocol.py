from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from stigmem_node.identity.manifest import (
    ManifestError,
    OrgManifest,
    RotationEvent,
    manifest_to_dict,
    sign_manifest,
    sign_rotation_event,
    verify_manifest,
    verify_rotation_chain,
)
from stigmem_node.identity.transparency_log import TransparencyLogUnavailable, _OffLog

from .helpers import fed_keypair, gen_keypair, make_manifest


def test_manifest_sign_verify_roundtrip():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64)
    assert verify_manifest(m)  # must not raise


def test_manifest_verify_bad_signature_fails():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64)
    m.signature = "AAAA" + m.signature[4:]  # corrupt
    with pytest.raises(ManifestError, match="self-signature"):
        verify_manifest(m)


def test_manifest_expiry_too_long_rejected():
    priv, pub_b64, _ = gen_keypair()
    now = datetime.now(UTC)
    m = OrgManifest(
        entity_uri="https://test.org",
        key_id="k1",
        public_key=pub_b64,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=731)).isoformat(),
        entities=["https://test.org"],
    )
    sign_manifest(m, priv)
    with pytest.raises(ManifestError, match="730"):
        verify_manifest(m)


def test_manifest_strict_365_day_limit():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64, days_valid=400)
    with pytest.raises(ManifestError, match="365"):
        verify_manifest(m, trust_mode="strict")


def test_manifest_relaxed_allows_up_to_730_days():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64, days_valid=700)
    assert verify_manifest(m, trust_mode="relaxed")


def test_manifest_rotation_events_limit():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64)
    # Inject 101 dummy rotation events (content doesn't matter for length check)
    event_time = datetime.now(UTC).isoformat()
    m.rotation_events = [
        RotationEvent(f"k{i}", f"k{i + 1}", pub_b64, event_time, "sig") for i in range(101)
    ]
    # Re-sign so self-signature is valid
    sign_manifest(m, priv)
    with pytest.raises(ManifestError, match="100"):
        verify_manifest(m)


# ===========================================================================
# 2. Rotation chain valid / invalid
# ===========================================================================


def test_rotation_chain_no_rotation_same_key():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64, key_id="genesis")
    assert verify_rotation_chain(m, "genesis", pub_b64)


def test_rotation_chain_no_rotation_different_key_fails():
    priv, pub_b64, _ = gen_keypair()
    m = make_manifest(priv, pub_b64, key_id="key-A")
    with pytest.raises(ManifestError, match="differs from previous"):
        verify_rotation_chain(m, "genesis", pub_b64)


def test_rotation_chain_single_valid_step():
    priv1, pub1_b64, _ = gen_keypair()
    priv2, pub2_b64, _ = gen_keypair()
    now = datetime.now(UTC).isoformat()

    rot_sig = sign_rotation_event("key-1", "key-2", pub2_b64, now, priv1)
    evt = RotationEvent(
        previous_key_id="key-1",
        new_key_id="key-2",
        new_public_key=pub2_b64,
        rotated_at=now,
        signature=rot_sig,
    )

    m = OrgManifest(
        entity_uri="https://example.org",
        key_id="key-2",
        public_key=pub2_b64,
        issued_at=now,
        expires_at=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
        entities=["https://example.org"],
        rotation_events=[evt],
    )
    sign_manifest(m, priv2)

    assert verify_rotation_chain(m, "key-1", pub1_b64)


def test_rotation_chain_regression_attack_rejected():
    """Rotation back to a previously-used key must be rejected."""
    priv1, pub1_b64, _ = gen_keypair()
    priv2, pub2_b64, _ = gen_keypair()
    now = datetime.now(UTC).isoformat()

    # Build: key-1 → key-2 (valid) → key-1 (regression — must fail)
    sig_12 = sign_rotation_event("key-1", "key-2", pub2_b64, now, priv1)
    sig_21 = sign_rotation_event("key-2", "key-1", pub1_b64, now, priv2)

    evt1 = RotationEvent("key-1", "key-2", pub2_b64, now, sig_12)
    evt2 = RotationEvent("key-2", "key-1", pub1_b64, now, sig_21)

    m = OrgManifest(
        entity_uri="https://example.org",
        key_id="key-1",
        public_key=pub1_b64,
        issued_at=now,
        expires_at=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
        entities=["https://example.org"],
        rotation_events=[evt1, evt2],
    )
    sign_manifest(m, priv1)

    with pytest.raises(ManifestError, match="regression|cycle"):
        verify_rotation_chain(m, "key-1", pub1_b64)


def test_rotation_chain_bad_event_signature_rejected():
    priv1, pub1_b64, _ = gen_keypair()
    priv2, pub2_b64, _ = gen_keypair()
    now = datetime.now(UTC).isoformat()

    # Use wrong private key to sign the rotation event (cross-entity replay F1)
    wrong_sig = sign_rotation_event(
        "key-1", "key-2", pub2_b64, now, priv2
    )  # signed with priv2 not priv1
    evt = RotationEvent("key-1", "key-2", pub2_b64, now, wrong_sig)

    m = OrgManifest(
        entity_uri="https://attacker.org",
        key_id="key-2",
        public_key=pub2_b64,
        issued_at=now,
        expires_at=(datetime.now(UTC) + timedelta(days=30)).isoformat(),
        entities=["https://attacker.org"],
        rotation_events=[evt],
    )
    sign_manifest(m, priv2)

    with pytest.raises(ManifestError, match="signature invalid|verification failed"):
        verify_rotation_chain(m, "key-1", pub1_b64)


# ===========================================================================
# 3. TL unavailable → 503 in strict mode, warn in relaxed (H2 regression)
# ===========================================================================


def test_tl_off_log_always_raises():
    off = _OffLog()
    with pytest.raises(TransparencyLogUnavailable):
        off.submit({"test": "data"})
    with pytest.raises(TransparencyLogUnavailable):
        from stigmem_node.identity.transparency_log import LogEntry

        off.verify_inclusion(LogEntry("", "", 0, 0))


def test_manifest_put_strict_mode_tl_unavailable_returns_503(strict_client: TestClient):
    priv, pub_b64, _ = fed_keypair()
    m = make_manifest(priv, pub_b64, entity_uri="https://strict-test.org", days_valid=30)
    body = manifest_to_dict(m)
    # strict_client has tl_backend="off" → TransparencyLogUnavailable → 503
    resp = strict_client.put("/v1/federation/manifest", json=body)
    assert resp.status_code == 503, resp.text


def test_manifest_put_relaxed_mode_tl_unavailable_warns(identity_client: TestClient):
    priv, pub_b64, _ = fed_keypair()
    m = make_manifest(priv, pub_b64, entity_uri="https://relaxed-test.org", days_valid=30)
    body = manifest_to_dict(m)
    # identity_client has tl_backend="off" but trust_mode="relaxed" → warn, not 503
    resp = identity_client.put("/v1/federation/manifest", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "tl_warning" in data  # warning present but accepted


# ===========================================================================
# 4. Expired manifest → token issuance rejected (H1 regression)
# ===========================================================================
