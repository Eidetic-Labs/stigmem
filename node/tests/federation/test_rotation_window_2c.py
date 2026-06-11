"""Phase 2c — the origin-key rotation window is bounded by ``rotated_at`` + grace.

Inherited from 2a, amplified by relay: ``_keys_from_manifest`` returned
``{public_key} ∪ {prior key from the most recent rotation event}`` with NO
reference to WHEN the rotation happened — so a single rotation (e.g. because the
prior key was COMPROMISED) left the retired key in the accepted set INDEFINITELY,
forging valid origin signatures (direct AND relayed).

These tests pin the time bound directly on the shared resolver helper
``_keys_from_manifest`` (used by both ``resolve_origin_key`` and
``resolve_origin_key_for_relay``). Time is controlled by monkeypatching the
module-level ``_now`` clock the implementation uses, so the test owns "now".

Cases:
    (a) rotation rotated_at = now - 1h (within grace)   → prior key STILL accepted
    (b) rotation rotated_at = now - 200h (> 168h grace)  → prior key DROPPED
    (c) current key accepted regardless of rotation age
    (d) missing/unparseable rotated_at                   → prior key DROPPED (fail-closed)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from stigmem_node.federation import origin_identity as oi
from stigmem_node.identity.manifest import OrgManifest, RotationEvent

_CURRENT_KEY = "CURRENT_pubkey_b64url"
_PRIOR_KEY = "PRIOR_pubkey_b64url"


def _manifest_with_rotation(
    rotated_at: str, *, previous_public_key: str = _PRIOR_KEY
) -> OrgManifest:
    """Build an OrgManifest whose most-recent rotation event carries the retiring key.

    Only the fields ``_keys_from_manifest`` reads matter here (public_key +
    rotation_events[-1]); the manifest does not need to self-verify for this unit.
    """
    return OrgManifest(
        entity_uri="https://rot.example",
        key_id="kid-current",
        public_key=_CURRENT_KEY,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=["https://rot.example", "stigmem:node:rot"],
        rotation_events=[
            RotationEvent(
                previous_key_id="kid-prior",
                new_key_id="kid-current",
                new_public_key=_CURRENT_KEY,
                rotated_at=rotated_at,
                signature="sig",
                previous_public_key=previous_public_key,
            )
        ],
    )


def _freeze_now(monkeypatch, now: datetime) -> None:
    monkeypatch.setattr(oi, "_now", lambda: now)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def test_prior_key_within_grace_is_accepted(monkeypatch):
    """(a) A rotation 1h ago is well within the 168h grace → prior key STILL accepted."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _freeze_now(monkeypatch, now)
    manifest = _manifest_with_rotation(_iso(now - timedelta(hours=1)))

    keys = oi._keys_from_manifest(manifest)

    assert keys == {_CURRENT_KEY, _PRIOR_KEY}


def test_prior_key_past_grace_is_dropped(monkeypatch):
    """(b) A rotation 200h ago is past the 168h grace → prior key DROPPED.

    A stale (potentially compromised) prior key can no longer forge once the
    window has elapsed; only the current key remains.
    """
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _freeze_now(monkeypatch, now)
    manifest = _manifest_with_rotation(_iso(now - timedelta(hours=200)))

    keys = oi._keys_from_manifest(manifest)

    assert keys == {_CURRENT_KEY}
    assert _PRIOR_KEY not in keys


def test_current_key_always_accepted_regardless_of_age(monkeypatch):
    """(c) The current public_key is in the set no matter how old the rotation is."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _freeze_now(monkeypatch, now)
    fresh = _manifest_with_rotation(_iso(now - timedelta(hours=1)))
    stale = _manifest_with_rotation(_iso(now - timedelta(days=400)))

    assert _CURRENT_KEY in oi._keys_from_manifest(fresh)
    assert _CURRENT_KEY in oi._keys_from_manifest(stale)


def test_unparseable_rotated_at_fails_closed(monkeypatch):
    """(d) A missing/unparseable rotated_at → prior key DROPPED (fail-closed).

    If the age cannot be determined we refuse to extend trust to the prior key
    rather than accepting it indefinitely; the current key still works.
    """
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _freeze_now(monkeypatch, now)

    garbage = _manifest_with_rotation("not-a-timestamp")
    empty = _manifest_with_rotation("")

    assert oi._keys_from_manifest(garbage) == {_CURRENT_KEY}
    assert oi._keys_from_manifest(empty) == {_CURRENT_KEY}


def test_no_rotation_events_returns_only_current(monkeypatch):
    """Sanity: no rotation events at all → just the current key (unchanged behaviour)."""
    now = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    _freeze_now(monkeypatch, now)
    manifest = OrgManifest(
        entity_uri="https://rot.example",
        key_id="kid-current",
        public_key=_CURRENT_KEY,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=["https://rot.example"],
    )
    assert oi._keys_from_manifest(manifest) == {_CURRENT_KEY}
