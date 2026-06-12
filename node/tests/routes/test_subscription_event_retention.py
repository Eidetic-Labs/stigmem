"""M12 / F-AVAIL-2 — subscription_events retention prune.

The delivery sweep prunes terminal (delivered/failed) subscription_events
rows older than ``subscription_event_retention_s``.  The prune horizon is
clamped to >= ``subscription_replay_s`` so the replay window is never
truncated.  ``subscription_event_retention_s=0`` disables pruning.

Tests
-----
(a) delivered row older than retention window is pruned after a sweep.
(b) failed row older than retention window is pruned.
(c) pending/delivering rows older than the window are NOT pruned.
(d) delivered row NEWER than the window is NOT pruned.
(e) clamp: with retention_s < replay_s, an event within the replay
    window is NOT pruned (the clamp floor protects the replay window).
(f) retention_s=0 disables pruning entirely.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

import stigmem_node.db as db_mod
import stigmem_node.settings as settings_mod
import stigmem_node.subscription_delivery as delivery_mod

Settings = settings_mod.Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_subscription(conn, tenant_id: str = "tenant:test") -> str:
    """Insert a minimal subscription row and return its id."""
    sub_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    conn.execute(
        """INSERT INTO subscriptions
           (id, subscriber_identity, tenant_id, target_kind, target,
            on_change, delivery_address, circuit_open, created_at)
           VALUES (?,?,?,'scope','local','webhook','https://example.com/hook',0,?)""",
        (sub_id, f"stigmem://test/agent/{sub_id}", tenant_id, now),
    )
    return sub_id


def _insert_event(
    conn,
    sub_id: str,
    status: str,
    age_s: float,
) -> str:
    """Insert a subscription_events row with controlled created_at and status.

    ``age_s`` seconds in the past from now.
    """
    event_id = str(uuid.uuid4())
    created_at = datetime.fromtimestamp(
        datetime.now(UTC).timestamp() - age_s, UTC
    ).isoformat()
    conn.execute(
        """INSERT INTO subscription_events
           (id, subscription_id, event_type, entity_uri, fact_id,
            payload, created_at, delivery_status)
           VALUES (?,?,'fact_asserted','stigmem://e1','f1',?,?,?)""",
        (event_id, sub_id, json.dumps({"id": "f1"}), created_at, status),
    )
    return event_id


def _row_exists(conn, event_id: str) -> bool:
    row = conn.execute(
        "SELECT id FROM subscription_events WHERE id=?", (event_id,)
    ).fetchone()
    return row is not None


def _patch_settings(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> Settings:
    """Build a test Settings with the given overrides and patch all modules."""
    base = settings_mod.settings
    new_settings = Settings(
        db_path=base.db_path,
        storage_backend=getattr(base, "storage_backend", "sqlite"),
        auth_required=False,
        subscription_delivery_sweep_s=86400,
        **overrides,  # type: ignore[arg-type]
    )
    monkeypatch.setattr(settings_mod, "settings", new_settings)
    monkeypatch.setattr(delivery_mod, "_settings_pkg", settings_mod)
    return new_settings


# ---------------------------------------------------------------------------
# (a) delivered row older than retention window is pruned
# ---------------------------------------------------------------------------


def test_delivered_old_row_pruned(client, monkeypatch):  # noqa: ANN001
    """(a) A delivered event older than retention_s is deleted by the sweep."""
    retention_s = 3600  # 1 hour window
    age_s = 7200  # created 2 hours ago — outside the window

    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=retention_s,
        subscription_replay_s=300,  # replay << retention, clamp irrelevant
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        event_id = _insert_event(conn, sub_id, "delivered", age_s)

    # Patch _sanitize_payload and httpx so the sweep doesn't try real HTTP.
    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert not _row_exists(conn, event_id), (
            f"delivered event {event_id} older than retention_s={retention_s} "
            "should have been pruned"
        )


# ---------------------------------------------------------------------------
# (b) failed row older than retention window is pruned
# ---------------------------------------------------------------------------


def test_failed_old_row_pruned(client, monkeypatch):  # noqa: ANN001
    """(b) A failed event older than retention_s is deleted by the sweep."""
    retention_s = 3600
    age_s = 7200

    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=retention_s,
        subscription_replay_s=300,
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        event_id = _insert_event(conn, sub_id, "failed", age_s)

    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert not _row_exists(conn, event_id), (
            f"failed event {event_id} older than retention_s={retention_s} "
            "should have been pruned"
        )


# ---------------------------------------------------------------------------
# (c) pending/delivering rows older than the window are NOT pruned
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["pending", "delivering"])
def test_non_terminal_row_not_pruned(client, monkeypatch, status):  # noqa: ANN001
    """(c) Non-terminal rows (pending/delivering) are never pruned."""
    retention_s = 3600
    age_s = 7200  # well outside retention window

    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=retention_s,
        subscription_replay_s=300,
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        event_id = _insert_event(conn, sub_id, status, age_s)

    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert _row_exists(conn, event_id), (
            f"non-terminal event with status={status!r} must NOT be pruned"
        )


# ---------------------------------------------------------------------------
# (d) delivered row NEWER than the window is NOT pruned
# ---------------------------------------------------------------------------


def test_delivered_recent_row_not_pruned(client, monkeypatch):  # noqa: ANN001
    """(d) A delivered event within the retention window is kept."""
    retention_s = 3600
    age_s = 60  # 1 minute old — well inside the window

    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=retention_s,
        subscription_replay_s=300,
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        event_id = _insert_event(conn, sub_id, "delivered", age_s)

    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert _row_exists(conn, event_id), (
            f"delivered event {event_id} within retention window should NOT be pruned"
        )


# ---------------------------------------------------------------------------
# (e) clamp: retention_s < replay_s → event in replay window not pruned
# ---------------------------------------------------------------------------


def test_clamp_protects_replay_window(client, monkeypatch):  # noqa: ANN001
    """(e) When retention_s < replay_s the clamp floor prevents pruning replay events.

    retention_s=60 (1 min), replay_s=3600 (1 hour).
    An event 120 s old is beyond retention_s but inside replay_s.
    After clamping, effective_retention_s = max(60, 3600) = 3600.
    The event must NOT be pruned.
    """
    retention_s = 60    # configured retention: only 1 minute
    replay_s = 3600     # replay window: 1 hour
    age_s = 120         # event is 2 minutes old — beyond retention but inside replay

    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=retention_s,
        subscription_replay_s=replay_s,
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        event_id = _insert_event(conn, sub_id, "delivered", age_s)

    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert _row_exists(conn, event_id), (
            "clamp failed: event inside replay_s should NOT be pruned even when "
            "retention_s is smaller than replay_s"
        )


# ---------------------------------------------------------------------------
# (f) retention_s=0 disables pruning entirely
# ---------------------------------------------------------------------------


def test_retention_disabled_when_zero(client, monkeypatch):  # noqa: ANN001
    """(f) subscription_event_retention_s=0 disables pruning (nothing deleted)."""
    _patch_settings(
        monkeypatch,
        subscription_event_retention_s=0,
        subscription_replay_s=300,
    )

    with db_mod.db() as conn:
        sub_id = _insert_subscription(conn)
        # Age far beyond any plausible window.
        delivered_id = _insert_event(conn, sub_id, "delivered", 10_000_000)
        failed_id = _insert_event(conn, sub_id, "failed", 10_000_000)

    with patch("stigmem_node.subscription_delivery._sanitize_payload", return_value=None):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        assert _row_exists(conn, delivered_id), (
            "retention=0: delivered row should NOT be pruned"
        )
        assert _row_exists(conn, failed_id), (
            "retention=0: failed row should NOT be pruned"
        )
