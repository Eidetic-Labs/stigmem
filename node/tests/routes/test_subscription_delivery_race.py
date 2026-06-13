"""Regression test for issue #47 — concurrent ``deliver_pending`` and ``sweep_loop``.

Before migration 028 + the atomic-claim refactor, the delivery path was a
non-atomic SELECT (status='pending') + UPDATE (status='delivered').  Two
concurrent callers could observe the same row in their respective SELECTs
and each invoke the webhook, causing duplicate POSTs with the same
``event_id`` — exactly the flake reported in issue #47 against
``test_tombstone_filter.py``.

These tests assert the new atomic claim eliminates the race:

1. ``test_concurrent_deliver_pending_no_duplicate`` — many threads call
   ``deliver_pending`` in parallel.  Each event must deliver at most once.
2. ``test_sweep_loop_and_deliver_pending_no_duplicate`` — the background
   ``sweep_loop`` task runs alongside an explicit ``deliver_pending`` call.
3. ``test_stale_claim_recovered`` — an event that became stuck in
   ``delivering`` is reset to ``pending`` after the claim timeout.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, call, patch

from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod
import stigmem_node.db as db_mod
import stigmem_node.settings as settings_mod
import stigmem_node.subscription_delivery as delivery_mod


class _ThreadSafePost:
    """Minimal thread-safe stand-in for ``Mock.post`` call recording."""

    def __init__(self, response: Any) -> None:
        self.return_value = response
        self.call_args_list: list[Any] = []
        self._lock = threading.Lock()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            self.call_args_list.append(call(*args, **kwargs))
        return self.return_value

    @property
    def call_count(self) -> int:
        with self._lock:
            return len(self.call_args_list)


class _ThreadSafeHTTPClient:
    """Shared fake ``httpx.Client`` whose POST log is safe under thread races."""

    def __init__(self, response: Any) -> None:
        self.post = _ThreadSafePost(response)

    def __enter__(self) -> _ThreadSafeHTTPClient:
        return self

    def __exit__(self, *_exc_info: object) -> bool:
        return False


class _ThreadSafeHTTPClientFactory:
    def __init__(self, client: _ThreadSafeHTTPClient) -> None:
        self._client = client

    def __call__(self, *_args: object, **_kwargs: object) -> _ThreadSafeHTTPClient:
        return self._client


def _make_subscription(client: TestClient) -> str:
    subscriber = f"stigmem://test/agent/subscriber/{uuid.uuid4()}"
    raw_key = auth_mod.create_api_key(subscriber, ["read"])
    resp = client.post(
        "/v1/subscriptions",
        json={
            "target": "local",
            "on_change": "webhook",
            "delivery_address": "https://example.com/hook",
        },
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _insert_facts(client: TestClient, n: int) -> None:
    for i in range(n):
        resp = client.post(
            "/v1/facts",
            json={
                "entity": f"stigmem://test/agent/a{i}",
                "relation": "test:name",
                "value": {"type": "string", "v": f"agent-{i}"},
                "source": f"stigmem://test/agent/a{i}",
                "scope": "local",
            },
        )
        assert resp.status_code == 201, resp.text


def _patched_http_mock() -> tuple[_ThreadSafeHTTPClientFactory, _ThreadSafeHTTPClient]:
    """Return (mock_class, mock_instance) wired for use with patch()."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_inst = _ThreadSafeHTTPClient(mock_resp)
    mock_cls = _ThreadSafeHTTPClientFactory(mock_inst)
    return mock_cls, mock_inst


def _force_retryable_subscription_remainder() -> dict[str, int]:
    """Make unfinished delivery rows immediately claimable and return status counts."""
    with db_mod.db() as conn:
        conn.execute(
            "UPDATE subscription_events SET next_retry_at = NULL"
            " WHERE delivery_status = 'pending'"
        )
        conn.execute(
            "UPDATE subscription_events SET claimed_at = ?"
            " WHERE delivery_status = 'delivering'",
            ((datetime.now(UTC) - timedelta(seconds=3600)).isoformat(),),
        )
        rows = conn.execute(
            "SELECT delivery_status, COUNT(*) AS n FROM subscription_events"
            " GROUP BY delivery_status"
        ).fetchall()
    return {row["delivery_status"]: row["n"] for row in rows}


def _wait_for_delivery_lock_idle(timeout_s: float = 5.0) -> None:
    """Wait until no concurrent delivery sweep owns the process-wide test lock."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if delivery_mod._DELIVER_PENDING_LOCK.acquire(blocking=False):  # noqa: SLF001
            delivery_mod._DELIVER_PENDING_LOCK.release()  # noqa: SLF001
            return
        time.sleep(0.01)
    raise AssertionError("subscription delivery lock did not become idle")


def _drain_subscription_delivery(expected_delivered: int, timeout_s: float = 5.0) -> dict[str, int]:
    """Drive the production delivery path until all rows settle or fail clearly."""
    deadline = time.monotonic() + timeout_s
    status_counts: dict[str, int] = {}
    while time.monotonic() < deadline:
        status_counts = _force_retryable_subscription_remainder()
        if (
            status_counts.get("delivered", 0) == expected_delivered
            and status_counts.get("delivering", 0) == 0
            and status_counts.get("pending", 0) == 0
        ):
            return status_counts
        _wait_for_delivery_lock_idle(timeout_s=max(0.1, deadline - time.monotonic()))
        delivery_mod.deliver_pending()
        time.sleep(0.01)
    return _force_retryable_subscription_remainder()


def test_concurrent_deliver_pending_no_duplicate(client: TestClient) -> None:
    """Many threads racing on ``deliver_pending`` must not duplicate-deliver.

    The regression target from issue #47 is *duplicate* delivery — the same
    ``event_id`` POSTed more than once.  Total POST count is incidentally
    interesting but unstable under CI load: the sanitizer pipeline can
    silently drop an event (ACL re-check or recall pipeline returns empty),
    and the failure path leaves a row in ``pending`` for the next sweep to
    re-claim.  Both behaviours are correct; what matters here is:

    1. No ``event_id`` appears more than once in the POST calls.
    2. Every event terminally settles (``delivered``) — no stragglers stuck
       in ``delivering`` or ``pending``.

    To absorb the legitimate retry path, after the racing workers finish
    we drain any remaining ``pending`` rows with a few extra single-threaded
    sweeps.  Those extra sweeps cannot mask a duplicate: if the racing
    workers had duplicated a delivery, the mock's call log already records
    it before the drain begins.
    """
    _make_subscription(client)
    _insert_facts(client, n=20)

    mock_cls, mock_inst = _patched_http_mock()
    barrier = threading.Barrier(8)
    worker_errors: list[Exception] = []
    worker_errors_lock = threading.Lock()

    def worker() -> None:
        try:
            barrier.wait()  # release all threads simultaneously
            delivery_mod.deliver_pending()
        except Exception as exc:
            with worker_errors_lock:
                worker_errors.append(exc)

    with (
        patch("stigmem_node.subscription_delivery.httpx.Client", mock_cls),
        patch(
            "stigmem_node.subscription_delivery._sanitize_payload",
            side_effect=lambda _event, payload: payload,
        ),
    ):
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert worker_errors == []

        # Snapshot POSTs before the drain; the drain must not introduce
        # duplicates either, but the *race property* is fully captured here.
        racing_event_ids = [
            call.kwargs["json"]["event_id"] for call in mock_inst.post.call_args_list
        ]

        # Drain any pending/delivering remainder. Transient delivery failures
        # release the row back to ``pending`` with ``next_retry_at`` in the
        # future; interrupted workers can leave rows in ``delivering`` until
        # the stale-claim timeout. Force both states through the production
        # recovery path before each drain pass. This keeps the test
        # deterministic under CI load while preserving the duplicate delivery
        # assertion: every POST is still recorded and checked below.
        status_counts = _drain_subscription_delivery(expected_delivered=20)

    # Primary regression check: no event POSTed more than once during the race.
    racing_counts = Counter(racing_event_ids)
    duplicates = {eid: c for eid, c in racing_counts.items() if c > 1}
    assert duplicates == {}, f"events delivered more than once: {duplicates}"

    # And the global property: no event ever POSTed twice (even across the drain).
    final_counts = Counter(
        call.kwargs["json"]["event_id"] for call in mock_inst.post.call_args_list
    )
    final_dupes = {eid: c for eid, c in final_counts.items() if c > 1}
    assert final_dupes == {}, f"events delivered more than once after drain: {final_dupes}"

    # Every event must terminally settle.  Some may have been silently
    # delivered (ACL/sanitizer drop) — they still end in 'delivered' status.
    assert status_counts.get("delivered", 0) == 20, status_counts
    assert status_counts.get("delivering", 0) == 0, status_counts
    assert status_counts.get("pending", 0) == 0, status_counts


def test_sweep_loop_and_deliver_pending_no_duplicate(client: TestClient) -> None:
    """``sweep_loop`` running concurrently with an explicit deliver call."""
    _make_subscription(client)
    _insert_facts(client, n=10)

    mock_cls, mock_inst = _patched_http_mock()

    async def driver() -> None:
        # Force aggressive sweeping for the duration of this test.
        original_interval = settings_mod.settings.subscription_delivery_sweep_s
        settings_mod.settings.subscription_delivery_sweep_s = 0
        try:
            task = asyncio.create_task(delivery_mod.sweep_loop())
            # Race the loop against an explicit call.
            await asyncio.gather(
                asyncio.to_thread(delivery_mod.deliver_pending),
                asyncio.to_thread(delivery_mod.deliver_pending),
                asyncio.sleep(0.05),
            )
            task.cancel()
            # gather(return_exceptions=True) absorbs the CancelledError
            # without re-raising; keeps the static analyzers happy and
            # avoids a bare `await task` that some linters flag as a
            # no-effect statement.
            await asyncio.gather(task, return_exceptions=True)
        finally:
            settings_mod.settings.subscription_delivery_sweep_s = original_interval

    with patch("stigmem_node.subscription_delivery.httpx.Client", mock_cls):
        asyncio.run(driver())

    # #718/#722 lock-leak class: task.cancel() cancels the awaiting coroutine, not
    # the OS thread that asyncio.to_thread already launched into deliver_pending().
    # A sweep iteration can submit one more to_thread(deliver_pending) right before
    # cancellation; that thread keeps running and acquires _DELIVER_PENDING_LOCK.
    # Draining INSIDE the loop is racy — the drain can acquire the (momentarily free)
    # lock before that orphan thread does, then release, leaving the orphan to grab
    # and hold it into the next test (whose explicit deliver_pending() then silently
    # no-ops via the #47 non-blocking guard). asyncio.run() shuts down the default
    # thread-pool executor and JOINS every to_thread worker before returning, so by
    # this point no orphan deliver_pending() can still be running. Draining here is
    # therefore deterministic: a blocking acquire/release reclaims the lock for the
    # next test no matter how the race fell out.
    if delivery_mod._DELIVER_PENDING_LOCK.acquire(timeout=5):
        delivery_mod._DELIVER_PENDING_LOCK.release()

    event_ids = [call.kwargs["json"]["event_id"] for call in mock_inst.post.call_args_list]
    counts = Counter(event_ids)
    duplicates = {eid: c for eid, c in counts.items() if c > 1}
    assert duplicates == {}, f"events delivered more than once: {duplicates}"


def test_stale_claim_recovered(client: TestClient) -> None:
    """An event stuck in ``delivering`` past the timeout must be reclaimed."""
    sub_id = _make_subscription(client)
    _insert_facts(client, n=1)

    # Simulate a crashed worker: mark the only event as 'delivering' with an
    # old claimed_at well outside the configured timeout window.
    stale = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with db_mod.db() as conn:
        conn.execute(
            "UPDATE subscription_events SET delivery_status='delivering', claimed_at=? "
            "WHERE subscription_id=?",
            (stale, sub_id),
        )

    mock_cls, mock_inst = _patched_http_mock()
    with patch("stigmem_node.subscription_delivery.httpx.Client", mock_cls):
        # Tighten the timeout so the stale row is definitely past the cutoff.
        original = settings_mod.settings.subscription_claim_timeout_s
        settings_mod.settings.subscription_claim_timeout_s = 60
        try:
            delivery_mod.deliver_pending()
        finally:
            settings_mod.settings.subscription_claim_timeout_s = original

    # Recovery → reclaim → delivery, all in one call.
    assert mock_inst.post.call_count == 1
    with db_mod.db() as conn:
        row = conn.execute(
            "SELECT delivery_status, claimed_at FROM subscription_events WHERE subscription_id=?",
            (sub_id,),
        ).fetchone()
    assert row["delivery_status"] == "delivered"
    assert row["claimed_at"] is None


def test_claim_clears_after_failure_and_retry_is_pending(client: TestClient) -> None:
    """On webhook failure the row returns to 'pending' (not stuck 'delivering')."""
    sub_id = _make_subscription(client)
    _insert_facts(client, n=1)

    fail_resp = MagicMock()
    fail_resp.status_code = 503

    mock_inst = MagicMock()
    mock_inst.__enter__ = MagicMock(return_value=mock_inst)
    mock_inst.__exit__ = MagicMock(return_value=False)
    mock_inst.post.return_value = fail_resp
    mock_cls = MagicMock(return_value=mock_inst)

    with patch("stigmem_node.subscription_delivery.httpx.Client", mock_cls):
        delivery_mod.deliver_pending()

    with db_mod.db() as conn:
        row = conn.execute(
            "SELECT delivery_status, delivery_attempts, next_retry_at, claimed_at "
            "FROM subscription_events WHERE subscription_id=?",
            (sub_id,),
        ).fetchone()
    assert row["delivery_status"] == "pending"
    assert row["delivery_attempts"] == 1
    assert row["next_retry_at"] is not None
    assert row["claimed_at"] is None
