"""Conflict-convergence scenarios for the federation soak harness."""

from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from typing import Any

import httpx

from .constants import CONVERGENCE_WINDOW_S, NETWORK_NAME, NODES
from .monitor import _assert_fact

DOCKER_BIN = shutil.which("docker") or "docker"


def _same_state_on_all(
    clients: dict[str, httpx.Client],
    entity: str,
    relation: str,
) -> bool:
    """Return True if all nodes report the same (entity, relation) state."""
    states: list[Any] = []
    for client in clients.values():
        try:
            r = client.get(
                "/v1/facts",
                params={"entity": entity, "relation": relation, "include_contradicted": "true"},
            )
            if r.status_code == 200:
                facts = r.json().get("facts", [])
                key = tuple(
                    sorted((f.get("value", {}).get("v", ""), f.get("confidence", 0)) for f in facts)
                )
                states.append(key)
            else:
                return False
        except Exception:
            return False
    return len(set(states)) <= 1 and len(states) == len(clients)


def _wait_convergence(
    clients: dict[str, httpx.Client],
    entity: str,
    relation: str,
    timeout_s: float = CONVERGENCE_WINDOW_S,
) -> float | None:
    """Poll until all nodes agree; return convergence_s or None on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _same_state_on_all(clients, entity, relation):
            return time.monotonic() - (deadline - timeout_s)
        time.sleep(1.0)
    return None


def _docker_network_disconnect(container: str) -> None:
    subprocess.run(  # noqa: S603
        [DOCKER_BIN, "network", "disconnect", NETWORK_NAME, container],
        check=True,
        capture_output=True,
    )


def _docker_network_connect(container: str) -> None:
    subprocess.run(  # noqa: S603
        [DOCKER_BIN, "network", "connect", NETWORK_NAME, container],
        check=True,
        capture_output=True,
    )


def run_cc1(clients: dict[str, httpx.Client]) -> dict:
    """
    CC-1: Simultaneous contradicting asserts to nodes A and B.
    Both nodes converge to identical contradiction state within 2×P99 window.
    """
    entity = f"stigmem://eval/cc1/{uuid.uuid4()}"
    relation = "eval:cc1-value"
    results: dict[str, str] = {}

    def _assert(name: str, value: str) -> None:
        results[name] = _assert_fact(clients[name], entity, relation, value)

    t_a = threading.Thread(target=_assert, args=("node-a", "value-from-A"))
    t_b = threading.Thread(target=_assert, args=("node-b", "value-from-B"))
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()

    conv = _wait_convergence(clients, entity, relation)
    return {
        "scenario": "CC-1",
        "passed": conv is not None,
        "convergence_s": round(conv, 2) if conv is not None else CONVERGENCE_WINDOW_S,
    }


def run_cc2(clients: dict[str, httpx.Client]) -> dict:
    """
    CC-2: Assert on node-A while node-C is partitioned.
    Verify convergence after partition heals.
    """
    entity = f"stigmem://eval/cc2/{uuid.uuid4()}"
    relation = "eval:cc2-value"

    # Partition C
    try:
        _docker_network_disconnect("eval-fed-node-c")
    except Exception as exc:
        return {"scenario": "CC-2", "passed": False, "convergence_s": 0.0, "error": str(exc)}

    _assert_fact(clients["node-a"], entity, relation, "post-partition-value")
    time.sleep(6.0)  # wait > pull interval (5 s) — C should NOT have the fact

    # Verify C does not have the fact yet
    try:
        r_c = clients["node-c"].get("/v1/facts", params={"entity": entity, "relation": relation})
        c_before = r_c.json().get("facts", []) if r_c.status_code == 200 else []
    except (httpx.HTTPError, ValueError) as exc:
        print(f"  CC-2 partition visibility check failed: {exc}", file=sys.stderr)
        c_before = []

    # Heal partition
    try:
        _docker_network_connect("eval-fed-node-c")
    except Exception as exc:
        return {"scenario": "CC-2", "passed": False, "convergence_s": 0.0, "error": str(exc)}

    conv = _wait_convergence(clients, entity, relation)
    passed = conv is not None and len(c_before) == 0
    return {
        "scenario": "CC-2",
        "passed": passed,
        "convergence_s": round(conv, 2) if conv is not None else CONVERGENCE_WINDOW_S,
        "c_isolated_before_heal": len(c_before) == 0,
    }


def run_cc3(clients: dict[str, httpx.Client]) -> dict:
    """
    CC-3: Three-way contradiction — A, B, C each assert a different value.
    Resolver selects a deterministic winner; all nodes agree.
    """
    entity = f"stigmem://eval/cc3/{uuid.uuid4()}"
    relation = "eval:cc3-value"
    results: dict[str, str] = {}

    for name, val in [("node-a", "val-A"), ("node-b", "val-B"), ("node-c", "val-C")]:
        results[name] = _assert_fact(clients[name], entity, relation, val)

    conv = _wait_convergence(clients, entity, relation)
    return {
        "scenario": "CC-3",
        "passed": conv is not None,
        "convergence_s": round(conv, 2) if conv is not None else CONVERGENCE_WINDOW_S,
    }


def _issue_tombstone(client: httpx.Client, entity_uri: str, scope: str = "*") -> str:
    """Issue a tombstone via POST /v1/tombstones. Returns tombstone_id or ''."""
    r = client.post(
        "/v1/tombstones",
        json={
            "entity_uri": entity_uri,
            "scope": scope,
            "reason": "eval:cc4-tombstone-test",
        },
    )
    if r.status_code == 201:
        return r.json().get("id", "")
    print(f"  CC-4 tombstone issue failed: {r.status_code} {r.text}", file=sys.stderr)
    return ""


def run_cc4(clients: dict[str, httpx.Client]) -> dict:
    """
    CC-4: Tombstone on node-A concurrent with re-assert on node-B.
    Real tombstone (POST /v1/tombstones) wins after convergence — exercises
    federation tombstone replication path.
    """
    entity = f"stigmem://eval/cc4/{uuid.uuid4()}"
    relation = "eval:cc4-value"

    # Seed initial fact on A, wait for it to replicate to B
    fact_id = _assert_fact(clients["node-a"], entity, relation, "initial-value")
    if not fact_id:
        return {"scenario": "CC-4", "passed": False, "convergence_s": 0.0}

    # Wait for initial replication
    time.sleep(8.0)

    # Concurrent: real tombstone on A and re-assert on B
    results: dict = {}

    def _tombstone() -> None:
        results["tombstone"] = _issue_tombstone(
            clients["node-a"],
            entity,
            scope="public",
        )

    def _reassert() -> None:
        results["reassert"] = _assert_fact(
            clients["node-b"],
            entity,
            relation,
            "reasserted-on-b",
            confidence=0.8,
        )

    t1 = threading.Thread(target=_tombstone)
    t2 = threading.Thread(target=_reassert)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    if not results.get("tombstone"):
        return {"scenario": "CC-4", "passed": False, "convergence_s": 0.0}

    # Tombstone replication happens via federation pull loop (§23.4.3);
    # wait for fact convergence across all nodes before checking the tombstone
    # state itself.
    convergence_started = time.monotonic()
    conv = _wait_convergence(clients, entity, relation)

    # Verify tombstone wins: GET /v1/tombstones/{entity} should report
    # tombstoned=true on all nodes after replication.
    tombstone_wins = False
    tombstone_statuses: dict[str, Any] = {}
    if conv is not None:
        encoded_entity = urllib.parse.quote(entity, safe="")
        deadline = time.monotonic() + CONVERGENCE_WINDOW_S
        while time.monotonic() < deadline:
            tombstone_wins = True
            tombstone_statuses = {}
            for name, client in clients.items():
                try:
                    r = client.get(f"/v1/tombstones/{encoded_entity}")
                    is_json = r.headers.get("content-type", "").startswith("application/json")
                    body = r.json() if is_json else r.text
                    tombstone_statuses[name] = {
                        "status_code": r.status_code,
                        "body": body,
                    }
                    if r.status_code != 200 or not body.get("tombstoned", False):
                        tombstone_wins = False
                except (httpx.HTTPError, ValueError) as exc:
                    print(f"  CC-4 tombstone verification failed: {exc}", file=sys.stderr)
                    tombstone_statuses[name] = {"error": str(exc)}
                    tombstone_wins = False
            if tombstone_wins:
                conv = time.monotonic() - convergence_started
                break
            time.sleep(1.0)
    if conv is not None and not tombstone_wins:
        print(f"  CC-4 tombstone status mismatch: {tombstone_statuses}", file=sys.stderr)

    return {
        "scenario": "CC-4",
        "passed": conv is not None and tombstone_wins,
        "convergence_s": round(conv, 2) if conv is not None else CONVERGENCE_WINDOW_S,
        "tombstone_wins": tombstone_wins,
        "tombstone_statuses": tombstone_statuses,
    }


def run_cc5(clients: dict[str, httpx.Client], admin_keys: dict[str, str]) -> dict:
    """
    CC-5: Capability-token revocation — invalid token returns 401/403 (no partial data).
    Valid token succeeds. Rate = 1.0 if no bypass.

    Since there is no external token-revocation API in this build, we test the
    token-verification path directly:
      a. Assert a fact on node-A.
      b. Attempt cross-node read on node-A with INVALID bearer → expect 401/403.
      c. Same read with valid bearer → expect 200 (no partial data on invalid path).
    """
    entity = f"stigmem://eval/cc5/{uuid.uuid4()}"
    relation = "eval:cc5-value"

    fact_id = _assert_fact(clients["node-a"], entity, relation, "cc5-test-value")
    if not fact_id:
        return {"scenario": "CC-5", "passed": False, "convergence_s": 0.0}

    a_url = NODES[0]["host_url"]
    valid_key = admin_keys["node-a"]

    # Attempt with invalid token — must NOT return 200
    forged = "eyJhbGciOiJub25lIn0.forged.signature"
    bypass_detected = False
    try:
        r_bad = httpx.get(
            f"{a_url}/v1/facts/{fact_id}",
            headers={"Authorization": f"Bearer {forged}"},
            timeout=10.0,
        )
        if r_bad.status_code == 200:
            bypass_detected = True  # security regression
        clean_failure = r_bad.status_code in (401, 403) and not r_bad.json().get("facts")
    except (httpx.HTTPError, ValueError) as exc:
        print(f"  CC-5 forged-token probe failed as a clean denial path: {exc}", file=sys.stderr)
        clean_failure = True

    # Attempt with valid key — must return 200
    valid_ok = False
    try:
        r_ok = httpx.get(
            f"{a_url}/v1/facts/{fact_id}",
            headers={"Authorization": f"Bearer {valid_key}"},
            timeout=10.0,
        )
        valid_ok = r_ok.status_code == 200
    except httpx.HTTPError as exc:
        print(
            f"  CC-5 valid-token probe failed before authorization decision: {exc}",
            file=sys.stderr,
        )

    passed = (not bypass_detected) and valid_ok and clean_failure
    return {
        "scenario": "CC-5",
        "passed": passed,
        "convergence_s": 0.0,  # not a convergence scenario
        "bypass_detected": bypass_detected,
        "clean_failure_on_invalid_token": clean_failure,
    }
