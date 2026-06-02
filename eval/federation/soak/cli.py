"""Command-line entrypoint for the federation soak harness."""

from __future__ import annotations

import argparse
import signal
import time
from datetime import UTC, datetime

from .constants import NODES, RESULTS_DIR
from .peers import make_client, register_full_mesh
from .report import build_artifact, write_artifacts
from .run import run_workload
from .setup import (
    create_admin_key,
    ensure_keypairs,
    publish_eval_admin_manifest,
    start_cluster,
    wait_healthy,
)
from .teardown import stop_cluster


def main() -> int:
    parser = argparse.ArgumentParser(description="Federation soak workload driver")
    parser.add_argument("--duration", type=int, default=3600, help="Soak duration in seconds")
    parser.add_argument("--smoke", action="store_true", help="5-minute abbreviated run")
    parser.add_argument(
        "--no-teardown", action="store_true", help="Leave cluster running after soak"
    )
    args = parser.parse_args()

    duration_s = 300.0 if args.smoke else float(args.duration)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    run_date = datetime.now(UTC).isoformat()
    date_str = run_date[:10]

    print("=" * 60)
    print("Stigmem Federation Soak Harness")
    print(f"  duration={duration_s:.0f} s  smoke={args.smoke}")
    print("=" * 60)

    teardown_done = False

    def _cleanup(signum=None, frame=None) -> None:
        nonlocal teardown_done
        if not args.no_teardown and not teardown_done:
            teardown_done = True
            stop_cluster()

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        # Phase 1: bootstrap
        print("\n[Phase 1] Bootstrap")
        env = ensure_keypairs()
        start_cluster()
        wait_healthy()

        print("→ Creating per-node admin API keys…")
        admin_keys: dict[str, str] = {}
        for node in NODES:
            key = create_admin_key(node["container"])
            admin_keys[node["name"]] = key
            print(f"  {node['name']}: key created")

        publish_eval_admin_manifest(env, admin_keys)
        register_full_mesh(env, admin_keys)

        # Give the pull loop one cycle to initialize cursors
        print("→ Waiting for pull loop initialization (10 s)…")
        time.sleep(10.0)

        # Phase 2: workload
        print("\n[Phase 2] Workload")
        clients = {node["name"]: make_client(node["name"], admin_keys) for node in NODES}
        workload = run_workload(clients, admin_keys, duration_s, args.smoke)
        for client in clients.values():
            client.close()

        # Phase 3: artifact
        print("\n[Phase 3] Artifacts")
        artifact = build_artifact(run_date, duration_s, workload, args.smoke)
        json_path, md_path = write_artifacts(artifact, date_str)
        print(f"  JSON: {json_path}")
        print(f"  MD:   {md_path}")

        # Summary
        print("\n" + "=" * 60)
        status = "PASS" if artifact["overall_pass"] else "FAIL"
        print(f"Overall: {status}")
        for r in artifact["conflict_convergence"]:
            flag = "PASS" if r["passed"] else "FAIL"
            print(f"  {r['scenario']}: {flag} ({r['convergence_s']:.1f} s)")
        lag_p99_ab = artifact["replication_lag"]["node_a_to_b"]["p99_ms"]
        lag_p99_ac = artifact["replication_lag"]["node_a_to_c"]["p99_ms"]
        print(f"  Lag P99: A→B={lag_p99_ab:.0f} ms  A→C={lag_p99_ac:.0f} ms")
        print(f"  Token verification rate: {artifact['token_verification_rate']:.4f}")
        print(f"  Audit completeness: {artifact['audit_completeness']:.4f}")
        print("=" * 60)

        return 0 if artifact["overall_pass"] else 1

    finally:
        _cleanup()
