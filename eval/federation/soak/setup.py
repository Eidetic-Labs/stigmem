"""Setup phase helpers for the federation soak harness."""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta

import canonicaljson
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .constants import COMPOSE_FILE, ENV_FILE, NODES, REPO_ROOT

DOCKER_BIN = shutil.which("docker") or "docker"


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _generate_keypair() -> tuple[str, str]:
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
    return pub_b64, priv_b64


def ensure_keypairs() -> dict[str, str]:
    """Generate keypairs for all 3 nodes and write to .env (idempotent)."""
    if ENV_FILE.exists():
        env: dict[str, str] = {}
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip()
        if all(f"NODE_{letter}_PUBKEY" in env for letter in ("A", "B", "C")):
            print(f"  keypairs: loaded from {ENV_FILE}")
            return env

    lines: list[str] = []
    env = {}
    for letter in ("A", "B", "C"):
        pub, priv = _generate_keypair()
        lines += [f"NODE_{letter}_PUBKEY={pub}", f"NODE_{letter}_PRIVKEY={priv}"]
        env[f"NODE_{letter}_PUBKEY"] = pub
        env[f"NODE_{letter}_PRIVKEY"] = priv

    ENV_FILE.write_text("\n".join(lines) + "\n")
    print(f"  keypairs: generated → {ENV_FILE}")
    return env


def _docker_compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [
        DOCKER_BIN,
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "--env-file",
        str(ENV_FILE),
        *args,
    ]
    return subprocess.run(cmd, capture_output=False, check=check, cwd=str(REPO_ROOT))  # noqa: S603


def _docker_compose_quiet(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [
        DOCKER_BIN,
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "--env-file",
        str(ENV_FILE),
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=str(REPO_ROOT))  # noqa: S603


def start_cluster() -> None:
    print("→ Starting 3-node eval federation cluster (build may take a moment)…")
    _docker_compose("up", "--build", "-d")


def dump_cluster_diagnostics() -> None:
    """Print Compose state and recent logs for failed startup debugging."""

    print("→ Federation cluster diagnostics", file=sys.stderr)
    ps = _docker_compose_quiet("ps", "--all", check=False)
    if ps.stdout.strip():
        print("docker compose ps --all:", file=sys.stderr)
        print(ps.stdout.rstrip(), file=sys.stderr)
    if ps.stderr.strip():
        print(ps.stderr.rstrip(), file=sys.stderr)

    for node in NODES:
        logs = _docker_compose_quiet(
            "logs", "--no-color", "--tail", "80", node["name"], check=False
        )
        print(f"logs for {node['name']} ({node['container']}):", file=sys.stderr)
        if logs.stdout.strip():
            print(logs.stdout.rstrip(), file=sys.stderr)
        if logs.stderr.strip():
            print(logs.stderr.rstrip(), file=sys.stderr)


def wait_healthy(timeout_s: float = 120.0) -> None:
    print("→ Waiting for all 3 nodes to be healthy…")
    deadline = time.monotonic() + timeout_s
    for node in NODES:
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                r = httpx.get(f"{node['host_url']}/healthz", timeout=5.0)
                if r.status_code == 200:
                    print(f"  {node['name']}: healthy")
                    break
            except httpx.HTTPError as exc:
                last_error = exc
            time.sleep(2.0)
        else:
            if last_error is not None:
                print(f"  {node['name']}: last health check error: {last_error}", file=sys.stderr)
            dump_cluster_diagnostics()
            raise RuntimeError(f"{node['name']} did not become healthy within {timeout_s:.0f} s")


def create_admin_key(container: str) -> str:
    """Create an admin API key via docker exec."""
    result = subprocess.run(  # noqa: S603
        [
            DOCKER_BIN,
            "exec",
            container,
            "python",
            "-c",
            (
                "from stigmem_node.auth import create_api_key; "
                "print(create_api_key("
                "'eval:admin', ['read','write','federate','admin','admin:federation']"
                "))"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def publish_eval_admin_manifest(env: dict[str, str], admin_keys: dict[str, str]) -> None:
    """Publish the eval tombstone signer manifest to every node."""
    print("→ Publishing eval admin signing manifest…")

    priv_raw = base64.urlsafe_b64decode(_pad(env["NODE_A_PRIVKEY"]))
    priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
    pub = priv.public_key()
    pub_b64 = (
        base64.urlsafe_b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    key_id = hashlib.sha256(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()[:16]
    issued_at = datetime.now(UTC).replace(microsecond=0)
    manifest = {
        "entity_uri": "eval:admin",
        "key_id": key_id,
        "public_key": pub_b64,
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(days=1)).isoformat(),
        "entities": ["eval:admin"],
        "rotation_events": [],
        "signature": "",
    }
    signing_body = canonicaljson.encode_canonical_json(
        {
            "entities": manifest["entities"],
            "entity_uri": manifest["entity_uri"],
            "expires_at": manifest["expires_at"],
            "issued_at": manifest["issued_at"],
            "key_id": manifest["key_id"],
            "public_key": manifest["public_key"],
            "rotation_events": manifest["rotation_events"],
        }
    )
    manifest["signature"] = base64.urlsafe_b64encode(priv.sign(signing_body)).decode().rstrip("=")

    for node in NODES:
        resp = httpx.put(
            f"{node['host_url']}/v1/federation/manifest",
            json=manifest,
            headers={"Authorization": f"Bearer {admin_keys[node['name']]}"},
            timeout=15.0,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"{node['name']} manifest publish failed: {resp.status_code} {resp.text}"
            )
        print(f"  {node['name']}: manifest stored")
