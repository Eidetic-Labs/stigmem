"""Peer registration helpers for the federation soak harness."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .constants import NODES


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _sign_declaration(priv_b64: str, fields: dict) -> str:
    raw = base64.urlsafe_b64decode(_pad(priv_b64))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(privkey.sign(canonical)).decode().rstrip("=")


def _pubkey_fingerprint(pubkey: str) -> str:
    return f"sha256:{hashlib.sha256(pubkey.encode()).hexdigest()}"


def register_full_mesh(env: dict[str, str], admin_keys: dict[str, str]) -> None:
    """Register 6 bidirectional peer relationships (full mesh, 3-node)."""
    print("→ Registering full-mesh peers (6 registrations)…")
    success = skipped = failed = 0

    for registrar in NODES:
        r_name = registrar["name"]
        r_key = admin_keys[r_name]

        for peer in NODES:
            if peer["name"] == r_name:
                continue

            p_letter = peer["letter"]
            p_priv = env[f"NODE_{p_letter}_PRIVKEY"]
            p_pub = env[f"NODE_{p_letter}_PUBKEY"]

            # Fetch peer's node_id from well-known
            try:
                wk_resp = httpx.get(f"{peer['host_url']}/.well-known/stigmem", timeout=10.0)
                wk_resp.raise_for_status()
                node_id = wk_resp.json()["node_id"]
            except Exception as exc:
                print(
                    f"  {r_name} ← {peer['name']}: well-known fetch failed: {exc}", file=sys.stderr
                )
                failed += 1
                continue

            signed_at = datetime.now(UTC).isoformat()
            allowed_scopes = ["public", "company"]
            signed_fields = {
                "allowed_scopes": sorted(allowed_scopes),
                "federation_pubkey": p_pub,
                "node_id": node_id,
                "node_url": peer["internal_url"],
                "signed_at": signed_at,
            }
            sig = _sign_declaration(p_priv, signed_fields)

            payload = {
                "node_url": peer["internal_url"],
                "node_id": node_id,
                "federation_pubkey": p_pub,
                "allowed_scopes": sorted(allowed_scopes),
                "declaration_sig": sig,
                "signed_at": signed_at,
            }

            try:
                resp = httpx.post(
                    f"{registrar['host_url']}/v1/federation/peers",
                    json=payload,
                    headers={"Authorization": f"Bearer {r_key}"},
                    timeout=15.0,
                )
                if resp.status_code == 201 and resp.json().get("status") == "active":
                    success += 1
                    print(f"  {r_name} ← {peer['name']}: active")
                elif resp.status_code == 201 and resp.json().get("status") == "pending_approval":
                    peer_id = resp.json()["peer_id"]
                    approve_resp = httpx.post(
                        f"{registrar['host_url']}/v1/federation/peers/{peer_id}/approve",
                        json={"pubkey_fingerprint": _pubkey_fingerprint(p_pub)},
                        headers={"Authorization": f"Bearer {r_key}"},
                        timeout=15.0,
                    )
                    if (
                        approve_resp.status_code == 200
                        and approve_resp.json().get("status") == "active"
                    ):
                        success += 1
                        print(f"  {r_name} ← {peer['name']}: approved")
                    else:
                        failed += 1
                        print(
                            f"  {r_name} ← {peer['name']}: APPROVE FAILED "
                            f"{approve_resp.status_code} {approve_resp.text}",
                            file=sys.stderr,
                        )
                elif resp.status_code == 409:
                    skipped += 1
                else:
                    failed += 1
                    print(
                        f"  {r_name} ← {peer['name']}: FAILED {resp.status_code} {resp.text}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                failed += 1
                print(f"  {r_name} ← {peer['name']}: ERROR {exc}", file=sys.stderr)

    print(f"  peers: {success} active, {skipped} skipped, {failed} failed")
    if failed:
        raise RuntimeError("Peer registration had failures — aborting")


def make_client(node_name: str, admin_keys: dict[str, str]) -> httpx.Client:
    key = admin_keys[node_name]
    return httpx.Client(
        base_url=next(n["host_url"] for n in NODES if n["name"] == node_name),
        headers={"Authorization": f"Bearer {key}"},
        timeout=30.0,
    )
