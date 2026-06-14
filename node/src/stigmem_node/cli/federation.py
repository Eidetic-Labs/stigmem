"""Federation CLI handlers."""

from __future__ import annotations

import argparse
import sys
from typing import Any


def _dnssec_pending_base_url(args: argparse.Namespace) -> str:
    """Resolve the local node base URL for the dnssec first-trust admin API."""
    from ..settings import settings

    return (args.node_url or settings.node_url).rstrip("/")


def _dnssec_auth_headers(args: argparse.Namespace) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"
    return headers


def _cmd_federation_dnssec_pending(args: argparse.Namespace) -> int:
    """List quarantined DNSSEC first-trust candidates (operator-confirm queue).

    Calls ``GET /v1/federation/dnssec/pending`` on the local node (admin-gated).
    """
    import json

    import httpx

    base = _dnssec_pending_base_url(args)
    try:
        resp = httpx.get(
            f"{base}/v1/federation/dnssec/pending",
            headers=_dnssec_auth_headers(args),
            timeout=15.0,
        )
    except Exception as exc:
        print(f"error: cannot reach node at {base}: {exc}", file=sys.stderr)
        return 1

    if resp.status_code != 200:
        print(f"error: node returned {resp.status_code}: {resp.text}", file=sys.stderr)
        return 1

    pending: list[dict[str, Any]] = resp.json().get("pending", [])
    print(json.dumps({"pending": pending}, indent=2))
    if not pending:
        print("no pending first-trust candidates", file=sys.stderr)
    return 0


def _cmd_federation_dnssec_confirm(args: argparse.Namespace) -> int:
    """Confirm a quarantined DNSSEC first-trust candidate (paste-to-confirm).

    Calls ``POST /v1/federation/dnssec/pending/confirm`` on the local node. The
    operator-supplied ``--key-fpr`` MUST byte-equal the stored candidate
    fingerprint (NF-D4-5); a mismatch is rejected by the node (no trust) and this
    command exits non-zero.
    """
    import json

    import httpx

    base = _dnssec_pending_base_url(args)
    payload = {
        "entity_uri": args.entity_uri,
        "node_id": args.node_id,
        "key_fpr": args.key_fpr,
    }
    try:
        resp = httpx.post(
            f"{base}/v1/federation/dnssec/pending/confirm",
            json=payload,
            headers=_dnssec_auth_headers(args),
            timeout=15.0,
        )
    except Exception as exc:
        print(f"error: cannot reach node at {base}: {exc}", file=sys.stderr)
        return 1

    if resp.status_code in (200, 201):
        print(json.dumps(resp.json(), indent=2))
        print("first-trust candidate confirmed and pinned", file=sys.stderr)
        return 0
    if resp.status_code == 422:
        print(
            "error: fingerprint did not match the quarantined candidate — not trusted",
            file=sys.stderr,
        )
        return 1
    if resp.status_code == 404:
        print("error: no such pending first-trust candidate", file=sys.stderr)
        return 1
    print(f"error: node returned {resp.status_code}: {resp.text}", file=sys.stderr)
    return 1


def _cmd_federation_dnssec_reject(args: argparse.Namespace) -> int:
    """Reject a quarantined DNSSEC first-trust candidate WITHOUT trusting it.

    Calls ``POST /v1/federation/dnssec/pending/reject`` on the local node.
    """
    import json

    import httpx

    base = _dnssec_pending_base_url(args)
    payload = {"entity_uri": args.entity_uri, "node_id": args.node_id}
    try:
        resp = httpx.post(
            f"{base}/v1/federation/dnssec/pending/reject",
            json=payload,
            headers=_dnssec_auth_headers(args),
            timeout=15.0,
        )
    except Exception as exc:
        print(f"error: cannot reach node at {base}: {exc}", file=sys.stderr)
        return 1

    if resp.status_code in (200, 204):
        if resp.status_code == 200 and resp.text:
            print(json.dumps(resp.json(), indent=2))
        print("first-trust candidate rejected", file=sys.stderr)
        return 0
    if resp.status_code == 404:
        print("error: no such pending first-trust candidate", file=sys.stderr)
        return 1
    print(f"error: node returned {resp.status_code}: {resp.text}", file=sys.stderr)
    return 1


def _cmd_federation_register_peer(args: argparse.Namespace) -> int:
    """Register this node as a peer with a remote node (Spec-05-Federation-Trust)."""
    import base64
    import json
    import ssl
    from datetime import UTC, datetime

    import httpx

    from ..db import apply_migrations
    from ..settings import settings

    # Ensure migrations are applied so keypair tables exist.
    apply_migrations()

    # Resolve local node URL: explicit flag > settings.
    local_url = (args.local_url or settings.node_url).rstrip("/")
    remote_url = args.remote_url.rstrip("/")
    allowed_scopes: list[str] = [s.strip() for s in args.scopes.split(",") if s.strip()]
    cert = (args.tls_cert, args.tls_key) if args.tls_cert and args.tls_key else None
    verify: ssl.SSLContext | str | bool | None = None
    if cert is not None:
        ssl_ctx = ssl.create_default_context(cafile=args.ca_bundle or None)
        ssl_ctx.load_cert_chain(*cert)
        verify = ssl_ctx
    elif args.ca_bundle:
        verify = args.ca_bundle

    # ------------------------------------------------------------------
    # 1. Fetch local /.well-known/stigmem to get our published metadata.
    # ------------------------------------------------------------------
    try:
        if verify is not None:
            with httpx.Client(timeout=15.0, trust_env=False, verify=verify) as client:
                wk = client.get(f"{local_url}/.well-known/stigmem")
        else:
            wk = httpx.get(f"{local_url}/.well-known/stigmem", timeout=10.0)
        wk.raise_for_status()
    except Exception as exc:
        print(f"error: cannot reach local node at {local_url}: {exc}", file=sys.stderr)
        return 1

    wk_data = wk.json()
    local_node_id: str = wk_data["node_id"]
    local_pubkey: str = wk_data.get("federation_pubkey", "")
    if not local_pubkey:
        print(
            "error: local node has no federation_pubkey in /.well-known/stigmem — "
            "set STIGMEM_FEDERATION_ENABLED=true and restart",
            file=sys.stderr,
        )
        return 1

    # ------------------------------------------------------------------
    # 2. Load local private key and sign the PeerDeclaration.
    # ------------------------------------------------------------------
    from ..federation.peer_token import init_federation_keys

    _, priv_b64 = init_federation_keys()

    def _pad(s: str) -> str:
        return s + "=" * (-len(s) % 4)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv_key = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(_pad(priv_b64)))

    signed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    signed_fields: dict[str, object] = {
        "allowed_scopes": sorted(allowed_scopes),
        "federation_pubkey": local_pubkey,
        "node_id": local_node_id,
        "node_url": local_url,
        "signed_at": signed_at,
    }
    canonical = json.dumps(signed_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_bytes = priv_key.sign(canonical)
    declaration_sig = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")

    # ------------------------------------------------------------------
    # 3. POST to the remote node.
    # ------------------------------------------------------------------
    payload = {
        "node_id": local_node_id,
        "node_url": local_url,
        "federation_pubkey": local_pubkey,
        "allowed_scopes": sorted(allowed_scopes),
        "signed_at": signed_at,
        "declaration_sig": declaration_sig,
    }

    headers = {"Content-Type": "application/json"}
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    try:
        if verify is not None:
            with httpx.Client(timeout=15.0, trust_env=False, verify=verify) as client:
                resp = client.post(
                    f"{remote_url}/v1/federation/peers",
                    json=payload,
                    headers=headers,
                )
        else:
            resp = httpx.post(
                f"{remote_url}/v1/federation/peers",
                json=payload,
                headers=headers,
                timeout=15.0,
            )
    except Exception as exc:
        print(f"error: cannot reach remote node at {remote_url}: {exc}", file=sys.stderr)
        return 1

    if resp.status_code in (200, 201):
        result = resp.json()
        peer_status = result.get("status", "unknown")
        peer_id = result.get("peer_id", "")
        if peer_status == "active":
            print(f"peer registered and verified (peer_id={peer_id})")
        else:
            print(
                f"peer registered but not yet active (status={peer_status}, peer_id={peer_id})\n"
                "Check that the remote node can reach this node's /.well-known/stigmem endpoint.",
                file=sys.stderr,
            )
            return 1
    elif resp.status_code == 409:
        print("peer already registered — nothing to do")
    else:
        print(
            f"error: remote node returned {resp.status_code}: {resp.text}",
            file=sys.stderr,
        )
        return 1

    return 0
