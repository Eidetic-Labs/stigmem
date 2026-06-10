"""Pull replication background task (spec §6.3).

The pull loop runs as an asyncio task in the app lifespan.
It is also callable directly for testing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
from datetime import UTC, datetime
from typing import Any

import httpx

from ..db import db
from ..multi_tenant_gate import multi_tenant_plugin_registered
from ..observability.metrics import FEDERATION_INGRESS, REPLICATION_LAG
from ..settings import settings
from .federation_ingest import (
    FederationIntegrityError,
    ingest_fact,
    node_is_multitenant,
    write_audit_log,
)
from .peer_policy import PeerPolicyError, resolve_ingest_tenant
from .peer_token import create_peer_token
from .tls import check_peer_san

logger = logging.getLogger("stigmem.federation.pull")

_MAX_BACKOFF_S = 300.0  # 5 minutes
_BASE_BACKOFF_S = 1.0


def _jitter(base: float) -> float:
    return base * (1 + random.uniform(-0.2, 0.2))  # noqa: S311  # nosec B311 — retry jitter, not crypto


def load_cursor(peer_id: str) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT cursor FROM replication_cursors WHERE peer_id = ? AND direction = 'inbound'",
            (peer_id,),
        ).fetchone()
    return row["cursor"] if row else None


def save_cursor(peer_id: str, cursor: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO replication_cursors (peer_id, direction, cursor, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(peer_id, direction)
               DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at""",
            (peer_id, "inbound", cursor, datetime.now(UTC).isoformat()),
        )


async def pull_from_peer_once(
    peer: dict[str, Any],
    client: httpx.AsyncClient,
    cursor: str | None,
) -> str | None:
    """Pull one page of facts from the peer. Returns the new cursor (or same if no more)."""
    allowed_scopes: list[str] = json.loads(peer["allowed_scopes"])
    token = create_peer_token(peer["node_id"], allowed_scopes)

    params: dict[str, Any] = {"limit": 100}
    if cursor:
        params["cursor"] = cursor

    backoff = _BASE_BACKOFF_S
    while True:
        try:
            resp = await client.get(
                f"{peer['node_url']}/v1/federation/facts",
                params=params,
                headers={"Authorization": f"Bearer {token}", "Stigmem-Verify": "full"},
                timeout=30.0,
            )
        except httpx.RequestError as exc:
            logger.warning("Pull network error from %s: %s", peer["node_id"], exc)
            return cursor  # retain old cursor; will retry next cycle

        if resp.status_code == 429:
            backoff = min(backoff * 2, _MAX_BACKOFF_S)
            delay = _jitter(backoff)
            logger.info("429 from %s — backing off %.1fs", peer["node_id"], delay)
            await asyncio.sleep(delay)
            token = create_peer_token(peer["node_id"], allowed_scopes)  # refresh token after sleep
            continue

        if resp.status_code != 200:
            logger.warning("Pull from %s returned %s", peer["node_id"], resp.status_code)
            return cursor

        # §22.1.2.4 — validate server cert URI SAN before consuming any data.
        if settings.mtls_enabled:
            ssl_obj = resp.extensions.get("ssl_object")
            peer_cert: dict[str, Any] = ssl_obj.getpeercert() if ssl_obj is not None else {}
            if peer_cert and not check_peer_san(peer_cert, peer["node_id"]):
                logger.warning(
                    "Client-side SAN mismatch from peer %s — cert URI SAN does not "
                    "match node_id; discarding response",
                    peer["node_id"],
                )
                write_audit_log(
                    peer["node_id"],
                    "san_mismatch",
                    {"peer_node_id": peer["node_id"], "direction": "pull"},
                )
                return cursor  # fail-closed: no data ingested from identity-mismatched peer
            if not peer_cert:
                logger.warning(
                    "mTLS peer certificate from %s was not exposed by httpx; "
                    "falling back to TLS-layer certificate verification",
                    peer["node_id"],
                )

        data = resp.json()

        # F-FED-INGEST-TENANT: resolve the local tenant this peer's inbound facts
        # are stamped into (fail-closed per peer policy). A misconfigured peer
        # (non-default tenant without the multi-tenant plugin, or an unpinned peer
        # on a multi-tenant node) yields a PeerPolicyError — skip this whole page
        # rather than silently land facts in 'default'.
        with db() as conn:
            node_mt = node_is_multitenant(conn)
        try:
            tenant_id = resolve_ingest_tenant(
                peer,
                plugin_active=multi_tenant_plugin_registered(),
                node_is_multitenant=node_mt,
            )
        except PeerPolicyError as exc:
            logger.warning(
                "Skipping pull from %s: peer tenant policy unsafe: %s",
                peer["node_id"],
                exc,
            )
            write_audit_log(
                peer["node_id"],
                "federation_tenant_policy_rejected",
                {"reason": str(exc)},
            )
            return cursor  # fail-closed: ingest nothing from a mis-pinned peer

        # origin_allowed_scopes = peer's registered declaration scope (spec §6.8.1).
        # These fields are internal and MUST NOT be re-replicated (§3.1), so we
        # derive them from the peer registry rather than reading from the fact payload.
        ingested = 0
        for fact in data.get("facts", []):
            try:
                ingest_fact(
                    fact,
                    peer["node_id"],
                    origin_allowed_scopes=allowed_scopes,
                    tenant_id=tenant_id,
                )
            except FederationIntegrityError as exc:
                logger.warning(
                    "Rejected federated fact %s from %s: %s",
                    exc.fact_id,
                    peer["node_id"],
                    exc.reason,
                )
                write_audit_log(
                    peer["node_id"],
                    "federation_integrity_rejected",
                    {
                        "fact_id": exc.fact_id,
                        "reason": exc.reason,
                        "stored_cid": exc.stored_cid,
                        "computed_cid": exc.computed_cid,
                    },
                )
                continue
            ingested += 1

        if ingested:
            FEDERATION_INGRESS.labels(peer_id=peer["node_id"], status="ok").inc(ingested)

        new_cursor: str | None = data.get("cursor")

        # Replication-lag gauge: difference between now and the cursor HLC timestamp.
        # The HLC is an ISO timestamp string; if parsing fails we leave the gauge unchanged.
        try:
            if new_cursor:
                from datetime import UTC, datetime

                cursor_ts = datetime.fromisoformat(new_cursor.split("_")[0].replace("Z", "+00:00"))
                if cursor_ts.tzinfo is None:
                    cursor_ts = cursor_ts.replace(tzinfo=UTC)
                lag_s = max(0.0, (datetime.now(UTC) - cursor_ts).total_seconds())
                REPLICATION_LAG.labels(peer_id=peer["node_id"]).set(lag_s)
        except Exception as exc:  # noqa: BLE001  # nosec B110 — best-effort lag metric
            logger.debug("replication lag metric update failed: %s", exc)

        return new_cursor


def _make_pull_client() -> httpx.AsyncClient:
    """Return an httpx client configured for mTLS when STIGMEM_TLS_* are set."""
    if settings.mtls_enabled:
        from .tls import build_client_ssl_context

        ssl_ctx = build_client_ssl_context(
            settings.tls_cert_path,
            settings.tls_key_path,
            settings.tls_ca_bundle,
        )
        return httpx.AsyncClient(verify=ssl_ctx)
    return httpx.AsyncClient()


async def pull_tombstones_from_peer_once(
    peer: dict[str, Any],
    client: httpx.AsyncClient,
    cursor: str | None,
) -> str | None:
    """Pull one page of tombstones from the peer (§23.4.3). Returns the new cursor."""
    allowed_scopes: list[str] = json.loads(peer["allowed_scopes"])
    token = create_peer_token(peer["node_id"], allowed_scopes)

    params: dict[str, Any] = {"limit": 200}
    if cursor:
        params["since"] = cursor

    try:
        resp = await client.get(
            f"{peer['node_url']}/v1/federation/tombstones",
            params=params,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
    except httpx.RequestError as exc:
        logger.warning("Tombstone pull network error from %s: %s", peer["node_id"], exc)
        return cursor

    if resp.status_code != 200:
        logger.warning("Tombstone pull from %s returned %s", peer["node_id"], resp.status_code)
        return cursor

    data = resp.json()
    tombstones = data.get("tombstones", [])
    new_cursor: str | None = data.get("cursor")

    # F-13 §23.4.3: emit tombstone_sync_gap when result set is non-empty and cursor
    # indicates skipped pages (more results available beyond this batch)
    if tombstones and new_cursor is not None:
        from ..observability.audit_event import emit_nofail

        emit_nofail(
            "tombstone_sync_gap",
            entity_uri=peer["node_id"],
            tenant_id="default",
            source=f"federation_pull:{peer['node_id']}",
            detail={
                "peer_node_id": peer["node_id"],
                "tombstones_in_batch": len(tombstones),
                "cursor": new_cursor,
            },
        )

    # Ingest tombstones and revocations
    from ..lifecycle.tombstones import apply_inbound_revocation, apply_inbound_tombstone
    from ..models.tombstones import TombstoneRecord, TombstoneRevocationRecord

    for t in tombstones:
        try:
            record = TombstoneRecord(**t)
            apply_inbound_tombstone(record)
        except Exception as exc:
            logger.warning("Tombstone ingest from %s failed: %s", peer["node_id"], exc)

    for r in data.get("revocations", []):
        try:
            rev = TombstoneRevocationRecord(**r)
            apply_inbound_revocation(rev)
        except Exception as exc:
            logger.warning("Tombstone revocation ingest from %s failed: %s", peer["node_id"], exc)

    return new_cursor


def _load_tombstone_cursor(peer_id: str) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT cursor FROM replication_cursors"
            " WHERE peer_id = ? AND direction = 'tombstone_inbound'",
            (peer_id,),
        ).fetchone()
    return row["cursor"] if row else None


def _save_tombstone_cursor(peer_id: str, cursor: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO replication_cursors (peer_id, direction, cursor, updated_at)
               VALUES (?,?,?,?)
               ON CONFLICT(peer_id, direction)
               DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at""",
            (peer_id, "tombstone_inbound", cursor, datetime.now(UTC).isoformat()),
        )


async def pull_all_peers_once() -> None:
    """Pull one batch from every active peer. Called by the loop and by tests."""
    with db() as conn:
        peers = conn.execute(
            "SELECT id, node_id, node_url, allowed_scopes FROM peers WHERE status = 'active'"
        ).fetchall()

    if not peers:
        return

    async with _make_pull_client() as client:
        for peer in peers:
            peer_dict = dict(peer)
            cursor = load_cursor(peer_dict["id"])
            new_cursor = await pull_from_peer_once(peer_dict, client, cursor)
            if new_cursor != cursor:
                save_cursor(peer_dict["id"], new_cursor)

            # §23.4.3: pull tombstones from peers
            tomb_cursor = _load_tombstone_cursor(peer_dict["id"])
            new_tomb_cursor = await pull_tombstones_from_peer_once(peer_dict, client, tomb_cursor)
            if new_tomb_cursor != tomb_cursor:
                _save_tombstone_cursor(peer_dict["id"], new_tomb_cursor)


async def pull_loop_task() -> None:
    """Background asyncio task: pull from all active peers every pull_interval_s."""
    while True:
        await asyncio.sleep(settings.federation_pull_interval_s)
        try:
            await pull_all_peers_once()
        except Exception:
            logger.exception("Unexpected error in pull loop")
