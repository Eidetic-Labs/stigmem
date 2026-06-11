"""Federation tombstone routes."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Header, HTTPException, Request, status

from ...db import get_node_entity_uri, get_or_create_node_id
from ...federation.origin_signature import sign_tombstone_origin
from ...federation.peer_token import _get_privkey_obj
from ...identity.capability import CapabilityTokenError, verify_token
from ...identity.trust_store import get_peer_manifest
from ...lifecycle.tombstones import list_federatable_tombstones, list_revocations
from ...models.federation import (
    FederationTombstonesResponseV2,
    OriginBlock,
    TombstoneEnvelopeEntry,
)
from ...models.tombstones import TombstoneRecord
from .._federation_impl import federation_ingest_tombstone_impl
from .common import _get_mtls_peer_cert, _public_module, _try_peer_token_auth, router

logger = logging.getLogger("stigmem.federation.tombstones")


def build_tombstone_origin_entry(
    record: TombstoneRecord,
    origin_fields: dict[str, Any],
    *,
    own_node_id: str,
    own_entity_uri: str,
    pull_tenant: str,
    priv: Any,
) -> TombstoneEnvelopeEntry | None:
    """Build one v2 tombstone envelope entry, mirroring facts ``build_origin_entry`` (W2.2).

    * **Self-originated** (``received_from`` is None / origin_node_id absent or this node):
      build a FRESH origin block from THIS node's identity and sign it via
      ``sign_tombstone_origin``. ``allowed_scopes`` includes the tombstone's single
      ``scope`` (facts set self-originated allowed_scopes to ``[record.scope]``);
      ``allowed_tenants`` = ``[pull_tenant]``. ``origin_manifest`` is None (self facts carry
      no manifest, mirroring build_origin_entry).
    * **Relayed** (``received_from`` set, stored origin_sig + origin_entity_uri present):
      forward the STORED origin block + STORED ``origin_sig`` VERBATIM (no re-sign) so the
      forwarded signature still verifies against the ORIGIN's key. A relayed tombstone
      missing the stored ``origin_sig`` / ``origin_entity_uri`` (pre-v2.1 origin) is not
      attributable → SKIP (return None). W6.7: attach ``origin_manifest`` = the stored
      manifest for the origin's entity_uri (best-effort) so an UNREACHABLE downstream can
      anchor-match it against a pin / stored binding (mirrors the fact path's W4.2 attach).

    Returns None (skip + warn) when a relayed tombstone is not forwardable.
    """
    import json as _json

    received_from = origin_fields.get("received_from")
    origin_node_id = origin_fields.get("origin_node_id")
    self_originated = received_from is None and (
        origin_node_id is None or origin_node_id == own_node_id
    )

    if self_originated:
        origin = OriginBlock(
            tenant=pull_tenant,
            node_id=own_node_id,
            allowed_scopes=[record.scope],
            allowed_tenants=[pull_tenant],
            entity_uri=own_entity_uri,
        )
        sig = sign_tombstone_origin(
            priv,
            tombstone_id=record.id,
            entity_uri=record.entity_uri,
            scope=record.scope,
            origin_node_id=own_node_id,
            origin_tenant=pull_tenant,
            origin_allowed_scopes=[record.scope],
            origin_allowed_tenants=[pull_tenant],
            origin_entity_uri=own_entity_uri,
        )
        return TombstoneEnvelopeEntry(
            tombstone=record, origin=origin, origin_sig=sig, origin_manifest=None
        )

    # Relayed: forward the stored origin block + stored sig verbatim (no re-sign).
    stored_sig = origin_fields.get("origin_sig")
    stored_entity_uri = origin_fields.get("origin_entity_uri")
    if not stored_sig or not stored_entity_uri:
        logger.warning(
            "federation tombstone relay skip: relayed tombstone %s missing stored "
            "origin_sig/origin_entity_uri (pre-v2.1 origin, not relayable)",
            record.id,
        )
        return None
    stored_scopes_raw = origin_fields.get("origin_allowed_scopes")
    stored_tenants_raw = origin_fields.get("origin_allowed_tenants")
    origin = OriginBlock(
        tenant=(origin_fields.get("origin_tenant") or pull_tenant),
        node_id=(origin_node_id or received_from),
        allowed_scopes=(
            _json.loads(stored_scopes_raw) if stored_scopes_raw else [record.scope]
        ),
        allowed_tenants=(_json.loads(stored_tenants_raw) if stored_tenants_raw else []),
        entity_uri=stored_entity_uri,
    )
    # W6.7: attach the origin's stored manifest body (best-effort) so an UNREACHABLE downstream
    # can anchor-match it against its pin / stored binding — mirrors the fact path's W4.2 attach
    # in replication.build_origin_entry. Absent if we hold no stored manifest for the origin
    # entity_uri (the manifest is an optimisation, never a trust grant; the downstream still
    # resolves via its own pin/binding/fetch).
    carried_manifest: dict[str, Any] | None = None
    try:
        stored_manifest = get_peer_manifest(
            stored_entity_uri,
            refresh_if_expired=False,
            trust_mode=_public_module().settings.trust_mode,
        )
        if stored_manifest is not None:
            from ...identity.manifest import manifest_to_dict

            carried_manifest = manifest_to_dict(stored_manifest)
    except Exception as exc:  # noqa: BLE001 — manifest attach is an optimisation, never blocks emit
        logger.debug(
            "federation tombstone relay: could not attach origin_manifest for %s: %s",
            stored_entity_uri,
            exc,
        )
    return TombstoneEnvelopeEntry(
        tombstone=record, origin=origin, origin_sig=stored_sig, origin_manifest=carried_manifest
    )


@router.get("/v1/federation/tombstones", response_model=FederationTombstonesResponseV2)
def federation_list_tombstones(
    request: Request,
    since: str | None = None,
    limit: int = 200,
    token_header: Annotated[str | None, Header(alias="Authorization")] = None,
) -> FederationTombstonesResponseV2:
    """Tombstone poll route (v2 signed-origin envelope, W6.5).

    Requires tombstone:read capability token. Covered by Spec-X2-RTBF-Tombstones.
    """
    raw_token = None
    if token_header and token_header.startswith("Bearer "):
        raw_token = token_header[7:]

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="capability token required",
        )

    fed_settings = _public_module().settings
    if fed_settings.trust_mode != "off":
        try:
            import json as _json

            token_data = _json.loads(raw_token) if raw_token.startswith("{") else {}
            verbs = token_data.get("verbs", token_data.get("verb", ""))
            if isinstance(verbs, str):
                verbs = [v.strip() for v in verbs.split(",")] if verbs else []
            if "tombstone:read" not in verbs and "admin" not in verbs:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="tombstone:read capability required",
                )
            verify_token(
                raw_token,
                lambda uri: get_peer_manifest(
                    uri, refresh_if_expired=True, trust_mode=fed_settings.trust_mode
                ),
                trust_mode=fed_settings.trust_mode,
            )
        except CapabilityTokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    else:
        import logging as _logging

        _logging.getLogger("stigmem.federation").warning(
            "tombstone poll: trust_mode=off — token signature verification skipped"
        )

    # W6.6: gate the egress of RELAYED tombstones by the origin's signed scope/tenant grant
    # for THIS peer, mirroring the FACT egress gate (replication.pull_facts W2.3). The gate is
    # built ENTIRELY in SQL (list_federatable_tombstones) so LIMIT applies post-filter. Resolve
    # the calling peer best-effort from the Authorization header to obtain its allowed_tenants;
    # when no peer row resolves (e.g. a capability-token-only caller) the relay gate fails
    # closed to self-only — a relayed tombstone is never re-federated without a known peer's
    # tenant set. With relay OFF this is byte-identical to the Phase-1 self-only set.
    peer: dict[str, Any] | None = None
    peer_auth = _try_peer_token_auth(token_header)
    if peer_auth is not None:
        peer = peer_auth[0]
    rows, has_more = list_federatable_tombstones(
        peer=peer,
        relay_enabled=fed_settings.federation_relay_enabled,
        since=since,
        limit=limit,
    )
    revocation_list = list_revocations(since=since)[:limit]
    cursor = rows[-1][0].created_at if rows else None

    # W6.5: build the v2 signed-origin envelope. A self-originated tombstone gets a fresh
    # origin block signed by THIS node's federation key; a relayed tombstone forwards its
    # stored origin block + sig verbatim (or is skipped if pre-v2.1 / unattributable).
    priv = _get_privkey_obj()
    own_node_id = get_or_create_node_id()
    own_entity_uri = get_node_entity_uri()
    pull_tenant = "default"
    entries: list[TombstoneEnvelopeEntry] = []
    for record, origin_fields in rows:
        entry = build_tombstone_origin_entry(
            record,
            origin_fields,
            own_node_id=own_node_id,
            own_entity_uri=own_entity_uri,
            pull_tenant=pull_tenant,
            priv=priv,
        )
        if entry is None:
            continue
        entries.append(entry)

    return FederationTombstonesResponseV2(
        v=2,
        tombstones=entries,
        revocations=revocation_list,
        cursor=cursor,
        has_more=has_more,
    )


@router.post("/v1/federation/tombstones/ingest", status_code=status.HTTP_200_OK)
def federation_ingest_tombstone(
    request: Request,
    payload: dict[str, Any],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_stigmem_capability: Annotated[str | None, Header(alias="x-stigmem-capability")] = None,
) -> dict[str, Any]:
    """Inbound tombstone push from a federation peer.

    Auth: peer JWT or capability token with tombstone:write verb (mirrors push_facts).
    Verifies signature against org manifest, writes to local tombstones table.
    Covered by Spec-X2-RTBF-Tombstones.
    """
    # Implementation lives in _federation_impl.federation_ingest_tombstone_impl.
    return federation_ingest_tombstone_impl(
        request,
        payload,
        authorization,
        x_stigmem_capability,
        _try_peer_token_auth,
        _get_mtls_peer_cert,
    )
