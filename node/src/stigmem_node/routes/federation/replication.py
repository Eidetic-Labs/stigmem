"""Federation fact pull and push routes."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import Header, HTTPException, Query, Request

from ...db import db, get_node_entity_uri, get_or_create_node_id
from ...federation.federation_ingest import (
    FederationHlcSkewError,
    FederationIntegrityError,
)
from ...federation.origin_identity import (
    OriginIdentityError,
    resolve_origin_key,
    resolve_origin_key_for_relay,
)
from ...federation.origin_signature import (
    OriginSignatureError,
    sign_origin,
    verify_origin_signature,
)
from ...federation.peer_policy import PeerPolicyError, resolve_origin_tenant_for_peer
from ...federation.peer_token import _get_privkey_obj
from ...federation.tls import check_peer_san
from ...identity.capability import CapabilityTokenError, verify_token
from ...identity.trust_store import get_peer_manifest
from ...metrics import FEDERATION_EGRESS
from ...models.facts import row_to_record
from ...models.federation import (
    FederationEnvelopeEntry,
    FederationFactsResponse,
    OriginBlock,
)
from ...plugins import Deny, TenantContext, get_registry
from .common import (
    PeerTokenDep,
    _allowed_output_scopes,
    _allowed_output_tenants,
    _cap_token_covers_scope,
    _get_mtls_peer_cert,
    _public_module,
    _try_peer_token_auth,
    logger,
    router,
)


def _json_token(value: str) -> str:
    """Return the canonical JSON-quoted token for *value* (``foo`` → ``"foo"``).

    Stored ``origin_allowed_scopes`` / ``origin_allowed_tenants`` are
    ``json.dumps(sorted([...]))`` TEXT, so each element appears verbatim as a
    JSON string literal. Searching for the quoted token makes a ``LIKE '%…%'``
    membership test exact (the surrounding quotes prevent a prefix/substring
    false match). ``json.dumps`` here matches the encoder ingest uses, so any
    string requiring escaping is encoded identically on both sides.
    """
    return json.dumps(value)


def build_origin_entry(
    record: Any,
    row: Any,
    *,
    own_node_id: str,
    own_entity_uri: str,
    pull_tenant: str,
    priv: Any,
) -> tuple[OriginBlock, str, dict[str, Any] | None] | None:
    """Build the (OriginBlock, origin_sig, origin_manifest) triple for one egress record.

    Two cases (F-FED-2c W2.2):

    * **Self-originated** (``record.received_from is None``): sign a FRESH origin
      block from THIS node's identity — unchanged 2b behaviour. A downstream peer
      verifies it against THIS node's manifest. The origin block's ``entity_uri`` is
      THIS node's own ``own_entity_uri`` (Phase 2c W3.1), bound into the signature.
    * **Relayed** (``received_from`` not None): forward the STORED origin block +
      STORED ``origin_sig`` VERBATIM. Re-signing here would destroy the original
      origin attribution — a downstream node must verify against the ORIGIN's
      manifest, not this relay's. The stored ``origin_tenant`` / ``origin_node_id``
      / ``origin_allowed_scopes`` / ``origin_allowed_tenants`` / ``origin_entity_uri``
      / ``origin_sig`` columns are read off the DB *row* because FactRecord does not
      surface them. The forwarded ``entity_uri`` is the STORED origin entity_uri so the
      forwarded signature still verifies against the ORIGIN's manifest (W3.1).

    W4.2: for a RELAYED fact, ATTACH the origin's stored manifest body as
    ``origin_manifest`` (best-effort) so an UNREACHABLE downstream has a candidate to
    anchor-match against its operator pin / stored binding. It is only the self-verifying
    manifest BODY — no proof/STH/Merkle. Self-originated facts carry no manifest (None).

    Returns ``None`` (skip + warn) when the record is not emittable: a relayed fact
    with no stored ``origin_sig`` cannot be attributed and must not be forwarded.
    """
    if record.received_from is None:
        # Self-originated: fresh origin block for THIS node + fresh signature.
        origin = OriginBlock(
            tenant=pull_tenant,
            node_id=own_node_id,
            allowed_scopes=(record.origin_allowed_scopes or [record.scope]),
            allowed_tenants=[pull_tenant],
            entity_uri=own_entity_uri,  # W3.1: bind THIS node's entity_uri into the sig
        )
        sig = sign_origin(
            priv,
            fact_id=record.id,
            cid=record.cid,
            origin=origin.model_dump(),
            valid_until=record.valid_until,
        )
        return origin, sig, None

    # Relayed: forward the stored origin block + stored sig verbatim (no re-sign).
    stored_sig = row["origin_sig"]
    if not stored_sig:
        logger.warning(
            "federation relay skip: relayed fact %s has no stored origin_sig", record.id
        )
        return None
    # W3.1: the forwarded entity_uri MUST be the STORED origin entity_uri (the value bound
    # into the original signature), so the forwarded sig still verifies against the ORIGIN's
    # manifest. A relayed fact stored without an origin_entity_uri (pre-v2.1 origin) cannot
    # produce a v2.1 origin block — skip it (fail-safe; it is simply not relayable).
    stored_entity_uri = row["origin_entity_uri"]
    if not stored_entity_uri:
        logger.warning(
            "federation relay skip: relayed fact %s has no stored origin_entity_uri "
            "(pre-v2.1 origin, not relayable)",
            record.id,
        )
        return None
    stored_scopes_raw = row["origin_allowed_scopes"]
    stored_tenants_raw = row["origin_allowed_tenants"]
    origin = OriginBlock(
        tenant=(row["origin_tenant"] or pull_tenant),
        node_id=(row["origin_node_id"] or record.received_from),
        allowed_scopes=(json.loads(stored_scopes_raw) if stored_scopes_raw else [record.scope]),
        allowed_tenants=(json.loads(stored_tenants_raw) if stored_tenants_raw else []),
        entity_uri=stored_entity_uri,
    )
    # W4.2: attach the origin's stored manifest body (best-effort) so an unreachable
    # downstream can anchor-match it against its pin / stored binding. Absent if we have
    # no stored manifest for the origin entity_uri (the downstream then relies on its own
    # pin/binding/fetch; the manifest is an optimisation, not a trust grant).
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
            "federation relay: could not attach origin_manifest for %s: %s",
            stored_entity_uri,
            exc,
        )
    return origin, stored_sig, carried_manifest


@router.get("/v1/federation/facts", response_model=FederationFactsResponse)
def pull_facts(
    peer_and_token: PeerTokenDep,
    scope: str | None = Query(None),
    cursor: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
) -> FederationFactsResponse:
    """Return scope-filtered, HLC-cursor-paged facts to an authenticated peer.

    Covered by Spec-05-Federation-Trust.
    """
    peer, token_payload = peer_and_token

    permitted = _allowed_output_scopes(peer, token_payload)
    if not permitted:
        raise HTTPException(status_code=403, detail="no permitted scopes")

    if scope is not None:
        if scope not in permitted:
            _public_module().write_audit_log(
                peer["id"],
                "scope_violation",
                {"requested_scope": scope, "permitted": list(permitted)},
            )
            raise HTTPException(status_code=403, detail="scope not permitted for this peer")
        query_scopes = {scope}
    else:
        query_scopes = permitted

    # F-FED-GARDEN T1: egress is a PEER concern. Pin to the peer's explicit
    # pull_tenant; only an explicit pin overrides the default tenant.
    pull_tenant = peer["pull_tenant"] or "default"

    # F-FED-2c W2.3: the re-federation clause. With relay OFF this is exactly
    # today's ``received_from IS NULL`` (no param) — byte-identical, zero
    # regression. With relay ON it widens to ALSO admit inbound (relayed) facts,
    # but ONLY within the origin's signed propagation grant, enforced ENTIRELY in
    # SQL so the LIMIT applies post-filter (no Python post-filtering → no short
    # pages / skipped cursor). The gate (all in SQL):
    #   * received_from IS NULL                         (self-originated, as today), OR
    #   * the fact is relayed AND
    #       - facts.scope ∈ origin_allowed_scopes ∩ peer.allowed_scopes ∩ token.scopes
    #         (the ``facts.scope IN (query_scopes)`` clause already constrains scope to
    #          the peer∩token set, so here we only additionally require the scope to be
    #          inside the per-fact origin grant), AND
    #       - origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅.
    # origin_allowed_scopes / origin_allowed_tenants are stored as the canonical
    # ``json.dumps(sorted([...]))`` TEXT (migration 044). Rather than json_each
    # (NOT translated by postgres_backend._pg_translate → would break Postgres) we
    # use a portable LIKE against that canonical text: each element appears verbatim
    # as the JSON-quoted token ``"value"``; the surrounding quotes make the match
    # exact (``"acme"`` never matches inside ``"acme2"``). All comparison values are
    # the peer's SMALL known set, bound as params — never string-interpolated.
    relay_clause: str
    relay_params: list[Any] = []
    if _public_module().settings.federation_relay_enabled:
        peer_tenants = _allowed_output_tenants(peer)
        if peer_tenants:
            # scope ∈ origin_allowed_scopes: the fact's own (already peer∩token-bounded)
            # ``facts.scope`` must appear in the stored origin grant. The grant is the
            # canonical sorted-JSON text, so the scope appears verbatim as ``"scope"``.
            # ``facts.scope`` is a COLUMN (not a bind value), so the JSON quotes are
            # added in SQL via ``||`` concat (portable: SQLite + Postgres). No param.
            scope_in_origin = (
                "facts.origin_allowed_scopes LIKE '%\"' || facts.scope || '\"%'"
            )
            # origin_allowed_tenants ∩ peer.allowed_tenants ≠ ∅: OR over the peer's
            # known tenant set (sorted for deterministic SQL + param order). Each
            # tenant is bound as the json-quoted token ``"tenant"`` so the LIKE match
            # is exact (``"a"`` never matches inside ``"ab"``).
            tenant_overlap = " OR ".join(
                "facts.origin_allowed_tenants LIKE '%' || ? || '%'" for _ in peer_tenants
            )
            relay_clause = (
                "(facts.received_from IS NULL"
                f" OR (facts.received_from IS NOT NULL AND {scope_in_origin}"
                f" AND ({tenant_overlap})))"
            )
            # Params, in the EXACT order their ? appears in relay_clause: one per
            # peer tenant for tenant_overlap (sorted to match the clause order).
            # scope_in_origin carries NO param (column-only concat).
            relay_params.extend(_json_token(t) for t in sorted(peer_tenants))
        else:
            # Peer authorised for no tenant ⇒ relay can never apply; fall back to
            # the self-only clause (no param).
            relay_clause = "facts.received_from IS NULL"
    else:
        relay_clause = "facts.received_from IS NULL"  # do not re-federate inbound facts (§3.1)

    scope_placeholders = ",".join("?" * len(query_scopes))
    params: list[Any] = list(query_scopes)
    conditions: list[str] = [
        # all bare columns qualified with facts. — the membership LEFT JOIN below
        # introduces fgm.garden_id, so an unqualified column could be ambiguous.
        f"facts.scope IN ({scope_placeholders})",
        "facts.tenant_id = ?",
        "facts.hlc IS NOT NULL",  # only facts with an HLC are replication-eligible
        relay_clause,  # F-FED-2c W2.3: self-only (relay off) OR origin-gated relayed
        "facts.entity NOT LIKE 'stigmem:conflict:%'",  # conflict entities are local (§6.5)
        "facts.relation NOT LIKE 'stigmem:%'",  # meta-facts (received_from, ttl) are local
        "facts.re_federation_blocked = 0",  # exclude relay-blocked company facts (§6.8.2)
        "(facts.derived_from IS NULL OR facts.derived_from = '' OR facts.derived_from = '[]')",
    ]
    # Param lockstep: the scope IN (...) placeholders are already at the front of
    # ``params``; ``facts.tenant_id = ?`` binds pull_tenant next; the relay_clause
    # placeholders (if any) come immediately AFTER because relay_clause sits after
    # the tenant_id clause in ``conditions`` and BEFORE the garden subquery's ?.
    params.append(pull_tenant)
    params.extend(relay_params)
    # F-FED-GARDEN T1 (fail-closed, UNCONDITIONAL — not gated on garden_acl_enforced()
    # and not routed through the identity read chokepoint): the fact's effective
    # garden is the PROJECTED garden COALESCE(fgm.garden_id, facts.garden_id). A
    # fact may egress only if it is in no garden, or in a garden explicitly marked
    # federatable for this pull tenant.
    conditions.append(
        "(COALESCE(fgm.garden_id, facts.garden_id) IS NULL"
        " OR COALESCE(fgm.garden_id, facts.garden_id) IN"
        "    (SELECT id FROM gardens WHERE federatable = 1 AND tenant_id = ?))"
    )
    params.append(pull_tenant)  # binds the federatable-garden subquery to the pull tenant
    # F-FED-GARDEN T1: quarantined facts never egress.
    conditions.append("facts.quarantine_garden_id IS NULL")
    if cursor:
        conditions.append("facts.hlc > ?")
        params.append(cursor)

    where = " AND ".join(conditions)
    params.append(limit + 1)

    with db() as conn:
        rows = conn.execute(
            f"SELECT facts.* FROM facts"  # noqa: S608  # nosec B608 — where built from literal fragments; values in params
            f" LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = facts.id"
            f" WHERE {where} ORDER BY facts.hlc ASC LIMIT ?",
            params,
        ).fetchall()

    has_more = len(rows) > limit
    rows = rows[:limit]

    seen: dict[tuple[str, str, str], int] = {}
    for r in rows:
        k = (r["entity"], r["relation"], r["scope"])
        seen[k] = seen.get(k, 0) + 1

    records = [
        row_to_record(r, contradicted=seen[(r["entity"], r["relation"], r["scope"])] > 1)
        for r in rows
    ]
    # F-FED-GARDEN T2: a federatable-garden fact may egress, but its garden_id is
    # a local-membership detail that must not leak to the peer. Strip it from the
    # emitted record (the DB row is untouched). Restricted-garden facts are already
    # excluded by the query above, so this only affects allowed federatable facts.
    for record in records:
        record.garden_id = None
    # The egress tenant is RESOLVED from the peer's per-peer pull policy
    # (``pull_tenant = peer["pull_tenant"] or "default"``); it is not a hardcoded
    # default pin, so the tenant_context_source is "resolved" (a "pinned" source
    # must be the literal default tenant — see check_tenant_resolution_consistency).
    tenant = TenantContext(
        tenant_id=pull_tenant,
        metadata={"tenant_context_source": "resolved"},
    )
    registry = get_registry()
    records = registry.fire_filter_chain(
        "federation_outbound_filter",
        records,
        peer=peer,
        token_payload=token_payload,
        tenant=tenant,
    )
    records = registry.fire_filter_chain(
        "federation_outbound_sign",
        records,
        peer=peer,
        token_payload=token_payload,
        tenant=tenant,
    )

    new_cursor: str | None = rows[-1]["hlc"] if rows else cursor

    # F-FED-2b: build the signed v2 envelope from the POST-filter records (records is
    # reassigned by the filter/sign chains above, so a positional zip(records, rows)
    # would misalign). Each entry carries the fact, an origin block, and the origin
    # signature over (fact_id, cid, origin, valid_until).
    priv = _get_privkey_obj()
    own_node_id = get_or_create_node_id()
    # W3.1: this node's own entity_uri is bound into every self-originated origin block.
    # get_node_entity_uri() returns settings.entity_uri or settings.node_url (never empty
    # when federation is enabled, since node_url is required), so a self-originated v2.1
    # signature is always producible.
    own_entity_uri = get_node_entity_uri()
    # F-FED-2c W2.2: relayed facts (received_from not NULL) forward their STORED
    # origin block + origin_sig verbatim; those columns are NOT on FactRecord, so
    # look them up by id off the original row (do NOT zip(records, rows) — the
    # filter/sign chains reassign ``records``, which is the 2b misalignment hazard).
    rows_by_id = {r["id"]: r for r in rows}
    entries: list[FederationEnvelopeEntry] = []
    for record in records:
        if record.cid is None:
            logger.warning("federation egress skip: fact %s has no cid", record.id)
            continue
        built = build_origin_entry(
            record,
            rows_by_id[record.id],
            own_node_id=own_node_id,
            own_entity_uri=own_entity_uri,
            pull_tenant=pull_tenant,
            priv=priv,
        )
        if built is None:
            continue
        origin, sig, origin_manifest = built
        entries.append(
            FederationEnvelopeEntry(
                fact=record, origin=origin, origin_sig=sig, origin_manifest=origin_manifest
            )
        )

    FEDERATION_EGRESS.labels(peer_id=peer["node_id"], status="ok").inc(len(entries))
    return FederationFactsResponse(facts=entries, cursor=new_cursor, has_more=has_more)


# ---------------------------------------------------------------------------
# POST /v1/federation/facts/push — optional push (§5.11)
# ---------------------------------------------------------------------------


def _verify_push_cap_token(x_stigmem_capability: str) -> dict[str, Any]:
    """Verify a capability-token header for the push path (H-SEC-2).

    On verification failure logs ``capability_rejected`` and raises 401.
    On success returns the decoded token dict and logs ``capability_verified``.
    """
    try:
        verify_token(
            x_stigmem_capability,
            lambda uri: get_peer_manifest(
                uri, refresh_if_expired=True, trust_mode=_public_module().settings.trust_mode
            ),
            trust_mode=_public_module().settings.trust_mode,
        )
    except CapabilityTokenError as exc:
        # M-SEC-4: log capability_rejected
        import uuid as _uuid
        from datetime import UTC as _UTC
        from datetime import datetime as _datetime

        _now = _datetime.now(_UTC).isoformat()
        try:
            import json as _json

            with db() as conn:
                conn.execute(
                    """INSERT INTO fact_audit_log
                       (id, fact_id, event_type, entity_uri, oidc_sub, source,
                        attested_key_id, detail, ts)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        str(_uuid.uuid4()),
                        "capability:rejected",
                        "capability_rejected",
                        None,
                        None,
                        "system:capability",
                        None,
                        _json.dumps({"reason": str(exc)}),
                        _now,
                    ),
                )
        except Exception as audit_exc:  # nosec B110 — audit log best-effort
            logger.debug("capability_rejected audit log failed: %s", audit_exc)
        raise HTTPException(status_code=401, detail=f"capability token invalid: {exc}") from exc

    try:
        cap_token: dict[str, Any] = json.loads(x_stigmem_capability)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400, detail=f"malformed capability token JSON: {exc}"
        ) from exc

    if cap_token.get("verb") != "write":
        raise HTTPException(
            status_code=403,
            detail="insufficient_capability: token verb must be 'write' for push",
        )

    # M-SEC-4: log capability_verified
    import uuid as _uuid2
    from datetime import UTC as _UTC2
    from datetime import datetime as _datetime2

    _now2 = _datetime2.now(_UTC2).isoformat()
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO fact_audit_log
                   (id, fact_id, event_type, entity_uri, oidc_sub, source,
                    attested_key_id, detail, ts)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    str(_uuid2.uuid4()),
                    cap_token.get("token_id", "unknown"),
                    "capability_verified",
                    cap_token.get("subject"),
                    None,
                    "system:capability",
                    None,
                    json.dumps(
                        {
                            "token_id": cap_token.get("token_id"),
                            "issuer": cap_token.get("issuer"),
                            "verb": cap_token.get("verb"),
                            "object": cap_token.get("object"),
                        }
                    ),
                    _now2,
                ),
            )
    except Exception as audit_exc:  # nosec B110 — audit log best-effort
        logger.debug("capability_verified audit log failed: %s", audit_exc)

    return cap_token


@router.post("/v1/federation/facts/push", status_code=202)
def push_facts(
    request: Request,
    body: dict[str, Any],
    authorization: Annotated[str | None, Header(alias="authorization")] = None,
    x_stigmem_capability: Annotated[str | None, Header(alias="x-stigmem-capability")] = None,
) -> dict[str, Any]:
    """Receive push-replicated facts from a peer. Off by default.

    Auth (H-SEC-2): peer JWT first; if that fails and X-Stigmem-Capability is
    present, fall through to capability-token verification.  Capability tokens
    must carry verb=write and an object that covers all pushed fact scopes.
    Covered by Spec-05-Federation-Trust.
    """
    if not _public_module().settings.federation_push_enabled:
        raise HTTPException(status_code=405, detail="push replication not enabled on this node")

    # F-FED-2b: clean break — only the v2 signed-origin envelope is accepted (no v1 interop).
    if body.get("v") != 2:
        raise HTTPException(
            status_code=422,
            detail="federation requires the v2 envelope (no v1 interop)",
        )

    # --- Phase 1: try peer JWT auth ---
    peer_auth = _try_peer_token_auth(authorization)

    peer: dict[str, Any] | None = None
    token_payload: dict[str, Any] | None = None
    cap_token: dict[str, Any] | None = None
    using_cap_token = False

    if peer_auth is not None:
        peer, token_payload = peer_auth
        # §22.1.2.4 — enforce SAN on the push path too
        if _public_module().settings.mtls_enabled:
            peer_cert = _get_mtls_peer_cert(request)
            if not check_peer_san(peer_cert, peer["node_id"]):
                _public_module().write_audit_log(
                    peer["id"], "san_mismatch", {"node_id": peer["node_id"]}
                )
                raise HTTPException(
                    status_code=401,
                    detail="peer certificate URI SAN does not match node_id",
                )
    elif x_stigmem_capability is not None:
        cap_token = _verify_push_cap_token(x_stigmem_capability)
        using_cap_token = True
    else:
        raise HTTPException(
            status_code=401,
            detail="peer token or X-Stigmem-Capability header required",
        )

    # F-FED-2b: the local tenant is now resolved PER FACT from the wire-carried,
    # signed origin tenant (see _push_fact_with_*). No pre-loop single-tenant resolve.

    entries = body.get("facts", [])
    accepted = 0
    rejected = 0
    errors: list[dict[str, Any]] = []
    # F-FED-2c W3.2: per-REQUEST relay key cache, threaded through the page loop so a
    # relayed-origin manifest fetch + rotation check runs once per push (not per fact).
    # A local (not a module global) so a stale binding never persists across requests.
    relay_cache: dict[tuple[str, str], set[str]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            rejected += 1
            errors.append({"fact_id": None, "error": "missing_origin_block"})
            continue
        fact = entry.get("fact")
        origin = entry.get("origin")
        origin_sig = entry.get("origin_sig")
        # W4.2: OPTIONAL carried origin manifest body — lets an unreachable receiver
        # anchor-match a relayed origin against its operator pin / stored binding.
        origin_manifest = entry.get("origin_manifest")
        if not isinstance(origin_manifest, dict):
            origin_manifest = None
        if not isinstance(fact, dict) or not isinstance(origin, dict) or not origin_sig:
            rejected += 1
            errors.append(
                {
                    "fact_id": (fact.get("id") if isinstance(fact, dict) else None),
                    "error": "missing_origin_block",
                }
            )
            continue

        fact_scope = fact.get("scope", "")

        if using_cap_token:
            assert cap_token is not None
            ok, err = _push_fact_with_cap_token(
                fact, fact_scope, origin, origin_sig, cap_token, relay_cache, origin_manifest
            )
        else:
            assert peer is not None and token_payload is not None
            ok, err = _push_fact_with_peer_token(
                fact, fact_scope, origin, origin_sig, peer, token_payload, relay_cache,
                origin_manifest,
            )

        if ok:
            accepted += 1
        else:
            rejected += 1
            if err is not None:
                errors.append(err)

    return {"accepted": accepted, "rejected": rejected, "errors": errors}


def _verify_origin_and_resolve_tenant(
    fact: dict[str, Any],
    fact_scope: str,
    origin: dict[str, Any],
    origin_sig: str,
    sender_node_id: str,
    peer_row: dict[str, Any] | Any,
    conn: Any,
    *,
    relay_cache: dict[tuple[str, str], set[str]] | None = None,
    origin_manifest: dict[str, Any] | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    """Run the fail-closed ordered origin checks; return (local_tenant, error).

    On any failure returns (None, error_dict) and the fact MUST NOT be ingested.
    Raises HTTPException(409) only for an unresolvable per-origin tenant policy
    (PeerPolicyError) — the push handler turns that into a 409 response.

    Relay (F-FED-2c W3.2): when ``federation_relay_enabled`` is OFF the
    ``origin.node_id == sender`` check is MANDATORY (unchanged 2b — byte-identical
    direct path). When ON and the origin differs from the sender (a RELAYED fact),
    it is admitted ONLY IF the sender peer is ``relay_trusted`` (fail-closed) AND the
    origin is independently verified by fetching the origin's manifest from its signed
    entity_uri (``resolve_origin_key_for_relay``). ``relay_cache`` is the per-request
    dict threaded through the page loop so the relay fetch/rotation check runs once.
    """
    fact_id = fact.get("id")
    # 0. fact id present (later steps sign over / index by it)
    if not fact_id:
        return None, {"fact_id": None, "error": "id_required"}
    # 1. cid present
    if not fact.get("cid"):
        return None, {"fact_id": fact_id, "error": "cid_required"}
    # 2. origin node_id vs authenticated sender — direct (==) vs relayed (!=)
    is_relayed = origin.get("node_id") != sender_node_id
    relay_enabled = _public_module().settings.federation_relay_enabled
    if is_relayed:
        # Relay OFF ⇒ origin==sender is mandatory (unchanged 2b): reject.
        if not relay_enabled:
            return None, {"fact_id": fact_id, "error": "origin_not_sender"}
        # Relay ON ⇒ the SENDER peer must be relay_trusted (fail-closed).
        relay_trusted = False
        try:
            relay_trusted = bool(peer_row["relay_trusted"])
        except (KeyError, IndexError, TypeError):
            relay_trusted = bool((peer_row or {}).get("relay_trusted"))
        if not relay_trusted:
            return None, {"fact_id": fact_id, "error": "relay_sender_not_trusted"}
    # 3. resolve the signing key set for the origin (regardless of trust_mode).
    #    Direct: 2a peer chain. Relayed: fetch-on-first from the signed entity_uri.
    try:
        if is_relayed:
            keys = resolve_origin_key_for_relay(
                origin["node_id"],
                origin.get("entity_uri", ""),
                cache=relay_cache if relay_cache is not None else {},
                origin_manifest=origin_manifest,
            )
        else:
            keys = resolve_origin_key(origin["node_id"])
    except OriginIdentityError:
        return None, {"fact_id": fact_id, "error": "origin_unresolvable"}
    # 4. verify origin signature over (fact_id, cid, origin, valid_until)
    try:
        verify_origin_signature(
            origin_sig,
            fact_id=fact_id,
            cid=fact["cid"],
            origin=origin,
            valid_until=fact.get("valid_until"),
            allowed_pubkeys=keys,
        )
    except OriginSignatureError:
        return None, {"fact_id": fact_id, "error": "origin_sig_invalid"}
    # 5. fact scope must be inside the origin's granted scopes
    if fact_scope not in origin.get("allowed_scopes", []):
        return None, {"fact_id": fact_id, "error": "scope_not_in_origin_grant"}
    # 6. resolve the wire-carried origin tenant to a local tenant (default-deny);
    #    PeerPolicyError bubbles up as a 409 on the push path.
    local_tenant = resolve_origin_tenant_for_peer(peer_row, origin["tenant"], conn)
    return local_tenant, None


def _push_fact_with_cap_token(
    fact: dict[str, Any],
    fact_scope: str,
    origin: dict[str, Any],
    origin_sig: str,
    cap_token: dict[str, Any],
    relay_cache: dict[tuple[str, str], set[str]] | None = None,
    origin_manifest: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Validate + ingest a single v2 fact under capability-token auth.

    Returns (ok, error_dict_or_None). Opens its own DB connection.
    """
    # H-SEC-2: verify capability token object covers this fact's scope
    token_object = cap_token.get("object", "")
    if not _cap_token_covers_scope(token_object, fact_scope):
        return False, {
            "fact_id": fact.get("id"),
            "error": "insufficient_capability: token object does not cover scope",
        }

    sender_node_id = cap_token.get("subject", "")
    fact_source = fact.get("source", "")
    # Source non-forgery: source must match the cap-token subject for a DIRECT fact.
    # F-FED-2c W3.2: a RELAYED fact (origin.node_id != sender, relay enabled) carries the
    # ORIGIN's node_id as source — accept it against the origin node_id; the relay-trust +
    # origin-signature checks below bind it to the verified origin key.
    _relay_on = _public_module().settings.federation_relay_enabled
    _is_relayed = _relay_on and origin.get("node_id") != sender_node_id
    _expected_source = origin.get("node_id") if _is_relayed else sender_node_id
    if fact_source != _expected_source:
        return False, {"fact_id": fact.get("id"), "error": "source_not_owned"}

    with db() as conn:
        # The cap-token subject is the origin node_id; load its (bound) peer row so the
        # per-origin tenant map resolves. No hardcoded tenant="default" any more.
        peer_row = conn.execute(
            "SELECT * FROM peers WHERE node_id = ? AND status = 'active'",
            (sender_node_id,),
        ).fetchone()
        peer_row = dict(peer_row) if peer_row is not None else {}

        try:
            local_tenant, err = _verify_origin_and_resolve_tenant(
                fact, fact_scope, origin, origin_sig, sender_node_id, peer_row, conn,
                relay_cache=relay_cache, origin_manifest=origin_manifest,
            )
        except PeerPolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if err is not None:
            return False, err
        assert local_tenant is not None

        # The cap-token push tenant is RESOLVED per-fact from the origin's
        # per-peer tenant map (``resolve_origin_tenant_for_peer``), not a
        # hardcoded default pin, so the tenant_context_source is "resolved".
        tenant = TenantContext(
            tenant_id=local_tenant,
            metadata={"tenant_context_source": "resolved"},
        )
        registry = get_registry()
        decision = registry.fire_voting(
            "federation_inbound_validate",
            fact=fact,
            fact_scope=fact_scope,
            cap_token=cap_token,
            tenant=tenant,
        )
        if isinstance(decision, Deny):
            return False, {"fact_id": fact.get("id"), "error": decision.reason}
        filtered_fact = registry.fire_filter_chain(
            "federation_inbound_filter",
            fact,
            fact_scope=fact_scope,
            cap_token=cap_token,
            tenant=tenant,
        )

    try:
        _public_module().ingest_fact(
            filtered_fact,
            sender_node_id,
            tenant_id=local_tenant,
            origin_node_id=origin["node_id"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_tenant=origin["tenant"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_sig=origin_sig,
            origin_entity_uri=origin["entity_uri"],
            identity_strength_boost=0.5,  # §19.4.2 boost for valid capability token
        )
        return True, None
    except FederationHlcSkewError:
        return False, {"fact_id": fact.get("id"), "error": "hlc_skew"}
    except FederationIntegrityError as exc:
        return False, {"fact_id": fact.get("id"), "error": exc.reason}
    except Exception:
        return False, {"fact_id": fact.get("id"), "error": "ingest_error"}


def _push_fact_with_peer_token(
    fact: dict[str, Any],
    fact_scope: str,
    origin: dict[str, Any],
    origin_sig: str,
    peer: dict[str, Any],
    token_payload: dict[str, Any],
    relay_cache: dict[tuple[str, str], set[str]] | None = None,
    origin_manifest: dict[str, Any] | None = None,
) -> tuple[bool, dict[str, Any] | None]:
    """Validate + ingest a single v2 fact under peer-JWT auth.

    Returns (ok, error_dict_or_None). Opens its own DB connection.
    """
    permitted = _allowed_output_scopes(peer, token_payload)

    if fact_scope not in permitted:
        _public_module().write_audit_log(
            peer["id"],
            "scope_violation",
            {"fact_id": fact.get("id"), "scope": fact_scope},
        )
        return False, {"fact_id": fact.get("id"), "error": "scope_not_permitted"}

    # Source non-forgery (§6.4): source must match the sending peer's node_id for a DIRECT
    # fact. F-FED-2c W3.2: a RELAYED fact (origin.node_id != sender, relay enabled) carries
    # the ORIGIN's node_id as source — the origin owns it, not the relay. In that case the
    # source must match the ORIGIN node_id instead; the relay-trust + origin-signature
    # checks in _verify_origin_and_resolve_tenant are what actually bind the fact to the
    # verified origin key. The byte-identical direct rule still applies when relay is OFF.
    fact_source = fact.get("source", "")
    _relay_on = _public_module().settings.federation_relay_enabled
    _is_relayed = _relay_on and origin.get("node_id") != peer["node_id"]
    _expected_source = origin.get("node_id") if _is_relayed else peer["node_id"]
    if fact_source != _expected_source:
        _public_module().write_audit_log(
            peer["id"],
            "rejected_fact",
            {
                "fact_id": fact.get("id"),
                "reason": "source_not_owned",
                "source": fact_source,
                "peer_node_id": peer["node_id"],
            },
        )
        return False, {"fact_id": fact.get("id"), "error": "source_not_owned"}

    sender_node_id = peer["node_id"]
    with db() as conn:
        try:
            local_tenant, err = _verify_origin_and_resolve_tenant(
                fact, fact_scope, origin, origin_sig, sender_node_id, peer, conn,
                relay_cache=relay_cache, origin_manifest=origin_manifest,
            )
        except PeerPolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if err is not None:
            return False, err
        assert local_tenant is not None

        # The peer-token push tenant is RESOLVED per-fact from the origin's
        # per-peer tenant map (``resolve_origin_tenant_for_peer``), not a
        # hardcoded default pin, so the tenant_context_source is "resolved".
        tenant = TenantContext(
            tenant_id=local_tenant,
            metadata={"tenant_context_source": "resolved"},
        )
        registry = get_registry()
        decision = registry.fire_voting(
            "federation_inbound_validate",
            fact=fact,
            fact_scope=fact_scope,
            peer=peer,
            token_payload=token_payload,
            tenant=tenant,
        )
        if isinstance(decision, Deny):
            return False, {"fact_id": fact.get("id"), "error": decision.reason}
        filtered_fact = registry.fire_filter_chain(
            "federation_inbound_filter",
            fact,
            fact_scope=fact_scope,
            peer=peer,
            token_payload=token_payload,
            tenant=tenant,
        )

    try:
        _public_module().ingest_fact(
            filtered_fact,
            sender_node_id,
            tenant_id=local_tenant,
            origin_node_id=origin["node_id"],
            origin_allowed_scopes=origin["allowed_scopes"],
            origin_tenant=origin["tenant"],
            origin_allowed_tenants=origin["allowed_tenants"],
            origin_sig=origin_sig,
            origin_entity_uri=origin["entity_uri"],
        )
        return True, None
    except FederationHlcSkewError:
        return False, {"fact_id": fact.get("id"), "error": "hlc_skew"}
    except FederationIntegrityError as exc:
        return False, {"fact_id": fact.get("id"), "error": exc.reason}
    except Exception:
        return False, {"fact_id": fact.get("id"), "error": "ingest_error"}
