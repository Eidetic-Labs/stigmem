"""Federation fact pull and push routes."""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import Header, HTTPException, Query, Request

from ...db import db
from ...federation.federation_ingest import (
    FederationHlcSkewError,
    FederationIntegrityError,
)
from ...federation.peer_policy import PeerPolicyError, resolve_ingest_tenant_for_peer
from ...federation.tls import check_peer_san
from ...identity.capability import CapabilityTokenError, verify_token
from ...identity.trust_store import get_peer_manifest
from ...metrics import FEDERATION_EGRESS
from ...models.facts import row_to_record
from ...models.federation import FederationFactsResponse
from ...plugins import Deny, TenantContext, get_registry
from .common import (
    PeerTokenDep,
    _allowed_output_scopes,
    _cap_token_covers_scope,
    _get_mtls_peer_cert,
    _public_module,
    _try_peer_token_auth,
    logger,
    router,
)


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

    scope_placeholders = ",".join("?" * len(query_scopes))
    params: list[Any] = list(query_scopes)
    conditions: list[str] = [
        # all bare columns qualified with facts. — the membership LEFT JOIN below
        # introduces fgm.garden_id, so an unqualified column could be ambiguous.
        f"facts.scope IN ({scope_placeholders})",
        "facts.tenant_id = ?",
        "facts.hlc IS NOT NULL",  # only facts with an HLC are replication-eligible
        "facts.received_from IS NULL",  # do not re-federate inbound facts (§3.1)
        "facts.entity NOT LIKE 'stigmem:conflict:%'",  # conflict entities are local (§6.5)
        "facts.relation NOT LIKE 'stigmem:%'",  # meta-facts (received_from, ttl) are local
        "facts.re_federation_blocked = 0",  # exclude relay-blocked company facts (§6.8.2)
        "(facts.derived_from IS NULL OR facts.derived_from = '' OR facts.derived_from = '[]')",
    ]
    params.append(pull_tenant)
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
    FEDERATION_EGRESS.labels(peer_id=peer["node_id"], status="ok").inc(len(records))
    return FederationFactsResponse(facts=records, cursor=new_cursor, has_more=has_more)


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

    # F-FED-INGEST-TENANT: resolve the local tenant for this push connection once,
    # fail-closed. The peer-token path uses the registered peer's pinned policy; the
    # capability-token path has no registered peer, so it is treated as an unpinned
    # peer (default on a single-tenant node, PeerPolicyError -> 409 on a multi-tenant
    # node — an explicit per-peer pin is required to land non-default federated facts).
    policy_peer: dict[str, Any] = peer if peer is not None else {}
    try:
        with db() as conn:
            tenant_id = resolve_ingest_tenant_for_peer(policy_peer, conn)
    except PeerPolicyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    facts = body.get("facts", [])
    accepted = 0
    rejected = 0
    errors: list[dict[str, Any]] = []

    for fact in facts:
        fact_scope = fact.get("scope", "")

        if using_cap_token:
            assert cap_token is not None
            ok, err = _push_fact_with_cap_token(fact, fact_scope, cap_token, tenant_id)
        else:
            assert peer is not None and token_payload is not None
            ok, err = _push_fact_with_peer_token(
                fact, fact_scope, peer, token_payload, tenant_id
            )

        if ok:
            accepted += 1
        else:
            rejected += 1
            if err is not None:
                errors.append(err)

    return {"accepted": accepted, "rejected": rejected, "errors": errors}


def _push_fact_with_cap_token(
    fact: dict[str, Any],
    fact_scope: str,
    cap_token: dict[str, Any],
    tenant_id: str,
) -> tuple[bool, dict[str, Any] | None]:
    """Validate + ingest a single fact under capability-token auth.

    Returns (ok, error_dict_or_None).
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
    # Source non-forgery: source must match capability token subject
    if fact_source != sender_node_id:
        return False, {"fact_id": fact.get("id"), "error": "source_not_owned"}

    tenant = TenantContext(
        tenant_id="default",
        metadata={"tenant_context_source": "pinned"},
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
            tenant_id=tenant_id,
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
    peer: dict[str, Any],
    token_payload: dict[str, Any],
    tenant_id: str,
) -> tuple[bool, dict[str, Any] | None]:
    """Validate + ingest a single fact under peer-JWT auth.

    Returns (ok, error_dict_or_None).
    """
    permitted = _allowed_output_scopes(peer, token_payload)

    if fact_scope not in permitted:
        _public_module().write_audit_log(
            peer["id"],
            "scope_violation",
            {"fact_id": fact.get("id"), "scope": fact_scope},
        )
        return False, {"fact_id": fact.get("id"), "error": "scope_not_permitted"}

    # Source non-forgery: source must match the sending peer's node_id (§6.4)
    fact_source = fact.get("source", "")
    if fact_source != peer["node_id"]:
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

    tenant = TenantContext(
        tenant_id="default",
        metadata={"tenant_context_source": "pinned"},
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
            peer["node_id"],
            origin_allowed_scopes=json.loads(peer["allowed_scopes"]),
            tenant_id=tenant_id,
        )
        return True, None
    except FederationHlcSkewError:
        return False, {"fact_id": fact.get("id"), "error": "hlc_skew"}
    except FederationIntegrityError as exc:
        return False, {"fact_id": fact.get("id"), "error": exc.reason}
    except Exception:
        return False, {"fact_id": fact.get("id"), "error": "ingest_error"}
