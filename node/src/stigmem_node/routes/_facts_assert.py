"""Implementation of POST /v1/facts (assert_fact) extracted from routes/facts.py.

Imported back into ``routes.facts``; the route stub there delegates to this
function inside its tracing span.  Helper symbols are imported lazily inside
the function to keep the module-level import graph acyclic.
No behavioural changes — code was moved verbatim from facts.py.
"""

from __future__ import annotations

import logging
import sys
import threading
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status

from ..auth import Identity
from ..billing import BillingEvent, get_hook_bus
from ..cid import compute_cid
from ..db import db
from ..entity_normalizer import NormalizationError, is_informal, normalize_entity_uri
from ..garden_acl import (
    get_garden_by_garden_uri,
    require_garden_write,
)
from ..hlc import node_hlc
from ..lifecycle.immutability import set_embedding_status, write_fact_journal
from ..metrics import CONTRADICTION, FACT_WRITE
from ..models.facts import AssertRequest, FactRecord, row_to_record
from ..plugins import TenantContext, get_registry
from ..recall.fuzzy_resolver import resolve_entity
from ..session_graph import encode_derived_from, ensure_write_allowed, record_write_scope
from ..settings import settings as _settings  # noqa: F401  — kept for parity


def _live_settings() -> Any:
    """Return the live Settings singleton.

    Uses sys.modules directly because some test fixtures replace
    `stigmem_node.settings` (the module attribute on the parent package) with
    a Settings instance. `from .. import settings` and `import x.y` both go
    through that patched attribute and would return the instance instead of
    the module — sys.modules['stigmem_node.settings'] is the only path that
    reliably reaches the original module so we can read its `.settings`
    singleton (which IS what tests intend to swap).
    """
    return sys.modules["stigmem_node.settings"].settings


logger = logging.getLogger("stigmem.facts")


def _verify_or_require_attestation(req: AssertRequest, identity: Identity) -> str | None:
    """C1: verify the attestation token (when supplied) or fail-closed if required."""
    from .facts import _encode_v

    if req.attestation is not None:
        from .agent_keys import verify_attestation

        value_v_for_sig = _encode_v(req.value.type, req.value.v)
        canonical = (
            f"{req.entity}\n{req.relation}\n{req.value.type}\n{value_v_for_sig}\n{req.source}"
        ).encode()
        return verify_attestation(
            key_id=req.attestation.key_id,
            signature_b64=req.attestation.signature,
            canonical_message=canonical,
            caller_entity_uri=identity.entity_uri,
        )
    if _live_settings().attestation_required:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="attestation required; register an agent key at POST /v1/auth/agent-keys",
        )
    return None


def _normalise_and_alias_uris(req: AssertRequest) -> tuple[str, str]:
    """Layer-1 strict normalisation + Layer-2 alias lookup. Emits deprecation warnings."""
    try:
        entity = normalize_entity_uri(req.entity)
        source = normalize_entity_uri(req.source)
    except NormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_entity_uri: {exc}",
        ) from exc

    # Deprecation warning for informal URIs (spec §2.5)
    if is_informal(req.entity):
        print(
            f"[stigmem] DEPRECATED: informal entity URI {req.entity!r} — "
            f"use stigmem://authority/type/id format (spec §2.5)",
            file=sys.stderr,
        )
    if is_informal(req.source):
        print(
            f"[stigmem] DEPRECATED: informal source URI {req.source!r} — "
            f"use stigmem://authority/type/id format (spec §2.5)",
            file=sys.stderr,
        )

    # Layer 2: resolve user-defined semantic aliases (spec §2.6.6) on canonical forms.
    with db() as _alias_conn:
        return resolve_entity(_alias_conn, entity), resolve_entity(_alias_conn, source)


def _resolve_garden_for_assert(req: AssertRequest, identity: Identity) -> Any:
    """Spec §17.3: resolve garden_id, enforce scope match + write ACL. Returns row or None."""
    if req.garden_id is None:
        return None
    garden = get_garden_by_garden_uri(req.garden_id, tenant_id=identity.tenant_id)
    if garden is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="garden not found")
    if garden["scope"] != req.scope:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                f"scope mismatch: garden scope is '{garden['scope']}' "
                f"but fact scope is '{req.scope}'"
            ),
        )
    require_garden_write(garden, identity)
    return garden


def _existing_record_for_cid(
    conn: Any,
    fact_cid: str,
    tenant_id: str,
) -> FactRecord | None:
    """Return the existing record for ``fact_cid``, or None when no alias exists yet."""
    existing_alias = conn.execute(
        "SELECT fact_id FROM fact_cid_aliases WHERE cid = ?", (fact_cid,)
    ).fetchone()
    if existing_alias is None:
        return None
    existing_row = conn.execute(
        "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
        (existing_alias["fact_id"], tenant_id),
    ).fetchone()
    return row_to_record(existing_row, contradicted=False) if existing_row is not None else None


def _require_interpretation_write(identity: Identity, interpret_as: str) -> None:
    if interpret_as != "instruction":
        return
    if identity.can_write_instruction():
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "code": "instruction_write_required",
            "message": "writing instruction-typed facts requires instruction:write permission",
        },
    )


def _detect_and_record_contradictions(
    conn: Any,
    fact_id: str,
    entity: str,
    req: AssertRequest,
    identity: Identity,
) -> bool:
    """Spec §9.1: skip system facts; else find siblings sharing (entity, relation, scope)."""
    from .facts import _SYSTEM_RELATION_PREFIX, _record_contradictions

    is_system = (
        entity.startswith(_SYSTEM_RELATION_PREFIX) and not entity.startswith("stigmem://")
    ) or (
        req.relation.startswith(_SYSTEM_RELATION_PREFIX)
        and not req.relation.startswith("stigmem://")
    )
    if is_system:
        return False
    siblings = conn.execute(
        """SELECT id FROM facts
           WHERE entity=? AND relation=? AND scope=? AND id!=? AND confidence>0.0
             AND tenant_id=?""",
        (entity, req.relation, req.scope, fact_id, identity.tenant_id),
    ).fetchall()
    if not siblings:
        return False
    _record_contradictions(
        conn,
        fact_id,
        entity,
        req.relation,
        req.scope,
        siblings,
        identity.tenant_id,
    )
    print(
        f"[stigmem] WARN: collision — entity={entity!r} relation={req.relation!r} "
        f"scope={req.scope!r}: fact {fact_id!r} contradicts {len(siblings)} existing "
        f"fact(s); verify relation namespacing (see relation-convention.md)",
        file=sys.stderr,
    )
    return True


def _emit_post_write_hooks(
    *,
    fact_id: str,
    entity: str,
    source: str,
    req: AssertRequest,
    identity: Identity,
    value_v: str | None,
    garden_uuid: str | None,
    now: str,
    contradicted: bool,
    _span: object,
) -> None:
    """Card-stale + background embed + billing + subscription fan-out + metrics + span attrs."""
    from .facts import _embed_fact_background

    # Phase 9: mark entity's memory card stale on every write (ACM-214)
    try:
        from ..card_materializer import mark_entity_stale as _mark_stale

        _mark_stale(entity, req.scope, identity.tenant_id)
    except Exception as _card_exc:
        logger.warning("card mark_stale failed for %r: %s", entity, _card_exc)

    # Phase 9 §2: write-time embedding (background thread, graceful fallback)
    if _live_settings().embed_enabled:
        threading.Thread(
            target=_embed_fact_background,
            args=(fact_id, entity, req.relation, req.value.type, value_v or ""),
            daemon=True,
        ).start()

    get_hook_bus().emit(
        BillingEvent(
            event_type="fact_written",
            tenant_id=identity.tenant_id,
            entity_uri=identity.entity_uri,
            fact_id=fact_id,
        )
    )

    # §20: fan out to subscribers (fast DB insert only; delivery happens in sweep loop)
    try:
        import json as _json

        from ..subscription_delivery import fan_out as _subscription_fan_out

        _subscription_fan_out(
            fact_id=fact_id,
            entity=entity,
            scope=req.scope,
            garden_id=garden_uuid,
            tenant_id=identity.tenant_id,
            fact_payload_json=_json.dumps(
                {
                    "id": fact_id,
                    "entity": entity,
                    "relation": req.relation,
                    "value_type": req.value.type,
                    "value_v": value_v,
                    "source": source,
                    "timestamp": now,
                    "scope": req.scope,
                    "confidence": req.confidence,
                    "garden_id": garden_uuid,
                }
            ),
        )
    except Exception as _sub_exc:
        print(f"[stigmem] WARN: subscription fan_out failed: {_sub_exc}", file=sys.stderr)

    FACT_WRITE.labels(principal=identity.entity_uri, tenant=identity.tenant_id).inc()
    if contradicted:
        CONTRADICTION.labels(tenant=identity.tenant_id).inc()
    try:
        _span.set_attribute("stigmem.fact_id", fact_id)  # type: ignore[attr-defined]
        _span.set_attribute("stigmem.contradicted", contradicted)  # type: ignore[attr-defined]
    except AttributeError as _span_exc:
        logger.debug("span attribute set skipped: %s", _span_exc)


def assert_fact_impl(
    req: AssertRequest,
    identity: Identity,
    _span: object,
    *,
    request_id: str,
    tenant: TenantContext,
    session_id: str | None = None,
) -> FactRecord:
    # Lazy imports of sibling helpers to avoid circular import with .facts
    from .facts import (
        _encode_v,
        _is_valid_entity_uri,
        _validate_relation,
    )

    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="write permission required",
        )

    attested_key_id = _verify_or_require_attestation(req, identity)
    entity, source = _normalise_and_alias_uris(req)

    # Source-attestation policy is plugin-owned. Core preserves the field but
    # does not evaluate source/identity binding in default installs.
    attested = None
    garden = _resolve_garden_for_assert(req, identity)

    garden_uuid = garden["id"] if garden is not None else None
    attested_int = None if attested is None else (1 if attested else 0)

    # Relation namespacing convention check (see relation-convention.md)
    relation_warnings = _validate_relation(req.relation)
    for w in relation_warnings:
        print(f"[stigmem] WARN: relation naming: {w}", file=sys.stderr)

    _require_interpretation_write(identity, req.value.interpret_as)

    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    hlc = node_hlc.tick()
    value_v = _encode_v(req.value.type, req.value.v)

    # §25.7.3: compute CID before write; persisted in the same transaction
    fact_cid = compute_cid(
        entity=entity,
        relation=req.relation,
        value_type=req.value.type,
        value_v=value_v or "",
        source=source,
        scope=req.scope,
        confidence=req.confidence,
        interpret_as=req.value.interpret_as,
    )

    _embed_enabled = _live_settings().embed_enabled
    embedding_missing_val = 1 if _embed_enabled else None

    derived_from_json = encode_derived_from(req.derived_from)

    # F-10 §25.7.3: idempotent CID pre-check — if CID already exists, return existing record
    with db() as _precheck_conn:
        ensure_write_allowed(
            _precheck_conn,
            identity=identity,
            session_id=session_id,
            target_scope=req.scope,
            write_mode=req.write_mode,
            derived_from=req.derived_from,
        )
        existing_record = _existing_record_for_cid(_precheck_conn, fact_cid, identity.tenant_id)
    if existing_record is not None:
        return existing_record

    with db() as conn:
        ensure_write_allowed(
            conn,
            identity=identity,
            session_id=session_id,
            target_scope=req.scope,
            write_mode=req.write_mode,
            derived_from=req.derived_from,
        )
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, attested_key_id,
                garden_id, attested, tenant_id, embedding_missing, cid, derived_from,
                interpret_as)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                entity,  # normalized (spec §2.6)
                req.relation,
                req.value.type,
                value_v,
                source,  # normalized (spec §2.6)
                now,
                req.valid_until,
                req.confidence,
                req.scope,
                hlc,
                None,  # local write; not received from a peer
                attested_key_id,
                garden_uuid,
                attested_int,
                identity.tenant_id,
                embedding_missing_val,
                fact_cid,
                derived_from_json,
                req.value.interpret_as,
            ),
        )
        write_fact_journal(
            conn,
            fact_id=fact_id,
            event_type="fact_insert",
            tenant_id=identity.tenant_id,
            actor_uri=identity.entity_uri,
            source=source,
            scope=req.scope,
            cid=fact_cid,
            body={
                "entity": entity,
                "relation": req.relation,
                "value_type": req.value.type,
                "value_v": value_v,
                "source": source,
                "timestamp": now,
                "valid_until": req.valid_until,
                "confidence": req.confidence,
                "scope": req.scope,
                "interpret_as": req.value.interpret_as,
            },
        )
        if embedding_missing_val is not None:
            set_embedding_status(
                conn,
                fact_id=fact_id,
                embedding_missing=bool(embedding_missing_val),
                updated_by="fact_assert",
            )

        # F-10 §25.7.3: alias table row — idempotent upsert on CID collision
        alias_result = conn.execute(
            "INSERT OR IGNORE INTO fact_cid_aliases (fact_id, cid) VALUES (?, ?)",
            (fact_id, fact_cid),
        )
        if alias_result.rowcount == 0:
            # Concurrent same-CID write race: return existing record
            existing = conn.execute(
                "SELECT f.* FROM facts f JOIN fact_cid_aliases a ON a.fact_id = f.id"
                " WHERE a.cid = ? AND f.tenant_id = ?",
                (fact_cid, identity.tenant_id),
            ).fetchone()
            if existing is not None:
                return row_to_record(existing, contradicted=False)

        record_write_scope(
            conn,
            identity=identity,
            session_id=session_id,
            scope=req.scope,
        )

        # C3 / §22.3: write-ahead audit entry for fact_write event (same transaction)
        from ..audit_event import emit as _emit_audit

        _emit_audit(
            "fact_write",
            entity_uri=identity.entity_uri,
            tenant_id=identity.tenant_id,
            oidc_sub=identity.oidc_sub,
            fact_id=fact_id,
            source=source,
            attested_key_id=attested_key_id,
            scope=req.scope,
            conn=conn,
        )

        # Graph adjacency index (§20.1.1): materialize edge for ref-typed facts
        if req.value.type == "ref" and value_v and _is_valid_entity_uri(value_v):
            from ..recall.graph_index import upsert_edge as _upsert_edge

            _upsert_edge(
                conn,
                fact_id=fact_id,
                subject=entity,
                relation=req.relation,
                object_uri=value_v,
                scope=req.scope,
                confidence=req.confidence,
                garden_id=garden_uuid,
                tenant_id=identity.tenant_id,
                received_from=None,
                source_trust=None,
                valid_until=req.valid_until,
            )

        row = conn.execute("SELECT * FROM facts WHERE id=?", (fact_id,)).fetchone()
        from ..fact_chain import append_fact_chain_entry

        append_fact_chain_entry(conn, row)
        persisted_record = row_to_record(row, contradicted=False)
        get_registry().fire_fire_and_forget(
            "post_assert_persist",
            fact=persisted_record,
            identity=identity,
            tenant=tenant,
            request_id=request_id,
        )
        contradicted = _detect_and_record_contradictions(conn, fact_id, entity, req, identity)

    _emit_post_write_hooks(
        fact_id=fact_id,
        entity=entity,
        source=source,
        req=req,
        identity=identity,
        value_v=value_v,
        garden_uuid=garden_uuid,
        now=now,
        contradicted=contradicted,
        _span=_span,
    )

    return row_to_record(row, contradicted=contradicted, warnings=relation_warnings)
