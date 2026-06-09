"""Intent Envelope route — spec §4, §5.14 (v0.8).

POST /v1/intents
  Accept a structured IntentEnvelope, validate it, decompose it into atomic
  facts in the fabric, and return a receipt with the generated intent ID and
  all written fact IDs.

GET /v1/intents/:intent_id
  Reconstruct and return the envelope by querying its reified facts.

Fact reification schema (all facts share the same intent_id entity, except
sub-entities for constraints/preferences/deferences/artifacts):

  (intent_id, "intent:from",           ref,    from_uri, scope)
  (intent_id, "intent:goal",           text,   from_uri, scope)
  (intent_id, "intent:to",             ref,    from_uri, scope)  — one per target
  (intent_id, "intent:escalation",     string, from_uri, scope)  — priority
  (intent_id, "intent:escalate_to",    ref,    from_uri, scope)
  (intent_id, "intent:escalation:channel",  string, ...)
  (intent_id, "intent:escalation:context",  string "true"|"false", ...)
  (intent_id, "intent:handoff_to",     ref,    from_uri, scope)  — to[0] when handoff present
  (intent_id, "intent:handoff_summary",text,   from_uri, scope)
  (intent_id, "intent:context_ref",    ref,    from_uri, scope)  — one per fact_ref
  (intent_id, "intent:continuation",   text,   from_uri, scope)
  (intent_id, "intent:constraint",     ref,    from_uri, scope)  — one per constraint sub-entity
  (intent_id, "intent:preference",     ref,    from_uri, scope)  — one per preference sub-entity
  (intent_id, "intent:deference",      ref,    from_uri, scope)  — one per deference sub-entity
  (intent_id, "intent:artifact",       ref,    from_uri, scope)  — one per artifact sub-entity

Sub-entities use the pattern "{intent_id}:{kind}:{index}" for stable referencing.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from ..auth import Identity, resolve_identity
from ..db import db
from ..entity_normalizer import NormalizationError, normalize_entity_uri
from ..fact_visibility import PROJECTED_GARDEN_JOIN, caller_read_scope, visible_facts_where
from ..hlc import node_hlc
from ..models.facts import FactValue
from ..models.intents import (
    Constraint,
    DeferenceRule,
    EscalationPolicy,
    HandoffArtifact,
    HandoffPayload,
    IntentEnvelopeRecord,
    IntentEnvelopeRequest,
    Preference,
)

router = APIRouter(prefix="/v1/intents", tags=["intents"])

# Relations that identify a fact row as the root of an IntentEnvelope.
_ROOT_RELATION = "intent:goal"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encode_v(vtype: str, v: Any) -> str:
    if vtype == "null":
        return "null"
    if vtype == "boolean":
        return "true" if v else "false"
    return str(v)


def _insert(
    conn: Any,
    entity: str,
    relation: str,
    vtype: str,
    vraw: Any,
    source: str,
    scope: str,
    valid_until: str | None,
    now: str,
    tenant_id: str,
) -> str:
    fact_id = str(uuid.uuid4())
    hlc = node_hlc.tick()
    conn.execute(
        """INSERT INTO facts
           (id, entity, relation, value_type, value_v, source, timestamp,
            valid_until, confidence, scope, hlc, received_from, tenant_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            fact_id,
            entity,
            relation,
            vtype,
            _encode_v(vtype, vraw),
            source,
            now,
            valid_until,
            1.0,
            scope,
            hlc,
            None,
            tenant_id,
        ),
    )
    return fact_id


def _decompose(
    conn: Any,
    intent_id: str,
    req: IntentEnvelopeRequest,
    now: str,
    tenant_id: str,
) -> list[str]:
    """Write all atomic facts for an IntentEnvelope; return list of fact IDs."""
    src = req.from_uri
    scope = req.scope
    exp = req.expires_at
    ids: list[str] = []

    def ins(entity: str, relation: str, vtype: str, vraw: Any) -> None:
        ids.append(_insert(conn, entity, relation, vtype, vraw, src, scope, exp, now, tenant_id))

    # Core facts on intent_id
    ins(intent_id, "intent:from", "ref", req.from_uri)
    ins(intent_id, "intent:goal", "text", req.goal)
    for to_uri in req.to:
        ins(intent_id, "intent:to", "ref", to_uri)

    # Escalation
    if req.escalation:
        esc = req.escalation
        ins(intent_id, "intent:escalation", "string", esc.priority)
        ins(intent_id, "intent:escalate_to", "ref", esc.escalate_to)
        ins(intent_id, "intent:escalation:channel", "string", esc.channel)
        ins(
            intent_id,
            "intent:escalation:context",
            "string",
            "true" if esc.include_context else "false",
        )

    # Handoff
    if req.handoff:
        h = req.handoff
        # Emit intent:handoff_to pointing at first `to` for adapter compat
        if req.to:
            ins(intent_id, "intent:handoff_to", "ref", req.to[0])
        ins(intent_id, "intent:handoff_summary", "text", h.summary)
        for ref_uri in h.fact_refs:
            ins(intent_id, "intent:context_ref", "ref", ref_uri)
        if h.continuation:
            ins(intent_id, "intent:continuation", "text", h.continuation)
        for i, artifact in enumerate(h.artifacts):
            art_id = f"{intent_id}:artifact:{i}"
            ins(art_id, "intent:artifact:name", "string", artifact.name)
            ins(art_id, "intent:artifact:ref", "ref", artifact.ref)
            ins(intent_id, "intent:artifact", "ref", art_id)

    # Constraints
    for i, c in enumerate(req.constraint):
        sub = f"{intent_id}:constraint:{i}"
        ins(sub, "intent:constraint:kind", "string", c.kind)
        ins(sub, "intent:constraint:limit", c.limit.type, c.limit.v)
        if c.unit is not None:
            ins(sub, "intent:constraint:unit", "string", c.unit)
        ins(intent_id, "intent:constraint", "ref", sub)

    # Preferences
    for i, p in enumerate(req.preference):
        sub = f"{intent_id}:preference:{i}"
        ins(sub, "intent:preference:kind", "string", p.kind)
        ins(sub, "intent:preference:value", p.value.type, p.value.v)
        ins(sub, "intent:preference:weight", "number", p.weight)
        ins(intent_id, "intent:preference", "ref", sub)

    # Deferences
    for i, d in enumerate(req.deference):
        sub = f"{intent_id}:deference:{i}"
        ins(sub, "intent:deference:condition", "text", d.condition)
        ins(sub, "intent:deference:defer_to", "ref", d.defer_to)
        if d.timeout_s is not None:
            ins(sub, "intent:deference:timeout_s", "number", d.timeout_s)
        ins(intent_id, "intent:deference", "ref", sub)

    return ids


def _index_root_rows(root: list[Any]) -> tuple[dict[str, list[str]], str | None, str | None]:
    """Group root rows by relation; surface earliest timestamp + last valid_until."""
    by_rel: dict[str, list[str]] = {}
    created_at: str | None = None
    expires_at: str | None = None
    for row in root:
        by_rel.setdefault(row["relation"], []).append(row["value_v"])
        if created_at is None or row["timestamp"] < created_at:
            created_at = row["timestamp"]
        if row["valid_until"] is not None:
            expires_at = row["valid_until"]
    return by_rel, created_at, expires_at


def _build_escalation(by_rel: dict[str, list[str]]) -> EscalationPolicy | None:
    if "intent:escalation" not in by_rel:
        return None
    return EscalationPolicy(
        escalate_to=(by_rel.get("intent:escalate_to") or [""])[0],
        channel=(by_rel.get("intent:escalation:channel") or ["stigmem"])[0],
        priority=by_rel["intent:escalation"][0],
        include_context=(by_rel.get("intent:escalation:context") or ["true"])[0] == "true",
    )


def _build_handoff(
    by_rel: dict[str, list[str]],
    rows_by_entity: dict[str, list[Any]],
) -> HandoffPayload | None:
    if "intent:handoff_summary" not in by_rel:
        return None
    artifacts: list[HandoffArtifact] = []
    for art_id in by_rel.get("intent:artifact", []):
        art_by_rel = {r["relation"]: r["value_v"] for r in rows_by_entity.get(art_id, [])}
        artifacts.append(
            HandoffArtifact(
                name=art_by_rel.get("intent:artifact:name", ""),
                ref=art_by_rel.get("intent:artifact:ref", ""),
            )
        )
    cont = by_rel.get("intent:continuation")
    return HandoffPayload(
        summary=by_rel["intent:handoff_summary"][0],
        fact_refs=by_rel.get("intent:context_ref", []),
        continuation=cont[0] if cont else None,
        artifacts=artifacts,
    )


def _build_constraints(
    by_rel: dict[str, list[str]],
    rows_by_entity: dict[str, list[Any]],
) -> list[Constraint]:
    out: list[Constraint] = []
    for sub_id in by_rel.get("intent:constraint", []):
        sub_rel = {r["relation"]: r for r in rows_by_entity.get(sub_id, [])}
        kind_row = sub_rel.get("intent:constraint:kind")
        limit_row = sub_rel.get("intent:constraint:limit")
        if kind_row and limit_row:
            unit_row = sub_rel.get("intent:constraint:unit")
            out.append(
                Constraint(
                    kind=kind_row["value_v"],
                    limit=FactValue(type=limit_row["value_type"], v=limit_row["value_v"]),
                    unit=unit_row["value_v"] if unit_row else None,
                )
            )
    return out


def _build_preferences(
    by_rel: dict[str, list[str]],
    rows_by_entity: dict[str, list[Any]],
) -> list[Preference]:
    out: list[Preference] = []
    for sub_id in by_rel.get("intent:preference", []):
        sub_rel = {r["relation"]: r for r in rows_by_entity.get(sub_id, [])}
        kind_row = sub_rel.get("intent:preference:kind")
        val_row = sub_rel.get("intent:preference:value")
        if kind_row and val_row:
            wt_row = sub_rel.get("intent:preference:weight")
            out.append(
                Preference(
                    kind=kind_row["value_v"],
                    value=FactValue(type=val_row["value_type"], v=val_row["value_v"]),
                    weight=float(wt_row["value_v"]) if wt_row else 1.0,
                )
            )
    return out


def _build_deferences(
    by_rel: dict[str, list[str]],
    rows_by_entity: dict[str, list[Any]],
) -> list[DeferenceRule]:
    out: list[DeferenceRule] = []
    for sub_id in by_rel.get("intent:deference", []):
        sub_rel = {r["relation"]: r for r in rows_by_entity.get(sub_id, [])}
        cond_row = sub_rel.get("intent:deference:condition")
        defer_row = sub_rel.get("intent:deference:defer_to")
        if cond_row and defer_row:
            timeout_row = sub_rel.get("intent:deference:timeout_s")
            out.append(
                DeferenceRule(
                    condition=cond_row["value_v"],
                    defer_to=defer_row["value_v"],
                    timeout_s=int(float(timeout_row["value_v"])) if timeout_row else None,
                )
            )
    return out


def _reconstruct(
    intent_id: str, rows_by_entity: dict[str, list[Any]]
) -> IntentEnvelopeRecord | None:
    """Rebuild an IntentEnvelopeRecord from raw DB rows grouped by entity."""
    root = rows_by_entity.get(intent_id, [])
    if not root:
        return None

    by_rel, created_at, expires_at = _index_root_rows(root)
    if _ROOT_RELATION not in by_rel:
        return None

    return IntentEnvelopeRecord(
        id=intent_id,
        **{"from": (by_rel.get("intent:from") or [""])[0]},
        to=by_rel.get("intent:to", []),
        goal=by_rel[_ROOT_RELATION][0],
        scope=root[0]["scope"],
        created_at=created_at or datetime.now(UTC).isoformat(),
        expires_at=expires_at,
        constraint=_build_constraints(by_rel, rows_by_entity),
        preference=_build_preferences(by_rel, rows_by_entity),
        deference=_build_deferences(by_rel, rows_by_entity),
        escalation=_build_escalation(by_rel),
        handoff=_build_handoff(by_rel, rows_by_entity),
        fact_ids=[],  # not returned on GET; fact_ids are a POST-only receipt
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=IntentEnvelopeRecord,
    response_model_by_alias=True,
    status_code=status.HTTP_201_CREATED,
)
def submit_intent(
    req: IntentEnvelopeRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> IntentEnvelopeRecord:
    """Submit an IntentEnvelope (Spec-X8-Intent-Envelope).

    Validates the envelope, normalizes URIs, decomposes it into atomic facts,
    and returns a receipt with the generated intent ID and all written fact IDs.
    Idempotent when the caller supplies a stable ``id``: if that intent_id already
    has a ``intent:goal`` fact in the fabric, returns 409 Conflict.
    """
    if not identity.can_write():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="write permission required"
        )

    # Normalize URIs
    try:
        from_uri = normalize_entity_uri(req.from_uri)
    except NormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid_entity_uri: from — {exc}",
        ) from exc

    normalized_to: list[str] = []
    for i, t in enumerate(req.to):
        try:
            normalized_to.append(normalize_entity_uri(t))
        except NormalizationError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid_entity_uri: to[{i}] — {exc}",
            ) from exc

    # Resolve intent_id
    intent_id = req.id if req.id else f"intent:{uuid.uuid4()}"

    now = datetime.now(UTC).isoformat()

    with db() as conn:
        # Idempotency check: reject if intent_id already exists in this tenant
        # (tenant-scoped so it is not a cross-tenant existence oracle).
        existing = conn.execute(
            "SELECT id FROM facts WHERE entity=? AND relation=? AND tenant_id=? LIMIT 1",
            (intent_id, _ROOT_RELATION, identity.tenant_id),
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"intent {intent_id!r} already exists; supply a new id "
                    "or omit for auto-generation"
                ),
            )

        # Build a normalised copy for decomposition
        normalised_req = req.model_copy(update={"from_uri": from_uri, "to": normalized_to})
        fact_ids = _decompose(conn, intent_id, normalised_req, now, identity.tenant_id)

    return IntentEnvelopeRecord(
        id=intent_id,
        **{"from": from_uri},
        to=normalized_to,
        goal=req.goal,
        scope=req.scope,
        created_at=now,
        expires_at=req.expires_at,
        constraint=req.constraint,
        preference=req.preference,
        deference=req.deference,
        escalation=req.escalation,
        handoff=req.handoff,
        fact_ids=fact_ids,
    )


@router.get(
    "/{intent_id:path}",
    response_model=IntentEnvelopeRecord,
    response_model_by_alias=True,
)
def get_intent(
    intent_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> IntentEnvelopeRecord:
    """Retrieve an IntentEnvelope by ID, reconstructed from its reified facts.

    Covered by Spec-X8-Intent-Envelope.
    """
    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    now = datetime.now(UTC).isoformat()
    # Escape LIKE metacharacters so a caller-supplied intent_id cannot inject
    # wildcards into the prefix scan (audit intents sibling of F-10).
    safe_prefix = intent_id.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    prefix = f"{safe_prefix}:%"

    # Restrict to facts the caller may read — own tenant + visible garden (audit
    # intents cross-tenant/garden sibling). visible_facts_where adds the
    # tenant + projected-garden predicate; PROJECTED_GARDEN_JOIN supplies fgm.
    read_scope = caller_read_scope(identity)
    scope_sql, scope_params = visible_facts_where(read_scope)
    sql = (
        f"SELECT f.* FROM facts f {PROJECTED_GARDEN_JOIN}"  # noqa: S608  # nosec B608
        "   WHERE (f.entity = ? OR f.entity LIKE ? ESCAPE '\\')"
        "     AND f.confidence > 0.0"
        "     AND (f.valid_until IS NULL OR f.valid_until > ?)"
        f"   {scope_sql}"
        "   ORDER BY f.entity, f.relation"
    )

    with db() as conn:
        rows = conn.execute(sql, [intent_id, prefix, now, *scope_params]).fetchall()

    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="intent not found")

    rows_by_entity: dict[str, list[Any]] = {}
    for row in rows:
        rows_by_entity.setdefault(row["entity"], []).append(row)

    record = _reconstruct(intent_id, rows_by_entity)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="intent not found")

    return record
