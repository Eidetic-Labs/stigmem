"""Idempotent fact ingestion from federated peers (spec §6.3, §6.5, §19.4–19.5).

ingest_fact() is the single entry-point for all federated facts.
It is safe to call multiple times for the same fact (no-op after first write).

Phase 8 (§19): source-trust score is computed at ingest time and stored as a
snapshot in facts.source_trust.  In trust_mode=strict, facts with t < 0.2 are
routed to the node's designated quarantine garden instead of the main fact table.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from ..db import db
from ..hlc import HLCRemoteSkewError, node_hlc
from ..models.facts import VALID_INTERPRET_AS
from ..observability.audit_event import (
    INSTRUCTION_QUARANTINED,
    emit_instruction_event_if_applicable,
    is_instruction_fact,
)
from ..observability.metrics import PEER_HLC_ANOMALY


class FederationHlcSkewError(ValueError):
    """Inbound federated fact was rejected because its HLC wall time is implausible."""

    def __init__(self, fact_id: str, sender_node_id: str, cause: HLCRemoteSkewError) -> None:
        self.fact_id = fact_id
        self.sender_node_id = sender_node_id
        self.direction = cause.direction
        self.skew_ms = cause.skew_ms
        self.remote_wall_ms = cause.remote_wall_ms
        self.local_wall_ms = cause.local_wall_ms
        super().__init__(
            "remote HLC skew outside configured bound "
            f"(fact_id={fact_id}, sender={sender_node_id}, direction={self.direction})"
        )


class FederationIntegrityError(ValueError):
    """Inbound federated fact failed integrity verification before ingest."""

    def __init__(
        self,
        *,
        fact_id: str,
        sender_node_id: str,
        reason: str,
        stored_cid: str | None = None,
        computed_cid: str | None = None,
    ) -> None:
        self.fact_id = fact_id
        self.sender_node_id = sender_node_id
        self.reason = reason
        self.stored_cid = stored_cid
        self.computed_cid = computed_cid
        super().__init__(f"inbound fact integrity verification failed: {reason}")


class FederationValidUntilExtensionError(ValueError):
    """Inbound federated fact tried to extend an existing valid_until."""

    def __init__(
        self,
        *,
        fact_id: str,
        sender_node_id: str,
        stored_valid_until: str | None,
        incoming_valid_until: str | None,
    ) -> None:
        self.fact_id = fact_id
        self.sender_node_id = sender_node_id
        self.stored_valid_until = stored_valid_until
        self.incoming_valid_until = incoming_valid_until
        super().__init__(
            "federation ingest rejected: incoming valid_until "
            f"({incoming_valid_until}) extends stored ({stored_valid_until}) "
            f"for fact_id={fact_id}, sender={sender_node_id} (R-18)"
        )


def _encode_v(value: dict[str, Any]) -> str:
    vtype = value["type"]
    v = value.get("v")
    if vtype == "null":
        return "null"
    if vtype == "boolean":
        return "true" if v else "false"
    return str(v)


def _interpret_as(fact: dict[str, Any]) -> str:
    interpret_as = fact.get("value", {}).get("interpret_as", "content")
    if interpret_as not in VALID_INTERPRET_AS:
        from fastapi import HTTPException

        raise HTTPException(status_code=422, detail="invalid_interpret_as")
    return str(interpret_as)


def _verify_inbound_cid(fact: dict[str, Any], sender_node_id: str) -> str | None:
    from ..cid import compute_cid

    stored_cid = fact.get("cid")
    if stored_cid is None:
        return None
    fact_id = str(fact.get("id", ""))
    value = fact.get("value", {})
    computed_cid = compute_cid(
        entity=str(fact.get("entity", "")),
        relation=str(fact.get("relation", "")),
        value_type=str(value.get("type", "")),
        value_v=_encode_v(value),
        source=str(fact.get("source", "")),
        scope=str(fact.get("scope", "")),
        confidence=float(fact.get("confidence", 1.0)),
        interpret_as=str(value.get("interpret_as", "content")),
    )
    if stored_cid != computed_cid:
        raise FederationIntegrityError(
            fact_id=fact_id,
            sender_node_id=sender_node_id,
            reason="cid_mismatch",
            stored_cid=str(stored_cid),
            computed_cid=computed_cid,
        )
    return str(stored_cid)


def _resolve_quarantine_garden_id(failure_detail: str) -> str:
    from ..settings import settings

    qg_id = settings.quarantine_garden_id
    if not qg_id:
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail=failure_detail)

    with db() as conn:
        qg_row = conn.execute(
            "SELECT id FROM gardens WHERE (id = ? OR slug = ?) AND quarantine = 1",
            (qg_id, qg_id),
        ).fetchone()
    if qg_row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=403, detail=failure_detail)
    return str(qg_row["id"])


def _audit_peer_hlc_anomaly(
    *,
    conn: Any,
    fact_id: str,
    sender_node_id: str,
    exc: HLCRemoteSkewError,
) -> None:
    from ..observability.audit_event import emit

    PEER_HLC_ANOMALY.labels(peer_id=sender_node_id, direction=exc.direction).inc()
    emit(
        "peer_hlc_anomaly",
        entity_uri="system:federation",
        fact_id=fact_id,
        source=sender_node_id,
        detail={
            "sender_node_id": sender_node_id,
            "direction": exc.direction,
            "skew_ms": exc.skew_ms,
            "remote_wall_ms": exc.remote_wall_ms,
            "local_wall_ms": exc.local_wall_ms,
            "max_future_skew_ms": exc.max_future_skew_ms,
            "max_past_skew_ms": exc.max_past_skew_ms,
        },
        conn=conn,
    )


def _audit_peer_integrity_failure(
    *,
    conn: Any,
    exc: FederationIntegrityError,
) -> None:
    from ..observability.audit_event import emit

    emit(
        "federation_integrity_rejected",
        entity_uri="system:federation",
        fact_id=exc.fact_id,
        source=exc.sender_node_id,
        detail={
            "sender_node_id": exc.sender_node_id,
            "reason": exc.reason,
            "stored_cid": exc.stored_cid,
            "computed_cid": exc.computed_cid,
        },
        conn=conn,
    )


def _audit_valid_until_extension(
    *,
    conn: Any,
    exc: FederationValidUntilExtensionError,
) -> None:
    from ..observability.audit_event import emit

    emit(
        "federation_valid_until_extension_rejected",
        entity_uri="system:federation",
        fact_id=exc.fact_id,
        source=exc.sender_node_id,
        detail={
            "sender_node_id": exc.sender_node_id,
            "stored_valid_until": exc.stored_valid_until,
            "incoming_valid_until": exc.incoming_valid_until,
            "reason": (
                "R-18: federation peer attempted to extend valid_until beyond "
                "the locally-stored value; rejected per local recomputation "
                "invariant"
            ),
        },
        conn=conn,
    )


def _is_valid_until_extension(stored: str | None, incoming: str | None) -> bool:
    """Return True when incoming would extend locally observed visibility.

    R-18 is independent of Phase 2b origin signing: a signed ``valid_until``
    authenticates the *value* the origin asserted, it does NOT grant the right
    to extend an already-observed visibility window. This guard fires on the
    locally-stored value regardless of whether the inbound fact carried a valid
    origin_sig.
    """

    if stored is None:
        return False
    if incoming is None:
        return True

    stored_ts = datetime.fromisoformat(stored.replace("Z", "+00:00"))
    incoming_ts = datetime.fromisoformat(incoming.replace("Z", "+00:00"))
    if stored_ts.tzinfo is None:
        stored_ts = stored_ts.replace(tzinfo=UTC)
    if incoming_ts.tzinfo is None:
        incoming_ts = incoming_ts.replace(tzinfo=UTC)
    return incoming_ts > stored_ts


def ingest_fact(
    fact: dict[str, Any],
    sender_node_id: str,
    origin_node_id: str | None = None,
    origin_allowed_scopes: list[str] | None = None,
    *,
    tenant_id: str,
    origin_tenant: str | None = None,
    origin_allowed_tenants: list[str] | None = None,
    origin_sig: str | None = None,
    origin_entity_uri: str | None = None,
    identity_strength_boost: float | None = None,
) -> bool:
    """Idempotently ingest a federated fact.

    Returns True if the fact was new, False if it already existed (no-op).
    Writes stigmem:received_from meta-fact atomically with the fact.
    Advances the local HLC.
    Detects contradictions and writes conflict entities (spec §6.5, §3.3).

    Phase 8 (§19): computes source_trust at ingest; routes to quarantine garden
    when trust_mode=strict and t < 0.2, or rejects with 403 if no quarantine
    garden is configured.

    origin_node_id / origin_allowed_scopes populate the v0.8 scope-propagation
    columns (spec §6.8.1, Migration 004). When None, defaults to sender_node_id
    and the fact's scope as a single-element list (first-hop inference).

    Company-scope facts are re_federation_blocked=1 by default (spec §6.8.2):
    the originating node's grant is non-transitive.
    """
    from ..settings import settings
    from ..source_trust import compute_source_trust

    fact_id = fact["id"]
    scope = fact["scope"]
    source = fact["source"]
    try:
        inbound_cid = _verify_inbound_cid(fact, sender_node_id)
    except FederationIntegrityError as exc:
        with db() as conn:
            _audit_peer_integrity_failure(conn=conn, exc=exc)
            conn.commit()
        raise
    interpret_as = _interpret_as(fact)
    is_instruction = is_instruction_fact(
        fact.get("entity"),
        fact.get("relation"),
        interpret_as,
    )

    # Phase 8: compute source-trust snapshot (§19.4)
    trust_score: float | None = None
    quarantine_garden_db_id: str | None = None
    quarantine_status: str | None = None
    quarantine_reason: str | None = None

    if is_instruction:
        quarantine_garden_db_id = _resolve_quarantine_garden_id("quarantine_garden_required")
        quarantine_status = "pending"
        quarantine_reason = "instruction_federation_inbound"

    trust_mode = settings.trust_mode
    if trust_mode != "off":
        trust_score = compute_source_trust(
            source,
            scope,
            identity=None,
            identity_strength_override=identity_strength_boost,
        )

        if trust_mode == "strict" and trust_score < 0.2:
            quarantine_garden_db_id = _resolve_quarantine_garden_id("trust_below_threshold")
            quarantine_status = "pending"
            quarantine_reason = "trust_below_threshold"

    # Scope-propagation columns (spec §6.8.1)
    # The v2 path passes explicit verified values for origin_node_id; the
    # origin==sender equality invariant is enforced at the route/client layer
    # (Phase 2b Task 5), not here — this resolver only fills the column.
    eff_origin_node_id = origin_node_id or sender_node_id
    eff_origin_scopes: str | None
    if origin_allowed_scopes is not None:
        eff_origin_scopes = json.dumps(sorted(origin_allowed_scopes))
    else:
        eff_origin_scopes = json.dumps([scope])
    # Phase 2b origin block (Migration 044): persist the verified per-origin tenant
    # claim byte-identical to the signed canonical form (F-8: json.dumps(sorted(...))
    # mirrors eff_origin_scopes). Populated by the v2 route/client in Task 5.
    eff_origin_tenants: str | None = (
        json.dumps(sorted(origin_allowed_tenants)) if origin_allowed_tenants is not None else None
    )
    # Phase 2c W3.1 (Migration 046): persist the verified origin entity_uri (the value bound
    # into the v2.1 signed origin tuple). NULL for local-origin / pre-v2.1 facts. A relayed
    # fact forwards this stored value so its origin_sig verifies against the ORIGIN's manifest.
    eff_origin_entity_uri: str | None = origin_entity_uri
    # company-scope facts: re-federation is blocked by default (§6.8.2)
    re_fed_blocked = 1 if scope == "company" else 0

    with db() as conn:
        existing = conn.execute(
            "SELECT id, valid_until FROM facts WHERE id = ?",
            (fact_id,),
        ).fetchone()
        if existing is not None:
            stored_valid_until = existing["valid_until"]
            incoming_valid_until = fact.get("valid_until")
            if _is_valid_until_extension(stored_valid_until, incoming_valid_until):
                violation = FederationValidUntilExtensionError(
                    fact_id=fact_id,
                    sender_node_id=sender_node_id,
                    stored_valid_until=stored_valid_until,
                    incoming_valid_until=incoming_valid_until,
                )
                _audit_valid_until_extension(conn=conn, exc=violation)
                conn.commit()
                raise violation
            return False  # already ingested; silent no-op per spec §5.8

        # Advance HLC (spec §6.3)
        remote_hlc = fact.get("hlc")
        try:
            new_hlc = (
                node_hlc.receive(
                    remote_hlc,
                    max_future_skew_ms=settings.federation_hlc_max_future_skew_s * 1000,
                    max_past_skew_ms=settings.federation_hlc_max_past_skew_s * 1000,
                )
                if remote_hlc
                else node_hlc.tick()
            )
        except HLCRemoteSkewError as exc:
            _audit_peer_hlc_anomaly(
                conn=conn,
                fact_id=fact_id,
                sender_node_id=sender_node_id,
                exc=exc,
            )
            # The fact insert is rejected, but the anomaly audit event is the
            # security evidence. Commit it before raising so the surrounding
            # transaction rollback does not erase the rejection trail.
            conn.commit()
            raise FederationHlcSkewError(fact_id, sender_node_id, exc) from exc

        # Insert the fact with received_from + scope-propagation columns (Migration 004)
        # Phase 8: also store source_trust snapshot + quarantine metadata
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from,
                origin_node_id, origin_allowed_scopes, re_federation_blocked,
                source_trust, quarantine_garden_id, quarantine_status,
                quarantine_reason, interpret_as, cid, tenant_id,
                origin_tenant, origin_allowed_tenants, origin_sig, origin_entity_uri)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                fact["entity"],
                fact["relation"],
                fact["value"]["type"],
                _encode_v(fact["value"]),
                source,
                fact["timestamp"],
                fact.get("valid_until"),
                fact["confidence"],
                scope,
                new_hlc,
                sender_node_id,
                eff_origin_node_id,
                eff_origin_scopes,
                re_fed_blocked,
                trust_score,
                quarantine_garden_db_id,
                quarantine_status,
                quarantine_reason,
                interpret_as,
                inbound_cid,
                tenant_id,
                origin_tenant,
                eff_origin_tenants,
                origin_sig,
                eff_origin_entity_uri,
            ),
        )

        # Phase 8 §19.5.4: audit entry for ingest-time quarantine routing
        if quarantine_status == "pending":
            audit_id = str(uuid.uuid4())
            audit_now = datetime.now(UTC).isoformat()
            conn.execute(
                """INSERT INTO fact_audit_log
                   (id, fact_id, event_type, entity_uri, oidc_sub, source,
                    attested_key_id, detail, ts)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    audit_id,
                    fact_id,
                    "quarantine_ingest",
                    "system:federation",
                    None,
                    sender_node_id,
                    None,
                    json.dumps(
                        {
                            "reason": quarantine_reason,
                            "trust_score": trust_score,
                            "interpret_as": interpret_as,
                        }
                    ),
                    audit_now,
                ),
            )
            emit_instruction_event_if_applicable(
                INSTRUCTION_QUARANTINED,
                fact_id=fact_id,
                fact_entity=fact.get("entity"),
                fact_relation=fact.get("relation"),
                fact_interpret_as=interpret_as,
                actor_uri="system:federation",
                source=sender_node_id,
                detail={
                    "reason": quarantine_reason,
                    "trust_score": trust_score,
                    "received_from": sender_node_id,
                },
                conn=conn,
            )

        # Write stigmem:received_from meta-fact atomically (spec §3.1)
        meta_id = str(uuid.uuid4())
        meta_now = datetime.now(UTC).isoformat()
        meta_hlc = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                meta_id,
                fact_id,  # entity = the ingested fact's ID
                "stigmem:received_from",
                "ref",
                sender_node_id,
                "system:stigmem",
                meta_now,
                None,
                1.0,
                "local",  # meta-facts are local; MUST NOT be re-replicated (spec §3.1)
                meta_hlc,
                None,
                tenant_id,
            ),
        )

        # Contradiction detection — skip for quarantined facts (§19.5.2)
        if quarantine_status is None:
            _detect_and_record_contradiction(conn, fact, fact_id, tenant_id)

    return True


_STIGMEM_NS = "stigmem:"
_STIGMEM_URI_NS = "stigmem://"


def _is_reserved_stigmem(s: str) -> bool:
    """True for bare stigmem: system names (e.g. 'stigmem:conflict:x').
    False for stigmem:// URI entities which are user content."""
    return s.startswith(_STIGMEM_NS) and not s.startswith(_STIGMEM_URI_NS)


def _detect_and_record_contradiction(
    conn: Any,
    fact: dict[str, Any],
    fact_id: str,
    tenant_id: str,
) -> None:
    """If a contradiction exists, assert conflict entities and write conflicts table."""
    # Reserved stigmem: facts are system state (status transitions, meta-facts), not
    # semantic content. Two stigmem:conflict:status facts with different values represent
    # a state transition, not a contradiction — exempt them from sibling-detection (§9.1).
    # Note: stigmem:// URI entities are user content and ARE subject to detection.
    if _is_reserved_stigmem(fact["entity"]) or _is_reserved_stigmem(fact["relation"]):
        return

    siblings = conn.execute(
        """SELECT id FROM facts
           WHERE entity = ? AND relation = ? AND scope = ?
             AND id != ? AND confidence > 0.0 AND tenant_id = ?""",
        (fact["entity"], fact["relation"], fact["scope"], fact_id, tenant_id),
    ).fetchall()

    if not siblings:
        return

    now = datetime.now(UTC).isoformat()

    for sibling in siblings:
        sibling_id = sibling["id"]
        conflict_uuid = str(uuid.uuid4())
        conflict_id = f"stigmem:conflict:{conflict_uuid}"

        # Skip if this pair already has a conflict record
        already = conn.execute(
            """SELECT c.id FROM conflicts c
               WHERE (c.fact_a_id = ? AND c.fact_b_id = ?)
                  OR (c.fact_a_id = ? AND c.fact_b_id = ?)""",
            (fact_id, sibling_id, sibling_id, fact_id),
        ).fetchone()
        if already:
            continue

        hlc_between = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                conflict_id,
                "stigmem:conflict:between",
                "text",
                f"{fact_id} {sibling_id}",
                "system:stigmem",
                now,
                None,
                1.0,
                fact["scope"],
                hlc_between,
                None,
                tenant_id,
            ),
        )

        hlc_status = node_hlc.tick()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, hlc, received_from, tenant_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                conflict_id,
                "stigmem:conflict:status",
                "string",
                "unresolved",
                "system:stigmem",
                now,
                None,
                1.0,
                fact["scope"],
                hlc_status,
                None,
                tenant_id,
            ),
        )

        conn.execute(
            """INSERT OR IGNORE INTO conflicts (id, fact_a_id, fact_b_id, status, detected_at)
               VALUES (?,?,?,?,?)""",
            (conflict_id, fact_id, sibling_id, "unresolved", now),
        )


def write_audit_log(
    peer_id: str,
    event_type: str,
    detail: dict[str, Any] | None = None,
) -> None:
    """Write a federation audit log entry (spec §6.4)."""
    entry_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO federation_audit (id, peer_id, event_type, detail, ts) VALUES (?,?,?,?,?)",
            (entry_id, peer_id, event_type, json.dumps(detail) if detail else None, now),
        )
