"""Shared helpers for fact route modules."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from ...hlc import node_hlc
from ...models.tombstones import TombstoneNotice

logger = logging.getLogger("stigmem.facts")

FACT_PROJECTION_SELECT = (
    "f.*, "
    "COALESCE(fvo.valid_until, f.valid_until) AS projected_valid_until, "
    "COALESCE(fvo.confidence, f.confidence) AS projected_confidence, "
    "COALESCE(fgm.garden_id, f.garden_id) AS projected_garden_id, "
    "COALESCE(fqs.quarantine_status, f.quarantine_status) AS projected_quarantine_status, "
    "COALESCE(fqs.quarantine_garden_id, f.quarantine_garden_id) "
    "AS projected_quarantine_garden_id, "
    "COALESCE(f.cid, (SELECT fca.cid FROM fact_cid_aliases fca "
    "WHERE fca.fact_id = f.id ORDER BY fca.cid LIMIT 1)) AS projected_cid"
)

FACT_PROJECTION_JOINS = (
    " LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id"
    " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
    " LEFT JOIN fact_quarantine_status fqs ON fqs.fact_id = f.id"
)

__all__ = [
    "FACT_PROJECTION_JOINS",
    "FACT_PROJECTION_SELECT",
    "router",
]


def _get_tombstone_filter(
    conn: Any,
    entity_uris: list[str],
    scope: str,
    is_admin_caller: bool,
    tenant_id: str,
) -> tuple[set[str], list[TombstoneNotice]]:
    """Return (excluded_entity_uris, tombstone_notices) for entity_uris in scope (§23.3, §24.3).

    excluded_entity_uris: entities under active (non-legal-hold) tombstones.
    tombstone_notices: annotations for legal_hold tombstones visible to admin callers.

    Suppression is scoped to ``tenant_id`` (the caller's tenant): only tombstones in
    the caller's own tenant partition may suppress the caller's facts. A tombstone in
    a different tenant MUST NOT hide this caller's content (R-3 / F-SBOLA3). Single-tenant
    nodes pass ``tenant_id="default"``, matching the ``default`` rows create_tombstone writes.
    """
    from ...lifecycle.tombstone_gate import tombstone_filter_enabled

    if not entity_uris or not tombstone_filter_enabled():
        return set(), []

    placeholders = ",".join("?" * len(entity_uris))
    # BEGIN IMMEDIATE for SQLite consistency (§23.3.3 rule 5).
    # On postgres this is a syntax error; rollback clears the failed txn state.
    try:
        conn.execute("BEGIN IMMEDIATE")
    except Exception as exc:  # nosec B110
        logger.debug(
            "BEGIN IMMEDIATE not supported or failed for tombstone filter transaction "
            "(expected on some backends, e.g. postgres); continuing with default "
            "transaction behavior: %s",
            exc,
        )
        try:  # noqa: SIM105
            conn.rollback()
        except Exception as rollback_exc:  # nosec B110
            logger.debug(
                "Rollback after BEGIN IMMEDIATE failure also failed; continuing because "
                "explicit BEGIN IMMEDIATE is optional in this path: %s",
                rollback_exc,
            )
    rows = conn.execute(
        # Same-issuer binding: only a revocation from the tombstone's OWN issuer
        # (r.signed_by = t.signed_by) lifts the suppression — a forged/cross-issuer
        # revocation can never un-suppress content another org tombstoned (RTBF integrity).
        # Tenant predicate (R-3 / F-SBOLA3): only a tombstone in the CALLER's own tenant
        # may suppress the caller's facts — a different tenant's tombstone must not hide them.
        f"""SELECT t.id, t.entity_uri, t.scope, t.created_at, t.legal_hold
            FROM tombstones t
            WHERE t.entity_uri IN ({placeholders})
            AND t.tenant_id = ?
            AND NOT EXISTS (
                SELECT 1 FROM tombstone_revocations r
                WHERE r.tombstone_id = t.id AND r.signed_by = t.signed_by
            )""",  # noqa: S608  # nosec B608 - dynamic SQL is generated placeholders only; entity values are bound params.
        [*entity_uris, tenant_id],
    ).fetchall()
    try:  # noqa: SIM105
        conn.execute("COMMIT")
    except Exception as exc:  # nosec B110
        logger.debug(
            "Tombstone filter COMMIT skipped or failed (can occur when explicit "
            "BEGIN IMMEDIATE was unavailable on this backend); continuing: %s",
            exc,
        )

    excluded: set[str] = set()
    notices: list[TombstoneNotice] = []

    for row in rows:
        uri = row["entity_uri"]
        row_scope = row["scope"]
        if row_scope != "*" and row_scope != scope:
            continue

        if row["legal_hold"]:
            if is_admin_caller:
                notices.append(
                    TombstoneNotice(
                        entity_uri=uri,
                        tombstone_id=row["id"],
                        legal_hold=True,
                        tombstone_created_at=row["created_at"],
                    )
                )
            else:
                excluded.add(uri)
        else:
            excluded.add(uri)

    return excluded, notices


router = APIRouter(prefix="/v1/facts", tags=["facts"])

_SYSTEM_RELATION_PREFIX = "stigmem:"


def _validate_relation(relation: str) -> list[str]:
    """Return convention warnings for a relation name (see relation-convention.md)."""
    if ":" not in relation:
        return [
            f"bare relation {relation!r} has no namespace prefix; "
            f"rename to 'your-prefix:{relation}' to prevent silent collisions "
            "(see relation-convention.md)"
        ]
    if relation.startswith(_SYSTEM_RELATION_PREFIX):
        return [
            f"relation {relation!r} uses reserved system prefix 'stigmem:'; "
            "non-system callers should use a custom namespace prefix (see spec §9.1)"
        ]
    return []


def _is_valid_entity_uri(uri: str) -> bool:
    """Return whether a ref value is eligible for graph edge derivation."""
    return "://" in uri or uri.startswith("urn:")


def _embed_fact_background(
    fact_id: str,
    entity: str,
    relation: str,
    value_type: str,
    value_v: str,
) -> None:
    """Background thread: embed one fact and persist to vec_facts."""
    try:
        from ... import settings as settings_pkg
        from ...db import db
        from ...embedding import get_embedding_model
        from ...recall.vector_search import check_or_register_model, embed_and_store_fact

        model = get_embedding_model(settings_pkg.settings)
        with db() as conn:
            check_or_register_model(conn, model.model_id, model.dimension)
            embed_and_store_fact(fact_id, entity, relation, value_type, value_v, conn, model)
    except Exception as exc:
        logger.warning("Write-time embedding failed for fact %s: %s", fact_id, exc)


def _record_contradictions(
    conn: Any,
    new_fact_id: str,
    entity: str,
    relation: str,
    scope: str,
    siblings: list[Any],
    tenant_id: str = "default",
) -> None:
    """Write conflict entities and conflicts table rows for new contradictions."""
    now = datetime.now(UTC).isoformat()
    for sibling in siblings:
        sibling_id = sibling["id"]

        already = conn.execute(
            """SELECT id FROM conflicts
               WHERE (fact_a_id=? AND fact_b_id=?) OR (fact_a_id=? AND fact_b_id=?)""",
            (new_fact_id, sibling_id, sibling_id, new_fact_id),
        ).fetchone()
        if already:
            continue

        conflict_id = f"stigmem:conflict:{uuid.uuid4()}"
        h_between = node_hlc.tick()
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
                f"{new_fact_id} {sibling_id}",
                "system:stigmem",
                now,
                None,
                1.0,
                scope,
                h_between,
                None,
                tenant_id,
            ),
        )
        h_status = node_hlc.tick()
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
                scope,
                h_status,
                None,
                tenant_id,
            ),
        )
        conn.execute(
            """INSERT OR IGNORE INTO conflicts (id, fact_a_id, fact_b_id, status, detected_at)
               VALUES (?,?,?,?,?)""",
            (conflict_id, new_fact_id, sibling_id, "unresolved", now),
        )


def _encode_v(vtype: str, v: Any) -> str:
    if vtype == "null":
        return "null"
    if vtype == "boolean":
        return "true" if v else "false"
    return str(v)
