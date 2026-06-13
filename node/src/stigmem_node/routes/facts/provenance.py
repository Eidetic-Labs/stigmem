"""Fact provenance route and helpers."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, HTTPException, status

from ...auth import Identity, resolve_identity
from ...db import db
from ...fact_visibility import ReadScope, caller_read_scope
from ...garden_acl import require_fact_garden_read
from ...models.provenance import ProvenanceEntry, ProvenanceResponse
from .common import _get_tombstone_filter, logger, router

_REF_SELECT = (
    "SELECT f.*, COALESCE(fgm.garden_id, f.garden_id) AS projected_garden_id FROM facts f"
    " LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"
    " WHERE f.id = ? AND f.tenant_id = ?"
)


def _resolve_provenance_entry(
    entry: Any, tenant_id: str, read_scope: ReadScope
) -> tuple[str, Any] | None:
    """Resolve a derived_from entry to (hash_val, ref_row | None); skip non-dict entries.

    A ref whose PROJECTED garden the caller cannot see is treated as unresolved
    (ref_row=None) so a restricted-garden ancestor's existence / fact_id / entity
    URI is not disclosed via lineage (audit F-PROV-REF). It then redacts to the
    same {hash, exists:false} shape as tombstoned/missing refs.
    """
    if not isinstance(entry, dict):
        return None
    hash_val: str = entry.get("hash", "")
    entry_fact_id: str | None = entry.get("fact_id")

    ref_row = None
    with db() as conn:
        if entry_fact_id:
            ref_row = conn.execute(_REF_SELECT, (entry_fact_id, tenant_id)).fetchone()
        elif hash_val.startswith("sha256:"):
            alias = conn.execute(
                "SELECT fact_id FROM fact_cid_aliases WHERE cid = ?",
                (hash_val,),
            ).fetchone()
            if alias:
                ref_row = conn.execute(_REF_SELECT, (alias["fact_id"], tenant_id)).fetchone()
    if ref_row is not None and not read_scope.garden_allows(ref_row["projected_garden_id"]):
        ref_row = None  # garden-hidden ancestor → redact like tombstoned
    return hash_val, ref_row


def _format_provenance_entry(hash_val: str, ref_row: Any, excluded: set[str]) -> ProvenanceEntry:
    """Render a resolved entry into a ProvenanceEntry, redacting tombstoned/missing rows."""
    if ref_row is None:
        return ProvenanceEntry(hash=hash_val, exists=False)
    if ref_row["entity"] in excluded:
        return ProvenanceEntry(hash=hash_val, exists=False)
    return ProvenanceEntry(
        hash=hash_val,
        fact_id=ref_row["id"],
        entity=ref_row["entity"],
        exists=True,
    )


@router.get("/{fact_id}/provenance", response_model=ProvenanceResponse)
def get_provenance(
    fact_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> ProvenanceResponse:
    """Provenance walk with tombstone suppression.

    Returns the derived_from chain for a fact.  Any entry whose referenced entity is
    tombstoned — or whose fact is otherwise inaccessible — is redacted to
    {"hash": "...", "exists": false}, indistinguishable from unauthorized
    cross-scope references to prevent existence leakage. Covered by
    Spec-X2-RTBF-Tombstones and Spec-X11-Recall-Graph.
    """
    import json as _prov_json

    if not identity.can_read():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="read permission required"
        )

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND tenant_id = ?",
            (fact_id, identity.tenant_id),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="fact not found")
        # Garden ACL: don't expose a restricted-garden fact's CID/lineage to a
        # non-member (spec §17.3; sibling of the single-get gate).
        require_fact_garden_read(conn, fact_id, identity.tenant_id, identity)

    derived_from_raw = row["derived_from"] if "derived_from" in row.keys() else None  # noqa: SIM118
    cid_val = row["cid"] if "cid" in row.keys() else None  # noqa: SIM118
    root_scope: str = row["scope"] or "local"

    if not derived_from_raw:
        return ProvenanceResponse(fact_id=fact_id, cid=cid_val, derived_from=[])

    try:
        entries_raw: list[Any] = _prov_json.loads(derived_from_raw)
    except Exception as exc:
        logger.warning("ignoring malformed provenance for fact %s: %s", fact_id, exc)
        entries_raw = []

    # Resolve each derived_from entry to its referenced fact row (garden-gated)
    read_scope = caller_read_scope(identity)
    resolved: list[tuple[str, Any]] = []  # (hash_val, ref_row | None)
    for entry in entries_raw:
        resolved_entry = _resolve_provenance_entry(entry, identity.tenant_id, read_scope)
        if resolved_entry is not None:
            resolved.append(resolved_entry)

    # Single tombstone filter call across all resolved entity URIs (§23.3.2 r.4)
    accessible_entities = [ref_row["entity"] for _, ref_row in resolved if ref_row is not None]
    excluded: set[str] = set()
    if accessible_entities:
        with db() as _tc_conn:
            is_admin = identity.is_admin()
            excluded, _ = _get_tombstone_filter(
                _tc_conn, accessible_entities, root_scope, is_admin, identity.tenant_id
            )

    # Build response — §23.3.2 r.4 tombstone and §20.6.2 unauthorized share identical shape
    result: list[ProvenanceEntry] = [
        _format_provenance_entry(hash_val, ref_row, excluded) for hash_val, ref_row in resolved
    ]

    return ProvenanceResponse(fact_id=fact_id, cid=cid_val, derived_from=result)
