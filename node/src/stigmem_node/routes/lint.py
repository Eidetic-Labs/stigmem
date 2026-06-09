"""Lint route — spec §14 (v0.7) + async job path (spec §14.5).

POST /v1/lint
{ scope, checks?, entity?, relation?, stale_lookahead_s? }
  → 200 sync result, or 202 { job_id, status, estimated_s } when scope > threshold.

GET /v1/lint/jobs/:job_id
  → 200 job status/result, or 404 if not found.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse

from ..auth import Identity, resolve_identity
from ..db import db
from ..jobs import create_job, get_job, mark_done, mark_failed, mark_running
from ..models.constants import VALID_SCOPES
from ..models.lint import ALL_CHECKS, LintCheck, LintFinding, LintRequest, LintResult
from ..settings import settings

router = APIRouter(tags=["lint"])

INTENT_ROUTING_RELATIONS = frozenset({"intent:handoff_to", "intent:context_ref"})

# Constant WHERE-fragment tails for the lint queries.  Optional filters are
# gated via ``(? IS NULL OR …)`` so the SQL strings are module-level constants
# — no user input ever flows into the query text.  Closes the
# ``py/sql-injection`` taint that the previous conditional-fragment builder
# triggered (issue #115).
_COUNT_SQL = (
    "SELECT COUNT(*) FROM facts f"
    " WHERE 1=1"
    " AND f.tenant_id = ?"
    " AND f.scope = ?"
    " AND (? IS NULL OR f.entity = ?)"
    " AND (? IS NULL OR f.relation = ?)"
)


def _lint_filter_params(
    tenant_id: str, scope: str, entity: str | None, relation: str | None
) -> list[Any]:
    """Return the bind values for the lint filter tails (tenant-scoped, audit H4).

    Empty-string entity/relation are normalized to None so the IS-NULL gate
    preserves the previous ``if entity:`` truthiness behaviour.
    """
    entity_p = entity or None
    relation_p = relation or None
    return [tenant_id, scope, entity_p, entity_p, relation_p, relation_p]


_CONFLICT_SQL = (
    "SELECT c.id AS conflict_id, c.fact_a_id, c.fact_b_id, fa.entity, fa.relation"
    " FROM conflicts c"
    " JOIN facts fa ON fa.id = c.fact_a_id"
    " JOIN facts fb ON fb.id = c.fact_b_id"
    " WHERE c.status = 'unresolved'"
    " AND fa.tenant_id = ?"
    " AND fa.scope = ?"
    " AND (? IS NULL OR fa.entity = ?)"
    " AND (? IS NULL OR fa.relation = ?)"
)


def _check_contradictions(conn: Any, fa_params: list[Any]) -> list[dict[str, Any]]:
    """Return contradiction findings for unresolved conflicts in the filtered scope."""
    findings: list[dict[str, Any]] = []
    for row in conn.execute(_CONFLICT_SQL, fa_params).fetchall():
        findings.append(
            {
                "check": "contradiction",
                "severity": "error",
                "entity": row["entity"],
                "relation": row["relation"],
                "fact_ids": [row["fact_a_id"], row["fact_b_id"]],
                "detail": f"unresolved conflict {row['conflict_id']}",
            }
        )
    return findings


_STALE_SQL = (
    "SELECT f.id, f.entity, f.relation, f.valid_until"
    " FROM facts f"
    " WHERE f.valid_until IS NOT NULL"
    " AND f.confidence > 0.0"
    " AND f.valid_until <= ?"
    " AND f.tenant_id = ?"
    " AND f.scope = ?"
    " AND (? IS NULL OR f.entity = ?)"
    " AND (? IS NULL OR f.relation = ?)"
)


def _check_stale(
    conn: Any,
    f_params: list[Any],
    now: str,
    lookahead: str,
    stale_lookahead_s: int,
) -> list[dict[str, Any]]:
    """Return stale (already-expired or expiring-soon) findings."""
    findings: list[dict[str, Any]] = []
    for row in conn.execute(_STALE_SQL, [lookahead] + f_params).fetchall():
        expired = row["valid_until"] <= now
        findings.append(
            {
                "check": "stale",
                "severity": "warning" if expired else "info",
                "entity": row["entity"],
                "relation": row["relation"],
                "fact_ids": [row["id"]],
                "detail": (
                    f"expired at {row['valid_until']}"
                    if expired
                    else f"expires at {row['valid_until']} (within {stale_lookahead_s}s)"
                ),
            }
        )
    return findings


_ORPHAN_SQL = (
    "SELECT entity FROM facts"
    " WHERE tenant_id = ?"
    "   AND scope = ?"
    "   AND (? IS NULL OR entity = ?)"
    " GROUP BY entity"
    " HAVING COUNT(*) > 0"
    " AND SUM(CASE WHEN confidence > 0.0"
    " AND (valid_until IS NULL OR valid_until > ?) THEN 1 ELSE 0 END) = 0"
)


def _check_orphans(
    conn: Any, tenant_id: str, scope: str, entity: str | None, now: str
) -> list[dict[str, Any]]:
    """Return orphan-entity findings (entities with no live facts in scope)."""
    findings: list[dict[str, Any]] = []
    entity_p = entity or None
    for row in conn.execute(_ORPHAN_SQL, [tenant_id, scope, entity_p, entity_p, now]).fetchall():
        findings.append(
            {
                "check": "orphan",
                "severity": "info",
                "entity": row["entity"],
                "relation": None,
                "fact_ids": [],
                "detail": f"entity {row['entity']!r} has no live facts in scope={scope}",
            }
        )
    return findings


_REF_SQL = (
    "SELECT f.id, f.entity, f.relation, f.value_v"
    " FROM facts f"
    " WHERE f.value_type = 'ref'"
    " AND f.confidence > 0.0"
    " AND (f.valid_until IS NULL OR f.valid_until > ?)"
    " AND f.tenant_id = ?"
    " AND f.scope = ?"
    " AND (? IS NULL OR f.entity = ?)"
    " AND (? IS NULL OR f.relation = ?)"
)


def _check_broken_refs(
    conn: Any, tenant_id: str, f_params: list[Any], now: str
) -> list[dict[str, Any]]:
    """Return broken-ref findings for value-type=ref facts whose target has no live facts."""
    findings: list[dict[str, Any]] = []
    for row in conn.execute(_REF_SQL, [now] + f_params).fetchall():
        target_entity = row["value_v"]
        live_count = conn.execute(
            "SELECT COUNT(*) FROM facts"
            " WHERE entity = ? AND tenant_id = ? AND confidence > 0.0"
            " AND (valid_until IS NULL OR valid_until > ?)",
            [target_entity, tenant_id, now],
        ).fetchone()[0]
        if live_count == 0:
            is_intent = row["relation"] in INTENT_ROUTING_RELATIONS
            findings.append(
                {
                    "check": "broken_ref",
                    "severity": "error" if is_intent else "warning",
                    "entity": row["entity"],
                    "relation": row["relation"],
                    "fact_ids": [row["id"]],
                    "detail": f"ref target entity {target_entity!r} has no live facts",
                }
            )
    return findings


_NS_SQL = (
    "SELECT f.entity, f.relation, GROUP_CONCAT(f.id) AS ids"
    " FROM facts f"
    " WHERE f.confidence > 0.0"
    " AND (f.valid_until IS NULL OR f.valid_until > ?)"
    " AND instr(f.relation, ':') = 0"
    " AND f.tenant_id = ?"
    " AND f.scope = ?"
    " AND (? IS NULL OR f.entity = ?)"
    " AND (? IS NULL OR f.relation = ?)"
    " GROUP BY f.entity, f.relation"
)


def _check_namespacing(conn: Any, f_params: list[Any], now: str) -> list[dict[str, Any]]:
    """Return namespacing findings for live facts whose relation lacks a 'prefix:' namespace."""
    findings: list[dict[str, Any]] = []
    for row in conn.execute(_NS_SQL, [now] + f_params).fetchall():
        findings.append(
            {
                "check": "namespacing",
                "severity": "warning",
                "entity": row["entity"],
                "relation": row["relation"],
                "fact_ids": row["ids"].split(",") if row["ids"] else [],
                "detail": (
                    f"bare relation {row['relation']!r} has no namespace prefix — "
                    f"rename to 'your-prefix:{row['relation']}' to avoid silent collisions"
                ),
            }
        )
    return findings


def _run_lint_sweep(
    tenant_id: str,
    scope: str,
    checks: list[LintCheck],
    entity: str | None,
    relation: str | None,
    stale_lookahead_s: int,
) -> dict[str, Any]:
    """Execute the lint sweep and return a dict matching LintResult fields."""
    now_dt = datetime.now(UTC)
    now = now_dt.isoformat()
    lookahead = (now_dt + timedelta(seconds=stale_lookahead_s)).isoformat()

    f_params = _lint_filter_params(tenant_id, scope, entity, relation)
    fa_params = _lint_filter_params(tenant_id, scope, entity, relation)

    findings: list[dict[str, Any]] = []
    fact_count = 0

    with db() as conn:
        fact_count = conn.execute(_COUNT_SQL, f_params).fetchone()[0]

        if "contradiction" in checks:
            findings.extend(_check_contradictions(conn, fa_params))

        if "stale" in checks:
            findings.extend(_check_stale(conn, f_params, now, lookahead, stale_lookahead_s))

        if "orphan" in checks:
            findings.extend(_check_orphans(conn, tenant_id, scope, entity, now))

        if "broken_ref" in checks:
            findings.extend(_check_broken_refs(conn, tenant_id, f_params, now))

        if "namespacing" in checks:
            findings.extend(_check_namespacing(conn, f_params, now))

    return {
        "findings": findings,
        "checked_at": now,
        "scope": scope,
        "checks_run": checks,
        "fact_count": fact_count,
    }


def _lint_job_worker(job_id: str, req: LintRequest, tenant_id: str) -> None:
    """Background task: run lint sweep and update job status."""
    mark_running(job_id)
    try:
        result = _run_lint_sweep(
            tenant_id=tenant_id,
            scope=req.scope,
            checks=req.checks or ALL_CHECKS,
            entity=req.entity,
            relation=req.relation,
            stale_lookahead_s=req.stale_lookahead_s,
        )
        mark_done(job_id, result)
    except Exception as exc:
        mark_failed(job_id, str(exc))


@router.post("/v1/lint")
def lint_scope(
    req: LintRequest,
    background_tasks: BackgroundTasks,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> Any:
    """Health-check sweep for a scope (Spec-20-Lint-Semantics). Read-only.

    Returns 200 with results synchronously for scopes ≤ threshold facts.
    Returns 202 with job_id for larger scopes; poll GET /v1/lint/jobs/:job_id.
    """
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")
    if req.scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope must be one of {VALID_SCOPES}")

    checks_to_run: list[LintCheck] = req.checks if req.checks else ALL_CHECKS

    # Count scope facts to choose sync vs. async path (spec §14.5).
    # Tenant-scoped so the count is not a cross-tenant oracle (audit H4).
    with db() as conn:
        scope_count: int = conn.execute(
            "SELECT COUNT(*) FROM facts WHERE tenant_id = ? AND scope = ?",
            [identity.tenant_id, req.scope],
        ).fetchone()[0]

    if scope_count > settings.async_job_threshold:
        estimated_s = max(10, scope_count // 5_000)
        job_id = create_job("lint", req.scope, estimated_s)
        background_tasks.add_task(_lint_job_worker, job_id, req, identity.tenant_id)
        return JSONResponse(
            status_code=202,
            content={"job_id": job_id, "status": "pending", "estimated_s": estimated_s},
        )

    result = _run_lint_sweep(
        identity.tenant_id,
        req.scope,
        checks_to_run,
        req.entity,
        req.relation,
        req.stale_lookahead_s,
    )
    return LintResult(
        findings=[LintFinding(**f) for f in result["findings"]],
        checked_at=result["checked_at"],
        scope=result["scope"],
        checks_run=result["checks_run"],
        fact_count=result["fact_count"],
    )


@router.get("/v1/lint/jobs/{job_id}")
def get_lint_job(
    job_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> Any:
    """Poll the status of an async lint job (Spec-20-Lint-Semantics)."""
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")
    job = get_job(job_id, job_type="lint")
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
