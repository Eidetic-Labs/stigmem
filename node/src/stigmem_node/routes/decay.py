"""Decay sweeper HTTP route — Phase 6 (spec §15) + async job path (spec §15.4).

POST /v1/decay/sweep
  → 200 sync result, or 202 { job_id, status, estimated_s } when scope > threshold.

GET /v1/decay/jobs/:job_id
  → 200 job status/result, or 404 if not found.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ..auth import Identity, resolve_identity
from ..db import db
from ..jobs import create_job, get_job, mark_done, mark_failed, mark_running
from ..lifecycle.decay import run_decay_sweep
from ..models.constants import VALID_SCOPES
from ..settings import settings

router = APIRouter(prefix="/v1/decay", tags=["decay"])


def _decay_job_worker(
    job_id: str,
    ttl_seconds: int | None,
    min_confidence: float | None,
    scope: str | None,
    dry_run: bool,
) -> None:
    """Background task: run decay sweep and update job status."""
    mark_running(job_id)
    try:
        result = run_decay_sweep(
            ttl_seconds=ttl_seconds,
            min_confidence=min_confidence,
            scope=scope,
            dry_run=dry_run,
        )
        mark_done(job_id, result)
    except Exception as exc:
        mark_failed(job_id, str(exc))


@router.post("/sweep")
def decay_sweep(
    background_tasks: BackgroundTasks,
    identity: Annotated[Identity, Depends(resolve_identity)],
    dry_run: bool = Query(False, description="Report what would be decayed without writing"),
    scope: str | None = Query(None, description="Restrict sweep to one scope"),
    ttl_seconds: int | None = Query(
        None, ge=0, description="Expire non-expiring facts older than N seconds (0 = all)"
    ),
    min_confidence: float | None = Query(
        None, ge=0.0, le=1.0, description="Expire active facts below this confidence"
    ),
) -> Any:
    """Mark stale facts as expired. Cron-friendly one-shot sweeper.

    Returns 200 synchronously for scopes ≤ threshold facts (Spec-X9-Decay-Semantics).
    Returns 202 with job_id for larger scopes; poll GET /v1/decay/jobs/:job_id.
    Note: dry_run is always synchronous per Spec-X9-Decay-Semantics.
    """
    if not identity.can_write():
        raise HTTPException(status_code=403, detail="write permission required")
    if scope is not None and scope not in VALID_SCOPES:
        raise HTTPException(status_code=400, detail=f"scope must be one of {VALID_SCOPES}")

    # Dry-run is always synchronous (spec §15.4).
    if not dry_run:
        # Tenant-scope the sizing counts so the sync-vs-async branch is not a
        # cross-tenant fact-count oracle (audit decay sibling of H4).
        with db() as conn:
            if scope is not None:
                scope_count: int = conn.execute(
                    "SELECT COUNT(*) FROM facts WHERE scope = ? AND tenant_id = ?",
                    [scope, identity.tenant_id],
                ).fetchone()[0]
            else:
                scope_count = conn.execute(
                    "SELECT COUNT(*) FROM facts WHERE tenant_id = ?",
                    [identity.tenant_id],
                ).fetchone()[0]

        if scope_count > settings.async_job_threshold:
            estimated_s = max(60, scope_count // 1_000)
            job_id = create_job("decay", scope, estimated_s)
            background_tasks.add_task(
                _decay_job_worker, job_id, ttl_seconds, min_confidence, scope, dry_run
            )
            return JSONResponse(
                status_code=202,
                content={"job_id": job_id, "status": "pending", "estimated_s": estimated_s},
            )

    return run_decay_sweep(
        ttl_seconds=ttl_seconds,
        min_confidence=min_confidence,
        scope=scope,
        dry_run=dry_run,
    )


@router.get("/jobs/{job_id}")
def get_decay_job(
    job_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> Any:
    """Poll the status of an async decay job (Spec-X9-Decay-Semantics)."""
    if not identity.can_read():
        raise HTTPException(status_code=403, detail="read permission required")
    job = get_job(job_id, job_type="decay")
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
