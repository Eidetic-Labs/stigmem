"""Async job store — spec §14.5 / §15.4.

Jobs are created by lint/decay routes when the scope exceeds the async threshold
(default 100,000 facts). Callers poll GET /v1/{lint,decay}/jobs/:job_id until
status is "done" or "failed".
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from .db import db


def create_job(job_type: str, scope: str | None, estimated_s: int, tenant_id: str) -> str:
    job_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with db() as conn:
        conn.execute(
            "INSERT INTO jobs (id, job_type, status, scope, estimated_s, created_at, tenant_id)"
            " VALUES (?, ?, 'pending', ?, ?, ?, ?)",
            (job_id, job_type, scope, estimated_s, now, tenant_id),
        )
    return job_id


def get_job(job_id: str, job_type: str, tenant_id: str) -> dict[str, Any] | None:
    """Return the job record, or None if not found (wrong type, or another tenant).

    F-SBOLA2: the lookup is tenant-scoped, so a caller who learns a job UUID for
    another tenant gets None (404 at the route) rather than that tenant's record.
    """
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = ? AND job_type = ? AND tenant_id = ?",
            (job_id, job_type, tenant_id),
        ).fetchone()
    if row is None:
        return None
    out: dict[str, Any] = {
        "job_id": row["id"],
        "status": row["status"],
        "scope": row["scope"],
        "estimated_s": row["estimated_s"],
        "created_at": row["created_at"],
    }
    if row["started_at"]:
        out["started_at"] = row["started_at"]
    if row["completed_at"]:
        out["completed_at"] = row["completed_at"]
    if row["result_json"]:
        out.update(json.loads(row["result_json"]))
    if row["error"]:
        out["error"] = row["error"]
    return out


def mark_running(job_id: str) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE jobs SET status='running', started_at=? WHERE id=?",
            (datetime.now(UTC).isoformat(), job_id),
        )


def mark_done(job_id: str, result: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE jobs SET status='done', completed_at=?, result_json=? WHERE id=?",
            (datetime.now(UTC).isoformat(), json.dumps(result), job_id),
        )


def mark_failed(job_id: str, error: str) -> None:
    with db() as conn:
        conn.execute(
            "UPDATE jobs SET status='failed', completed_at=?, error=? WHERE id=?",
            (datetime.now(UTC).isoformat(), error, job_id),
        )
