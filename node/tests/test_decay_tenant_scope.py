"""Decay sweep tenant-scoping regression tests (R-1 / F-SBOLA1).

The decay sweep must only expire/count facts belonging to the caller's tenant.
Before the fix it selected candidates across ALL tenants, so a tenant-B caller
could expire every tenant's facts (ttl_seconds=0) and use dry_run as a global
fact-count oracle.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

from stigmem_node.lifecycle.decay import run_decay_sweep


def _seed_fact(db_path: str, *, tenant_id: str, entity: str) -> str:
    """Insert one active (non-expiring) fact for the given tenant via direct SQL."""
    fact_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO facts "
            "(id, entity, relation, value_type, value_v, source, timestamp, "
            " valid_until, confidence, scope, tenant_id, interpret_as) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                fact_id,
                entity,
                "test:role",
                "string",
                "admin",
                "stigmem://test/source/hr",
                now,
                None,
                0.9,
                "local",
                tenant_id,
                "content",
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return fact_id


def _valid_until(db_path: str, fact_id: str) -> str | None:
    """Effective valid_until — the decay sweep records expiry via an override row."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(fvo.valid_until, f.valid_until) "
            "FROM facts f "
            "LEFT JOIN fact_validity_overrides fvo ON fvo.fact_id = f.id "
            "WHERE f.id = ?",
            (fact_id,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_ttl_sweep_only_expires_callers_tenant(migrated_db: str) -> None:
    """ttl_seconds=0 for tenantB must not expire tenant-default facts."""
    default_id = _seed_fact(migrated_db, tenant_id="default", entity="stigmem://test/user/a")
    tenant_b_id = _seed_fact(migrated_db, tenant_id="tenantB", entity="stigmem://test/user/b")

    result = run_decay_sweep(ttl_seconds=0, tenant_id="tenantB")

    # Only tenantB's fact is touched.
    assert result["decayed"] == 1
    assert _valid_until(migrated_db, tenant_b_id) is not None
    # tenant-default fact stays alive (valid_until NULL).
    assert _valid_until(migrated_db, default_id) is None


def test_dry_run_scanned_counts_only_callers_tenant(migrated_db: str) -> None:
    """dry_run must not be a cross-tenant count oracle (TA-7)."""
    default_id = _seed_fact(migrated_db, tenant_id="default", entity="stigmem://test/user/a")
    _seed_fact(migrated_db, tenant_id="tenantB", entity="stigmem://test/user/b")
    _seed_fact(migrated_db, tenant_id="tenantB", entity="stigmem://test/user/c")

    result = run_decay_sweep(ttl_seconds=0, dry_run=True, tenant_id="tenantB")

    # Counts only the two tenantB facts, not the tenant-default one.
    assert result["scanned"] == 2
    assert result["dry_run"] is True
    # Nothing written.
    assert _valid_until(migrated_db, default_id) is None
