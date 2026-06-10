from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from stigmem_node.main import create_app

from .helpers import Settings, apply_migrations, patched_test_settings


def test_quarantine_list_hides_fact_value(tmp_path: Path):
    """GET /v1/quarantine must not expose the fact's value field (M3)."""
    db_file = str(tmp_path / "quarantine_m3.db")
    apply_migrations(db_path=db_file)

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="relaxed",
    )
    with patched_test_settings(test_settings):
        # Insert a quarantine garden and a quarantined fact with a sensitive value
        conn = sqlite3.connect(db_file)
        garden_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT INTO gardens (id, slug, name, scope, created_by, created_at, quarantine) "
            "VALUES (?,?,?,?,?,?,1)",
            (garden_id, "qtest", "Quarantine Test", "company", "agent:test", now),
        )
        fact_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO facts (id,entity,relation,value_type,value_v,source,timestamp,"
            "confidence,scope,quarantine_status,quarantine_garden_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                fact_id,
                "ent:1",
                "rel:secret",
                "string",
                "TOP_SECRET_VALUE",
                "src:1",
                now,
                1.0,
                "company",
                "pending",
                garden_id,
            ),
        )
        conn.commit()
        conn.close()

        app = create_app()
        with TestClient(app, raise_server_exceptions=True) as client:
            resp = client.get("/v1/quarantine")
            assert resp.status_code == 200
            data = resp.json()

            assert data["total"] >= 1
            fact_record = next((r for r in data["items"] if r["fact_id"] == fact_id), None)
            assert fact_record is not None
            # M3: value must not appear in the quarantine list response
            assert "TOP_SECRET_VALUE" not in json.dumps(fact_record)
            # Metadata fields are present
            assert fact_record["entity"] == "ent:1"
            assert fact_record["relation"] == "rel:secret"
            assert fact_record["quarantine_status"] == "pending"


# ===========================================================================
# 8. Token revocation ownership (H-SEC-3 regression — BOLA)
# ===========================================================================


def test_quarantine_ingest_writes_audit_log_entry(tmp_path: Path):
    """fact_audit_log must record a quarantine_ingest row when trust_mode=strict
    routes a low-trust fact to the quarantine garden at ingest time."""
    import sqlite3 as _sqlite3

    from stigmem_node.source_trust import bust_trust_cache

    db_file = str(tmp_path / "qaudit_test.db")
    apply_migrations(db_path=db_file)

    # Create a quarantine garden directly in the DB.
    garden_id = str(uuid.uuid4())
    sender_node_id = f"stigmem://low-trust-sender-{uuid.uuid4()}"
    now = datetime.now(UTC).isoformat()
    conn = _sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO gardens (id, slug, name, scope, created_by, created_at, quarantine) "
        "VALUES (?,?,?,?,?,?,1)",
        (garden_id, "test-quarantine", "Test Quarantine", "company", "agent:test", now),
    )
    # Blocklist the sender so compute_source_trust returns 0.0 deterministically.
    conn.execute(
        "INSERT INTO quarantine_rules (id, rule_type, org_uri, created_by, created_at) "
        "VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), "never_trust", sender_node_id, "agent:test", now),
    )
    conn.commit()
    conn.close()

    test_settings = Settings(
        db_path=db_file,
        auth_required=False,
        node_url="http://testnode",
        trust_mode="strict",
        quarantine_garden_id=garden_id,
        tl_backend="off",
    )

    with patched_test_settings(test_settings):
        try:
            bust_trust_cache(sender_node_id)

            from stigmem_node.federation_ingest import ingest_fact

            fact_id = str(uuid.uuid4())
            fact = {
                "id": fact_id,
                "entity": "test:entity",
                "relation": "test:value",
                "value": {"type": "string", "v": "quarantined-payload"},
                "source": sender_node_id,
                "timestamp": now,
                "hlc": None,
                "confidence": 1.0,
                "scope": "public",
                "valid_until": None,
            }

            result = ingest_fact(fact, sender_node_id=sender_node_id, tenant_id="default")
            assert result is True, "ingest_fact should return True for a new fact"

            # Verify quarantine_ingest audit entry was written.
            conn2 = _sqlite3.connect(db_file)
            conn2.row_factory = _sqlite3.Row
            row = conn2.execute(
                "SELECT * FROM fact_audit_log "
                "WHERE fact_id = ? AND event_type = 'quarantine_ingest'",
                (fact_id,),
            ).fetchone()
            conn2.close()

            assert row is not None, "fact_audit_log must have a quarantine_ingest entry"
            assert row["entity_uri"] == "system:federation"
            assert row["source"] == sender_node_id
            assert row["oidc_sub"] is None
            detail = json.loads(row["detail"])
            assert "trust_score" in detail
            assert detail["trust_score"] == 0.0

            # Verify the fact itself was routed to quarantine.
            conn3 = _sqlite3.connect(db_file)
            conn3.row_factory = _sqlite3.Row
            fact_row = conn3.execute(
                "SELECT quarantine_status, quarantine_garden_id FROM facts WHERE id = ?",
                (fact_id,),
            ).fetchone()
            conn3.close()
            assert fact_row is not None
            assert fact_row["quarantine_status"] == "pending"
            assert fact_row["quarantine_garden_id"] == garden_id
        finally:
            bust_trust_cache(sender_node_id)


# ===========================================================================
# 13. H-SEC-1 regression — BOLA on capability-token issuance
# ===========================================================================
