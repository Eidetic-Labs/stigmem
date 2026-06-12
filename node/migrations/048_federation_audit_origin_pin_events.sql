-- node/migrations/048_federation_audit_origin_pin_events.sql
-- Phase 2c W4.1: add origin_pin_set / origin_pin_deleted to the federation_audit
-- event_type allowlist.  Mirrors the pattern in 037/038/042 (rename + recreate).
-- Additive + PG-safe: no data is dropped; the old table is preserved under a
-- temporary name and all rows are copied.

PRAGMA legacy_alter_table = ON;

ALTER TABLE federation_audit RENAME TO federation_audit_old;

CREATE TABLE federation_audit (
    id         TEXT PRIMARY KEY,
    peer_id    TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK(event_type IN (
                    'rejected_fact','rejected_token','scope_violation','replay_attempt',
                    'tl_proof_missing','tl_proof_verified','manifest_stored',
                    'manifest_refresh_failed','san_mismatch',
                    'peer_approved','peer_approval_failed','peer_policy_updated',
                    'origin_pin_set','origin_pin_deleted'
               )),
    detail     TEXT,
    ts         TEXT NOT NULL
);

INSERT INTO federation_audit SELECT * FROM federation_audit_old;

DROP TABLE federation_audit_old;

DROP INDEX IF EXISTS idx_audit_peer_ts;
CREATE INDEX IF NOT EXISTS idx_audit_peer_ts ON federation_audit(peer_id, ts);

PRAGMA legacy_alter_table = OFF;
