-- node/migrations/058_federation_audit_first_trust_confirm_rejected.sql
-- Phase 3 (DNSSEC-rooted origin key first-trust, Rev 6 §5): add
-- dnssec_first_trust_confirm_rejected to the federation_audit event_type
-- allowlist. A paste-to-confirm whose supplied key_fpr does NOT byte-equal the
-- quarantined candidate fingerprint is a MITM/attack signal and was previously
-- written to no audit. The operator-confirm route now records this event
-- (detail: reason=fpr_mismatch) on the 422 path.
-- Mirrors the rename+recreate pattern in 037/038/042/048/057.
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
                    'origin_pin_set','origin_pin_deleted',
                    'dnssec_first_trust_confirmed','dnssec_first_trust_rejected',
                    'dnssec_first_trust_confirm_rejected'
               )),
    detail     TEXT,
    ts         TEXT NOT NULL
);

INSERT INTO federation_audit SELECT * FROM federation_audit_old;

DROP TABLE federation_audit_old;

DROP INDEX IF EXISTS idx_audit_peer_ts;
CREATE INDEX IF NOT EXISTS idx_audit_peer_ts ON federation_audit(peer_id, ts);

PRAGMA legacy_alter_table = OFF;
