-- node/migrations/050_revocation_v2_origin.sql
-- Phase 2c Rev-1: revocation relay origin columns (mirror tombstone migration 049).
-- Additive + PG-safe: plain ALTER TABLE ADD COLUMN, all nullable, no non-constant defaults.
-- NULL = self/direct revocation (unchanged behaviour); non-NULL = relayed revocation.
ALTER TABLE tombstone_revocations ADD COLUMN received_from          TEXT;  -- node_id a relayed revocation arrived from; NULL = self/direct
ALTER TABLE tombstone_revocations ADD COLUMN origin_node_id         TEXT;  -- NULL = local origin
ALTER TABLE tombstone_revocations ADD COLUMN origin_tenant          TEXT;
ALTER TABLE tombstone_revocations ADD COLUMN origin_entity_uri      TEXT;
ALTER TABLE tombstone_revocations ADD COLUMN origin_allowed_scopes  TEXT;  -- JSON array, json.dumps(sorted(...))
ALTER TABLE tombstone_revocations ADD COLUMN origin_allowed_tenants TEXT;  -- JSON array, json.dumps(sorted(...))
ALTER TABLE tombstone_revocations ADD COLUMN origin_sig             TEXT;  -- base64url Ed25519 origin attestation
